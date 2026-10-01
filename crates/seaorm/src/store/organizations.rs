use super::{
    SeaOrmStore, map_db_err,
    organization_models::{self as models, Entity, values},
};
use crate::schema::AuthSchema;
use crate::types_org::{CreateOrganization, Organization, UpdateOrganization};
use crate::{SeaOrmOrganizationModel, SeaOrmOrganizationSchema};
use async_trait::async_trait;
use better_auth_core::{
    AuthError, AuthResult, organization_fields::OrganizationFields, store::OrganizationStore,
};
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, TransactionTrait};
use serde_json::json;

#[async_trait]
impl<S: AuthSchema, O: SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> OrganizationStore
    for SeaOrmStore<S, O, P>
{
    async fn insert_organization(&self, record: Organization) -> AuthResult<Organization> {
        let config = self.organization_fields()?.organization;
        let core = self.create_fields(
            "organization",
            if record.id.is_undefined() {
                None
            } else {
                Some(record.id.typed()?.clone())
            },
            values([
                ("name", serde_json::to_value(record.name)?),
                ("slug", serde_json::to_value(record.slug)?),
                ("logo", serde_json::to_value(record.logo)?),
                (
                    "metadata",
                    record.metadata.json()?.unwrap_or(serde_json::Value::Null),
                ),
                ("created_at", serde_json::to_value(record.created_at)?),
                ("auth_updated_at", json!(Utc::now())),
            ]),
        )?;
        models::active::<O::Organization>(
            core,
            record.additional_fields,
            &config,
            true,
            self.connection().get_database_backend(),
        )?
        .insert(self.connection())
        .await
        .map_err(map_db_err)?
        .record(&config)
    }
    async fn delete_organization_records(&self, id: &str) -> AuthResult<()> {
        let _ = Entity::<O::Member>::delete_many()
            .filter(O::Member::column("organization_id")?.eq(id))
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        let _ = Entity::<O::Invitation>::delete_many()
            .filter(O::Invitation::column("organization_id")?.eq(id))
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        let _ = Entity::<O::Organization>::delete_many()
            .filter(O::Organization::column("id")?.eq(id))
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        Ok(())
    }

    fn configure_organization_fields(&self, fields: OrganizationFields) -> AuthResult<()> {
        let mut fields = fields.into_storage();
        models::validate_fields::<O::Organization>("organization", &fields.organization)?;
        models::validate_fields::<O::Member>("member", &fields.member)?;
        models::validate_fields::<O::Invitation>("invitation", &fields.invitation)?;
        models::validate_fields::<O::Team>("team", &fields.team)?;
        models::validate_fields::<O::OrganizationRole>(
            "organizationRole",
            &fields.organization_role,
        )?;
        let backend = self.connection().get_database_backend();
        models::configure_json_fields::<O::Organization>(&mut fields.organization, backend)?;
        models::configure_json_fields::<O::Member>(&mut fields.member, backend)?;
        models::configure_json_fields::<O::Invitation>(&mut fields.invitation, backend)?;
        models::configure_json_fields::<O::Team>(&mut fields.team, backend)?;
        models::configure_json_fields::<O::OrganizationRole>(
            &mut fields.organization_role,
            backend,
        )?;
        *self
            .organization_fields
            .write()
            .map_err(|error| AuthError::internal(error.to_string()))? = fields;
        Ok(())
    }

    async fn create_organization(&self, org: CreateOrganization) -> AuthResult<Organization> {
        let config = self.organization_fields()?.organization;
        let now = Utc::now();
        let mut core = self.create_fields(
            "organization",
            org.id,
            values([("created_at", json!(now)), ("auth_updated_at", json!(now))]),
        )?;
        for (name, value) in [
            ("name", org.name.json()?),
            ("slug", org.slug.json()?),
            ("logo", org.logo.json()?),
        ] {
            if let Some(value) = value {
                let _ = core.insert(name.into(), value);
            }
        }
        let native_metadata = !config.additional_fields.contains_key("metadata")
            && matches!(
                O::Organization::column("metadata")?.def().get_column_type(),
                sea_orm::ColumnType::Json | sea_orm::ColumnType::JsonBinary
            );
        if !native_metadata
            && let Some(value) =
                better_auth_core::organization_fields::metadata_input(org.metadata.json()?, true)
        {
            let _ = core.insert("metadata".into(), value);
        }
        let mut active = models::active::<O::Organization>(
            core,
            org.additional_fields,
            &config,
            true,
            self.connection().get_database_backend(),
        )?;
        // Native JSON retains SQL NULL separately from a stored JSON null value.
        let metadata = match org.metadata {
            better_auth_core::SchemaValue::Typed(value) => value,
            better_auth_core::SchemaValue::Dynamic(value) => Some(value),
            better_auth_core::SchemaValue::Undefined => None,
            better_auth_core::SchemaValue::InvalidDate => Some(serde_json::Value::Null),
        };
        if native_metadata {
            active.set(
                O::Organization::column("metadata")?,
                sea_orm::Value::Json(metadata.map(Box::new)),
            );
        }
        active
            .insert(self.connection())
            .await
            .map_err(map_db_err)?
            .record(&config)
    }

    async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<Organization>> {
        let config = self.organization_fields()?.organization;
        models::find::<O::Organization, _>(self.connection(), id)
            .await?
            .map(|row| row.record(&config))
            .transpose()
    }

    async fn get_organization_by_id_value(
        &self,
        id: &serde_json::Value,
    ) -> AuthResult<Option<Organization>> {
        Entity::<O::Organization>::find()
            .filter(super::value_filter::equals(
                O::Organization::column("id")?,
                id,
            ))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
            .map(|row| row.record(&self.organization_fields()?.organization))
            .transpose()
    }

    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Organization>> {
        self.get_organization_by_slug_value(&json!(slug)).await
    }

    async fn get_organization_by_slug_value(
        &self,
        slug: &serde_json::Value,
    ) -> AuthResult<Option<Organization>> {
        let config = self.organization_fields()?.organization;
        let column = O::Organization::column("slug")?;
        let filter = super::value_filter::equals(column, slug);
        Entity::<O::Organization>::find()
            .filter(filter)
            .one(self.connection())
            .await
            .map_err(map_db_err)?
            .map(|row| row.record(&config))
            .transpose()
    }

    async fn list_organizations_by_ids(&self, ids: &[String]) -> AuthResult<Vec<Organization>> {
        let config = self.organization_fields()?.organization;
        models::project::<O::Organization>(
            Entity::<O::Organization>::find()
                .filter(O::Organization::column("id")?.is_in(ids.iter().cloned()))
                .all(self.connection())
                .await
                .map_err(map_db_err)?,
            &config,
        )
    }

    async fn update_organization(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Organization> {
        let config = self.organization_fields()?.organization;
        let mut core = values([("auth_updated_at", json!(Utc::now()))]);
        for (name, value) in [
            ("id", update.id.as_ref().map(|v| json!(v))),
            ("name", update.name.map(|v| json!(v))),
            ("slug", update.slug.map(|v| json!(v))),
            ("logo", update.logo.map(|v| json!(v))),
            ("created_at", update.created_at.map(|v| json!(v))),
        ] {
            if let Some(value) = value {
                let _ = core.insert(name.into(), value);
            }
        }
        let native_metadata = !config.additional_fields.contains_key("metadata")
            && matches!(
                O::Organization::column("metadata")?.def().get_column_type(),
                sea_orm::ColumnType::Json | sea_orm::ColumnType::JsonBinary
            );
        if !native_metadata
            && let Some(value) = better_auth_core::organization_fields::metadata_input(
                update.metadata.clone(),
                false,
            )
        {
            let _ = core.insert("metadata".into(), value);
        }
        let mut active = models::active::<O::Organization>(
            core,
            update.additional_fields,
            &config,
            false,
            self.connection().get_database_backend(),
        )?;
        if native_metadata && let Some(metadata) = update.metadata {
            active.set(
                O::Organization::column("metadata")?,
                sea_orm::Value::Json(Some(Box::new(metadata))),
            );
        }
        let _ = Entity::<O::Organization>::update_many()
            .set(active)
            .filter(O::Organization::column("id")?.eq(id))
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        self.get_organization_by_id(update.id.as_deref().unwrap_or(id))
            .await?
            .ok_or_else(|| AuthError::not_found("Organization not found"))
    }

    async fn delete_organization(&self, id: &str) -> AuthResult<()> {
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        let _ = Entity::<O::Member>::delete_many()
            .filter(O::Member::column("organization_id")?.eq(id))
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        let _ = Entity::<O::Invitation>::delete_many()
            .filter(O::Invitation::column("organization_id")?.eq(id))
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        let _ = Entity::<O::Organization>::delete_many()
            .filter(O::Organization::column("id")?.eq(id))
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        tx.commit().await.map_err(map_db_err)
    }

    async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<Organization>> {
        let config = self.organization_fields()?;
        let members = models::project::<O::Member>(
            Entity::<O::Member>::find()
                .filter(O::Member::column("user_id")?.eq(user_id))
                .all(self.connection())
                .await
                .map_err(map_db_err)?,
            &config.member,
        )?;
        let ids = members
            .iter()
            .map(|member| member.organization_id.typed().cloned())
            .collect::<AuthResult<Vec<_>>>()?;
        let organizations = models::project::<O::Organization>(
            Entity::<O::Organization>::find()
                .filter(O::Organization::column("id")?.is_in(ids.clone()))
                .all(self.connection())
                .await
                .map_err(map_db_err)?,
            &config.organization,
        )?
        .into_iter()
        .map(|organization| (organization.id.as_str().map(str::to_owned), organization))
        .collect::<std::collections::HashMap<_, _>>();
        Ok(ids
            .into_iter()
            .filter_map(|id| organizations.get(&Some(id)).cloned())
            .collect())
    }
}
