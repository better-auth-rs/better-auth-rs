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
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, TransactionTrait,
};
use serde_json::json;

#[async_trait]
impl<S: AuthSchema, O: SeaOrmOrganizationSchema> OrganizationStore for SeaOrmStore<S, O> {
    fn configure_organization_fields(&self, fields: OrganizationFields) -> AuthResult<()> {
        let fields = fields.into_storage()?;
        models::validate_fields::<O::Organization>("organization", &fields.organization)?;
        models::validate_fields::<O::Member>("member", &fields.member)?;
        models::validate_fields::<O::Invitation>("invitation", &fields.invitation)?;
        models::validate_fields::<O::Team>("team", &fields.team)?;
        models::validate_fields::<O::OrganizationRole>(
            "organizationRole",
            &fields.organization_role,
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
        let mut core = values([
            (
                "id",
                json!(org.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
            ),
            ("name", json!(org.name)),
            ("slug", json!(org.slug)),
            ("created_at", json!(now)),
            ("updated_at", json!(now)),
        ]);
        if let Some(logo) = org.logo {
            let _ = core.insert("logo".into(), json!(logo));
        }
        if config.additional_fields.contains_key("updatedAt") {
            let _ = core.remove("updated_at");
        }
        let mut active =
            models::active::<O::Organization>(core, org.additional_fields, &config, true)?;
        // Native JSON retains SQL NULL separately from a stored JSON null value.
        active.set(
            O::Organization::column("metadata")?,
            sea_orm::Value::Json(org.metadata.map(Box::new)),
        );
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

    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Organization>> {
        let config = self.organization_fields()?.organization;
        Entity::<O::Organization>::find()
            .filter(O::Organization::column("slug")?.eq(slug))
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
        let mut core = Default::default();
        if !config.additional_fields.contains_key("updatedAt") {
            core = values([("updated_at", json!(Utc::now()))]);
        }
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
        let mut active =
            models::active::<O::Organization>(core, update.additional_fields, &config, false)?;
        if let Some(metadata) = update.metadata {
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
        let ids = members.into_iter().map(|member| member.organization_id);
        models::project::<O::Organization>(
            Entity::<O::Organization>::find()
                .filter(O::Organization::column("id")?.is_in(ids))
                .order_by_asc(O::Organization::column("created_at")?)
                .all(self.connection())
                .await
                .map_err(map_db_err)?,
            &config.organization,
        )
    }
}
