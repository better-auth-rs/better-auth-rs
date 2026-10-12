use super::{
    SeaOrmStore, map_db_err,
    organization_models::{self as models, Entity, values},
};
use crate::schema::AuthSchema;
use crate::store::query_compile::Execute;
use crate::types_org::{CreateOrganization, Organization, UpdateOrganization};
use crate::{SeaOrmOrganizationModel, SeaOrmOrganizationSchema};
use async_trait::async_trait;
use better_auth_core::{
    AuthError, AuthResult, organization_fields::OrganizationFields, store::OrganizationStore,
};
use better_auth_core::{FieldValue, SchemaField};
use chrono::Utc;
use sea_orm::{EntityTrait, QueryFilter, TransactionTrait};

impl<S: AuthSchema, O: SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmStore<S, O, P>
{
    pub(super) fn set_organization_fields(&self, fields: OrganizationFields) -> AuthResult<()> {
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
}

#[async_trait]
impl<S: AuthSchema, O: SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> OrganizationStore
    for SeaOrmStore<S, O, P>
where
    S::User: crate::SeaOrmUserModel,
    S::Session: crate::SeaOrmSessionModel,
    S::Account: crate::SeaOrmAccountModel,
    S::Verification: crate::SeaOrmVerificationModel,
{
    async fn get_organization_details(
        &self,
        query: better_auth_core::store::OrganizationDetailsQuery<'_>,
    ) -> AuthResult<Option<better_auth_core::store::OrganizationDetails>> {
        self.read_organization_details(query).await
    }

    async fn insert_organization(&self, record: Organization) -> AuthResult<Organization> {
        let config = self.organization_fields()?.organization;
        let core = models::with_id(
            values([
                ("name", record.name.into_field_value()),
                ("slug", record.slug.into_field_value()),
                ("logo", record.logo.into_field_value()),
                ("metadata", record.metadata.into_field_value()),
                ("created_at", record.created_at.into_field_value()),
                ("auth_updated_at", FieldValue::Date((Utc::now()).into())),
            ]),
            (!record.id.is_undefined()).then(|| record.id.field_value()),
        );
        let row = models::active::<O::Organization>(
            core,
            record.additional_fields,
            &config,
            Some("organization"),
            self.connection().get_database_backend(),
            self.config().advanced.database.generate_id(),
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::Organization,
            ),
        )
        .await?
        .insert_raw(
            self.connection(),
            super::create_readback::CreateReadback {
                schema: &config,
                policy: self.config().advanced.database.generate_id(),
                scope: super::create_readback::ReadbackScope::Direct(self.connection()),
                column: O::Organization::column,
            },
        )
        .await?
        .ok_or_else(|| AuthError::internal("Organization creation returned no record"))?;
        models::record::<O::Organization>(
            &row.into(),
            &config,
            self.connection().get_database_backend(),
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::Organization,
            ),
        )
        .await
    }
    async fn delete_organization_records(&self, id: &str) -> AuthResult<()> {
        let _ = Entity::<O::Member>::delete_many()
            .filter(self.organization_field_equals::<O::Member>(
                better_auth_core::store::schema::EntityRole::Member,
                "organizationId",
                &id.into(),
            )?)
            .exec_native(self.connection())
            .await?;
        let _ = Entity::<O::Invitation>::delete_many()
            .filter(self.organization_field_equals::<O::Invitation>(
                better_auth_core::store::schema::EntityRole::Invitation,
                "organizationId",
                &id.into(),
            )?)
            .exec_native(self.connection())
            .await?;
        let _ = Entity::<O::Organization>::delete_many()
            .filter(self.organization_field_equals::<O::Organization>(
                better_auth_core::store::schema::EntityRole::Organization,
                "id",
                &id.into(),
            )?)
            .exec_native(self.connection())
            .await?;
        Ok(())
    }

    fn configure_organization_fields(&self, fields: OrganizationFields) -> AuthResult<()> {
        self.set_organization_fields(fields.into_storage())
    }

    async fn create_organization(&self, org: CreateOrganization) -> AuthResult<Organization> {
        let config = self.organization_fields()?.organization;
        let now = Utc::now();
        let mut core = models::with_id(
            values([
                ("created_at", FieldValue::Date((now).into())),
                ("auth_updated_at", FieldValue::Date((now).into())),
            ]),
            org.id.map(FieldValue::from),
        );
        for (name, value) in [
            (
                "name",
                Some(org.name.field_value()).filter(|value| !value.is_undefined()),
            ),
            (
                "slug",
                Some(org.slug.field_value()).filter(|value| !value.is_undefined()),
            ),
            (
                "logo",
                Some(org.logo.field_value()).filter(|value| !value.is_undefined()),
            ),
        ] {
            if let Some(value) = value {
                let _ = core.insert(name.into(), value);
            }
        }
        if let Some(value) = better_auth_core::organization_fields::metadata_input(
            Some(org.metadata.field_value()).filter(|value| !value.is_undefined()),
            true,
        )? {
            let _ = core.insert("metadata".into(), value);
        }
        let active = models::active::<O::Organization>(
            core,
            org.additional_fields,
            &config,
            Some("organization"),
            self.connection().get_database_backend(),
            self.config().advanced.database.generate_id(),
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::Organization,
            ),
        )
        .await?;
        let row = active
            .insert_raw(
                self.connection(),
                super::create_readback::CreateReadback {
                    schema: &config,
                    policy: self.config().advanced.database.generate_id(),
                    scope: super::create_readback::ReadbackScope::Direct(self.connection()),
                    column: O::Organization::column,
                },
            )
            .await?
            .ok_or_else(|| AuthError::internal("Organization creation returned no record"))?;
        models::record::<O::Organization>(
            &row.into(),
            &config,
            self.connection().get_database_backend(),
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::Organization,
            ),
        )
        .await
    }

    async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<Organization>> {
        self.get_organization_by_id_value(&id.into()).await
    }

    async fn get_organization_by_id_value(
        &self,
        id: &FieldValue,
    ) -> AuthResult<Option<Organization>> {
        self.get_organization_by_id_value_with_connection(self.connection(), id)
            .await
    }

    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Organization>> {
        self.get_organization_by_slug_value(&(slug).to_owned().into_field())
            .await
    }

    async fn get_organization_by_slug_value(
        &self,
        slug: &FieldValue,
    ) -> AuthResult<Option<Organization>> {
        let config = self.organization_fields()?.organization;
        let filter = self.organization_field_equals::<O::Organization>(
            better_auth_core::store::schema::EntityRole::Organization,
            "slug",
            slug,
        )?;
        let row = super::plugin_rows::one(
            self.connection(),
            super::plugin_rows::select_all::<Entity<O::Organization>>().filter(filter),
        )
        .await?;
        match row {
            Some(row) => models::record::<O::Organization>(
                &row,
                &config,
                self.connection().get_database_backend(),
                (
                    &self.model_fields,
                    better_auth_core::store::schema::EntityRole::Organization,
                ),
            )
            .await
            .map(Some),
            None => Ok(None),
        }
    }

    async fn list_organizations_by_ids(&self, ids: &[String]) -> AuthResult<Vec<Organization>> {
        let config = self.organization_fields()?.organization;
        let bound = self.bind_organization_query_field(
            better_auth_core::store::schema::EntityRole::Organization,
            "id",
            &FieldValue::Array(ids.iter().map(|id| id.as_str().into()).collect()),
        )?;
        let (column, value) = self.resolve_organization_query_field::<O::Organization>(
            better_auth_core::store::schema::EntityRole::Organization,
            bound,
        )?;
        models::project::<O::Organization>(
            super::plugin_rows::all(
                self.connection(),
                super::plugin_rows::select_all::<Entity<O::Organization>>().filter(
                    super::value_filter::is_in(
                        column,
                        &value,
                        self.connection().get_database_backend(),
                    )?,
                ),
            )
            .await?,
            &config,
            self.connection().get_database_backend(),
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::Organization,
            ),
        )
        .await
    }

    async fn update_organization(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Organization> {
        self.update_organization_value(&id.into(), update).await
    }

    async fn update_organization_value(
        &self,
        id: &better_auth_core::FieldValue,
        update: UpdateOrganization,
    ) -> AuthResult<Organization> {
        let config = self.organization_fields()?.organization;
        let mut core = values([("auth_updated_at", FieldValue::Date((Utc::now()).into()))]);
        for (name, value) in [
            ("id", update.id.as_ref().map(|v| v.to_owned().into_field())),
            ("name", update.name.map(|v| v.to_owned().into_field())),
            ("slug", update.slug.map(|v| v.to_owned().into_field())),
            ("logo", update.logo.map(|v| v.to_owned().into_field())),
            (
                "created_at",
                update.created_at.map(|v| v.to_owned().into_field()),
            ),
        ] {
            if let Some(value) = value {
                let _ = core.insert(name.into(), value);
            }
        }
        if let Some(value) =
            better_auth_core::organization_fields::metadata_input(update.metadata, false)?
        {
            let _ = core.insert("metadata".into(), value);
        }
        self.update_organization_model::<O::Organization>(
            self.connection(),
            better_auth_core::store::schema::EntityRole::Organization,
            id,
            core,
            update.additional_fields,
            &config,
        )
        .await
    }

    async fn delete_organization(&self, id: &str) -> AuthResult<()> {
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        let _ = Entity::<O::Member>::delete_many()
            .filter(self.organization_field_equals::<O::Member>(
                better_auth_core::store::schema::EntityRole::Member,
                "organizationId",
                &id.into(),
            )?)
            .exec_native(&tx)
            .await?;
        let _ = Entity::<O::Invitation>::delete_many()
            .filter(self.organization_field_equals::<O::Invitation>(
                better_auth_core::store::schema::EntityRole::Invitation,
                "organizationId",
                &id.into(),
            )?)
            .exec_native(&tx)
            .await?;
        let _ = Entity::<O::Organization>::delete_many()
            .filter(self.organization_field_equals::<O::Organization>(
                better_auth_core::store::schema::EntityRole::Organization,
                "id",
                &id.into(),
            )?)
            .exec_native(&tx)
            .await?;
        tx.commit().await.map_err(map_db_err)
    }

    async fn list_user_organizations(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<better_auth_core::store::JoinValue<better_auth_core::FieldMap>>> {
        self.list_user_organizations_value(&user_id.into()).await
    }

    async fn list_user_organizations_value(
        &self,
        user_id: &better_auth_core::FieldValue,
    ) -> AuthResult<Vec<better_auth_core::store::JoinValue<better_auth_core::FieldMap>>> {
        self.list_member_organizations(user_id).await
    }
}

impl<
    S: better_auth_core::AuthSchema,
    O: crate::SeaOrmOrganizationSchema,
    P: crate::SeaOrmPluginSchema,
> SeaOrmStore<S, O, P>
{
    pub(super) async fn get_organization_by_id_value_with_connection<
        C: sea_orm::ConnectionTrait,
    >(
        &self,
        db: &C,
        id: &FieldValue,
    ) -> AuthResult<Option<Organization>> {
        let row = super::plugin_rows::one(
            db,
            super::plugin_rows::select_all::<Entity<O::Organization>>().filter(
                self.organization_field_equals::<O::Organization>(
                    better_auth_core::store::schema::EntityRole::Organization,
                    "id",
                    id,
                )?,
            ),
        )
        .await?;
        match row {
            Some(row) => models::record::<O::Organization>(
                &row,
                &self.organization_fields()?.organization,
                db.get_database_backend(),
                (
                    &self.model_fields,
                    better_auth_core::store::schema::EntityRole::Organization,
                ),
            )
            .await
            .map(Some),
            None => Ok(None),
        }
    }
}
