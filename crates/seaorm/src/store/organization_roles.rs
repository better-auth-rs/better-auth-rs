use super::id_filter::IdColumn;
use super::{
    SeaOrmStore, map_db_err,
    organization_models::{self as models, Entity, values},
};
use crate::schema::AuthSchema;
use crate::{SeaOrmOrganizationModel, SeaOrmOrganizationSchema};
use async_trait::async_trait;
use better_auth_core::{
    AuthResult, CreateOrganizationRole, OrganizationRole, UpdateOrganizationRole,
    store::OrganizationRoleStore,
};
use better_auth_core::{FieldValue, SchemaField};
use chrono::Utc;
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QuerySelect};

#[async_trait]
impl<S: AuthSchema, O: SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> OrganizationRoleStore
    for SeaOrmStore<S, O, P>
{
    async fn create_organization_role(
        &self,
        mut input: CreateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        let config = self.organization_fields()?.organization_role;
        let permission = input
            .permission
            .stringify()?
            .map(FieldValue::String)
            .unwrap_or_default();
        let mut core = self.create_fields(
            "organizationRole",
            None,
            values([
                ("organizationId", (input.organization_id).into_field()),
                ("role", (input.role).into_field()),
                ("permission", permission),
                ("createdAt", FieldValue::Date((Utc::now()).into())),
            ]),
        )?;
        for name in [
            "organizationId",
            "role",
            "permission",
            "createdAt",
            "updatedAt",
        ] {
            if let Some(value) = input.additional_fields.remove(name) {
                let _ = core.insert(name.into(), value);
            }
        }
        models::insert::<O::OrganizationRole, _>(
            self.connection(),
            core,
            input.additional_fields,
            &config,
            self.config().advanced.database.generate_id(),
        )
        .await
    }
    async fn get_organization_role(&self, id: &str) -> AuthResult<Option<OrganizationRole>> {
        let config = self.organization_fields()?.organization_role;
        let row = models::find::<O::OrganizationRole, _>(
            self.connection(),
            id,
            self.config().advanced.database.generate_id(),
        )
        .await?;
        match row {
            Some(row) => row
                .record(
                    &config,
                    self.connection().get_database_backend() == sea_orm::DbBackend::Postgres,
                )
                .await
                .map(Some),
            None => Ok(None),
        }
    }
    async fn list_organization_roles(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<OrganizationRole>> {
        let rows = Entity::<O::OrganizationRole>::find()
            .filter(O::OrganizationRole::column("organization_id")?.eq_id(
                organization_id,
                self.config().advanced.database.generate_id(),
            )?)
            .limit(super::pagination::default_limit(
                self.config(),
                self.connection().get_database_backend(),
            )?)
            .all(self.connection())
            .await
            .map_err(map_db_err)?;
        models::project::<O::OrganizationRole>(
            rows,
            &self.organization_fields()?.organization_role,
            self.connection().get_database_backend() == sea_orm::DbBackend::Postgres,
        )
        .await
    }
    async fn query_organization_roles(
        &self,
        organization_id: &str,
        names: &[String],
    ) -> AuthResult<Vec<OrganizationRole>> {
        let rows = Entity::<O::OrganizationRole>::find()
            .filter(O::OrganizationRole::column("organization_id")?.eq_id(
                organization_id,
                self.config().advanced.database.generate_id(),
            )?)
            .filter(O::OrganizationRole::column("role")?.is_in(names.iter().cloned()))
            .limit(super::pagination::default_limit(
                self.config(),
                self.connection().get_database_backend(),
            )?)
            .all(self.connection())
            .await
            .map_err(map_db_err)?;
        models::project::<O::OrganizationRole>(
            rows,
            &self.organization_fields()?.organization_role,
            self.connection().get_database_backend() == sea_orm::DbBackend::Postgres,
        )
        .await
    }
    async fn find_organization_role(
        &self,
        organization_id: &str,
        key: better_auth_core::store::OrganizationRoleKey<'_>,
    ) -> AuthResult<Option<OrganizationRole>> {
        use better_auth_core::store::OrganizationRoleKey;
        let condition = match key {
            OrganizationRoleKey::Id(id) => O::OrganizationRole::column("id")?
                .eq_id(id, self.config().advanced.database.generate_id())?,
            OrganizationRoleKey::Name(name) => O::OrganizationRole::column("role")?.eq(name),
        };
        let row = Entity::<O::OrganizationRole>::find()
            .filter(O::OrganizationRole::column("organization_id")?.eq_id(
                organization_id,
                self.config().advanced.database.generate_id(),
            )?)
            .filter(condition)
            .one(self.connection())
            .await
            .map_err(map_db_err)?;
        match row {
            Some(row) => row
                .record(
                    &self.organization_fields()?.organization_role,
                    self.connection().get_database_backend() == sea_orm::DbBackend::Postgres,
                )
                .await
                .map(Some),
            None => Ok(None),
        }
    }
    async fn count_organization_roles(&self, organization_id: &str) -> AuthResult<u64> {
        Entity::<O::OrganizationRole>::find()
            .filter(O::OrganizationRole::column("organization_id")?.eq_id(
                organization_id,
                self.config().advanced.database.generate_id(),
            )?)
            .count(self.connection())
            .await
            .map_err(map_db_err)
    }
    async fn update_organization_role(
        &self,
        id: &str,
        mut input: UpdateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        let config = self.organization_fields()?.organization_role;
        let mut core = Default::default();
        if !config.fields().contains_key("updatedAt") {
            core = values([("updatedAt", FieldValue::Date((Utc::now()).into()))]);
        }
        if let Some(role) = input.role {
            let _ = core.insert("role".into(), (role).to_owned().into_field());
        }
        if let Some(permission) = input.permission {
            let value = permission
                .stringify()?
                .map(FieldValue::String)
                .unwrap_or_default();
            let _ = core.insert("permission".into(), value);
        }
        for name in ["id", "organizationId", "role", "createdAt", "updatedAt"] {
            if let Some(value) = input.additional_fields.remove(name) {
                let _ = core.entry(name).or_insert(value);
            }
        }
        let updated_id = core
            .get("id")
            .and_then(FieldValue::as_str)
            .unwrap_or(id)
            .to_owned();
        let active = models::active::<O::OrganizationRole>(
            core,
            input.additional_fields,
            &config,
            false,
            self.connection().get_database_backend(),
            self.config().advanced.database.generate_id(),
        )
        .await?;
        let _ = active
            .update(self.connection().get_database_backend())?
            .filter(
                O::OrganizationRole::column("id")?
                    .eq_id(id, self.config().advanced.database.generate_id())?,
            )
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        models::find::<O::OrganizationRole, _>(
            self.connection(),
            &updated_id,
            self.config().advanced.database.generate_id(),
        )
        .await?
        .ok_or_else(|| better_auth_core::AuthError::not_found("Role not found"))?
        .record(
            &config,
            self.connection().get_database_backend() == sea_orm::DbBackend::Postgres,
        )
        .await
    }
    async fn delete_organization_role(&self, id: &str) -> AuthResult<()> {
        let _ = Entity::<O::OrganizationRole>::delete_many()
            .filter(
                O::OrganizationRole::column("id")?
                    .eq_id(id, self.config().advanced.database.generate_id())?,
            )
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        Ok(())
    }
}
