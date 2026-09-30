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
use chrono::Utc;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use serde_json::json;

#[async_trait]
impl<S: AuthSchema, O: SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> OrganizationRoleStore
    for SeaOrmStore<S, O, P>
{
    async fn create_organization_role(
        &self,
        mut input: CreateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        let config = self.organization_fields()?.organization_role;
        let permission = if config.additional_fields.contains_key("permission") {
            json!(input.permission.to_string())
        } else {
            input.permission
        };
        let mut core = values([
            ("id", json!(uuid::Uuid::new_v4().to_string())),
            ("organizationId", json!(input.organization_id)),
            ("role", json!(input.role)),
            ("permission", permission),
            ("createdAt", json!(Utc::now())),
        ]);
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
        )
        .await
    }
    async fn get_organization_role(&self, id: &str) -> AuthResult<Option<OrganizationRole>> {
        let config = self.organization_fields()?.organization_role;
        models::find::<O::OrganizationRole, _>(self.connection(), id)
            .await?
            .map(|row| row.record(&config))
            .transpose()
    }
    async fn list_organization_roles(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<OrganizationRole>> {
        models::project::<O::OrganizationRole>(
            Entity::<O::OrganizationRole>::find()
                .filter(O::OrganizationRole::column("organization_id")?.eq(organization_id))
                .order_by_asc(O::OrganizationRole::column("created_at")?)
                .all(self.connection())
                .await
                .map_err(map_db_err)?,
            &self.organization_fields()?.organization_role,
        )
    }
    async fn update_organization_role(
        &self,
        id: &str,
        mut input: UpdateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        let config = self.organization_fields()?.organization_role;
        let mut core = Default::default();
        if !config.additional_fields.contains_key("updatedAt") {
            core = values([("updatedAt", json!(Utc::now()))]);
        }
        if let Some(role) = input.role {
            let _ = core.insert("role".into(), json!(role));
        }
        if let Some(permission) = input.permission {
            let value = if config.additional_fields.contains_key("permission") {
                json!(permission.to_string())
            } else {
                permission
            };
            let _ = core.insert("permission".into(), value);
        }
        for name in ["id", "organizationId", "role", "createdAt", "updatedAt"] {
            if let Some(value) = input.additional_fields.remove(name) {
                let _ = core.entry(name).or_insert(value);
            }
        }
        let updated_id = core
            .get("id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(id)
            .to_owned();
        let active =
            models::active::<O::OrganizationRole>(core, input.additional_fields, &config, false)?;
        let _ = Entity::<O::OrganizationRole>::update_many()
            .set(active)
            .filter(O::OrganizationRole::column("id")?.eq(id))
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        models::find::<O::OrganizationRole, _>(self.connection(), &updated_id)
            .await?
            .ok_or_else(|| better_auth_core::AuthError::not_found("Role not found"))?
            .record(&config)
    }
    async fn delete_organization_role(&self, id: &str) -> AuthResult<()> {
        let _ = Entity::<O::OrganizationRole>::delete_many()
            .filter(O::OrganizationRole::column("id")?.eq(id))
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        Ok(())
    }
}
