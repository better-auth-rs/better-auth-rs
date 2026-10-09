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
use better_auth_core::{FieldMap, FieldValue, SchemaField, store::schema::EntityRole};
use chrono::Utc;
use sea_orm::{Condition, EntityTrait, FromQueryResult, PaginatorTrait, QueryFilter, QuerySelect};

impl<S: AuthSchema, O: SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmStore<S, O, P>
{
    fn organization_role_filter(&self, selectors: &FieldMap) -> AuthResult<Condition> {
        self.resolve_organization_role_filter(self.bind_organization_role_filter(selectors)?)
    }

    fn bind_organization_role_filter(
        &self,
        selectors: &FieldMap,
    ) -> AuthResult<Vec<super::value_filter::BoundQueryField>> {
        let fields = self
            .organization_fields()?
            .query_schema_for(EntityRole::OrganizationRole)?;
        let backend = self.connection().get_database_backend();
        selectors
            .iter()
            .map(|(name, value)| {
                self.bind_query_field(EntityRole::OrganizationRole, &fields, name, value, backend)
            })
            .collect()
    }

    fn resolve_organization_role_filter(
        &self,
        selectors: Vec<super::value_filter::BoundQueryField>,
    ) -> AuthResult<Condition> {
        let fields = self
            .organization_fields()?
            .query_schema_for(EntityRole::OrganizationRole)?;
        let backend = self.connection().get_database_backend();
        selectors
            .into_iter()
            .try_fold(Condition::all(), |condition, selector| {
                let (column, value) = selector.resolve(EntityRole::OrganizationRole, &fields)?;
                Ok(condition.add(super::value_filter::equals(
                    O::OrganizationRole::column(&column)?,
                    &value,
                    backend,
                )?))
            })
    }

    async fn organization_role_write(
        &self,
        mut input: UpdateOrganizationRole,
    ) -> AuthResult<super::record_write::RecordWrite<Entity<O::OrganizationRole>>> {
        let config = self.organization_fields()?.organization_role;
        let mut core = FieldMap::new();
        if let Some(role) = input.role {
            let _ = core.insert("role".into(), role.into());
        }
        if let Some(permission) = input.permission {
            let _ = core.insert(
                "permission".into(),
                permission
                    .stringify()?
                    .map(FieldValue::String)
                    .unwrap_or_default(),
            );
        }
        for field in better_auth_core::store::schema::core_fields(EntityRole::OrganizationRole) {
            let column = O::OrganizationRole::column(field.name)?;
            if let Some(name) = O::OrganizationRole::core_field_name(&column)
                && let Some(value) = input.additional_fields.remove(name)
            {
                let _ = core.entry(name.to_owned()).or_insert(value);
            }
        }
        models::active::<O::OrganizationRole>(
            core,
            input.additional_fields,
            &config,
            false,
            self.connection().get_database_backend(),
            self.config().advanced.database.generate_id(),
        )
        .await
    }
}

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
            super::create_readback::ReadbackScope::Direct(self.connection()),
            core,
            input.additional_fields,
            &config,
            self.config().advanced.database.generate_id(),
        )
        .await
    }
    async fn get_organization_role(&self, id: &str) -> AuthResult<Option<OrganizationRole>> {
        self.find_organization_role_by_fields(&[("id".into(), id.into())].into())
            .await
    }
    async fn find_organization_role_by_fields(
        &self,
        selectors: &FieldMap,
    ) -> AuthResult<Option<OrganizationRole>> {
        let config = self.organization_fields()?.organization_role;
        let row = Entity::<O::OrganizationRole>::find()
            .filter(self.organization_role_filter(selectors)?)
            .one(self.connection())
            .await
            .map_err(map_db_err)?;
        match row {
            Some(row) => row
                .record(&config, self.connection().get_database_backend())
                .await
                .map(Some),
            None => Ok(None),
        }
    }
    async fn list_organization_roles(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<OrganizationRole>> {
        self.list_organization_roles_value(&organization_id.into())
            .await
    }
    async fn list_organization_roles_value(
        &self,
        organization_id: &better_auth_core::FieldValue,
    ) -> AuthResult<Vec<OrganizationRole>> {
        let rows = Entity::<O::OrganizationRole>::find()
            .filter(self.organization_field_equals::<O::OrganizationRole>(
                EntityRole::OrganizationRole,
                "organizationId",
                organization_id,
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
            self.connection().get_database_backend(),
        )
        .await
    }
    async fn query_organization_roles(
        &self,
        organization_id: &str,
        names: &[String],
    ) -> AuthResult<Vec<OrganizationRole>> {
        self.query_organization_roles_value(&organization_id.into(), names)
            .await
    }

    async fn query_organization_roles_value(
        &self,
        organization_id: &better_auth_core::FieldValue,
        names: &[String],
    ) -> AuthResult<Vec<OrganizationRole>> {
        let organization = self.bind_organization_query_field(
            EntityRole::OrganizationRole,
            "organizationId",
            organization_id,
        )?;
        let names = self.bind_organization_query_field(
            EntityRole::OrganizationRole,
            "role",
            &FieldValue::Array(names.iter().map(|name| name.as_str().into()).collect()),
        )?;
        let (organization_column, organization) = self
            .resolve_organization_query_field::<O::OrganizationRole>(
                EntityRole::OrganizationRole,
                organization,
            )?;
        let (role_column, names) = self.resolve_organization_query_field::<O::OrganizationRole>(
            EntityRole::OrganizationRole,
            names,
        )?;
        let backend = self.connection().get_database_backend();
        let rows = Entity::<O::OrganizationRole>::find()
            .filter(super::value_filter::equals(
                organization_column,
                &organization,
                backend,
            )?)
            .filter(super::value_filter::is_in(role_column, &names, backend)?)
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
            self.connection().get_database_backend(),
        )
        .await
    }
    async fn find_organization_role(
        &self,
        organization_id: &str,
        key: better_auth_core::store::OrganizationRoleKey<'_>,
    ) -> AuthResult<Option<OrganizationRole>> {
        self.find_organization_role_value(&organization_id.into(), key)
            .await
    }

    async fn find_organization_role_value(
        &self,
        organization_id: &better_auth_core::FieldValue,
        key: better_auth_core::store::OrganizationRoleKey<'_>,
    ) -> AuthResult<Option<OrganizationRole>> {
        use better_auth_core::store::OrganizationRoleKey;
        let (name, value) = match key {
            OrganizationRoleKey::Id(id) => ("id", id),
            OrganizationRoleKey::Name(name) => ("role", name),
        };
        self.find_organization_role_by_fields(
            &[
                ("organizationId".into(), organization_id.clone()),
                (name.into(), value.into()),
            ]
            .into(),
        )
        .await
    }
    async fn count_organization_roles(&self, organization_id: &str) -> AuthResult<u64> {
        self.count_organization_roles_value(&organization_id.into())
            .await
    }

    async fn count_organization_roles_value(
        &self,
        organization_id: &better_auth_core::FieldValue,
    ) -> AuthResult<u64> {
        Entity::<O::OrganizationRole>::find()
            .filter(self.organization_field_equals::<O::OrganizationRole>(
                EntityRole::OrganizationRole,
                "organizationId",
                organization_id,
            )?)
            .count(self.connection())
            .await
            .map_err(map_db_err)
    }
    async fn update_organization_role(
        &self,
        id: &str,
        input: UpdateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        self.update_organization_role_value(&id.into(), input).await
    }
    async fn update_organization_role_value(
        &self,
        id: &FieldValue,
        input: UpdateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        let config = self.organization_fields()?.organization_role;
        let backend = self.connection().get_database_backend();
        let schema = self
            .organization_fields()?
            .query_schema_for(EntityRole::OrganizationRole)?;
        let selector =
            self.bind_query_field(EntityRole::OrganizationRole, &schema, "id", id, backend)?;
        let active = self.organization_role_write(input).await?;
        let (column, value) = selector.resolve(EntityRole::OrganizationRole, &schema)?;
        let selector =
            super::value_filter::equals(O::OrganizationRole::column(&column)?, &value, backend)?;
        let row = super::updates::execute_update_returning_raw::<Entity<O::OrganizationRole>, _>(
            self.connection(),
            active.update_returning(backend)?.filter(selector.clone()),
            selector,
        )
        .await?
        .ok_or_else(|| better_auth_core::AuthError::not_found("Role not found"))?;
        O::OrganizationRole::from_query_result(&row, "")
            .map_err(map_db_err)?
            .record(&config, backend)
            .await
    }
    async fn update_organization_roles(
        &self,
        selectors: &FieldMap,
        input: UpdateOrganizationRole,
    ) -> AuthResult<u64> {
        let selectors = self.bind_organization_role_filter(selectors)?;
        let active = self.organization_role_write(input).await?;
        let selectors = self.resolve_organization_role_filter(selectors)?;
        active
            .update(self.connection().get_database_backend())?
            .filter(selectors)
            .exec(self.connection())
            .await
            .map(|result| std::cmp::min(result.rows_affected, 9_007_199_254_740_991))
            .map_err(map_db_err)
    }
    async fn delete_organization_role(&self, id: &str) -> AuthResult<()> {
        self.delete_organization_role_by_fields(&[("id".into(), id.into())].into())
            .await
    }
    async fn delete_organization_role_by_fields(&self, selectors: &FieldMap) -> AuthResult<()> {
        let _ = Entity::<O::OrganizationRole>::delete_many()
            .filter(self.organization_role_filter(selectors)?)
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::{
        AuthConfig, CreateOrganization,
        organization_fields::OrganizationFields,
        store::OrganizationStore,
        user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[tokio::test]
    async fn role_mutations_preserve_scope_skip_batch_projection_and_read_changed_native_id() {
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        super::super::migrator::run_migrations(&db).await.unwrap();
        let store = SeaOrmStore::<super::super::bundled_schema::BundledSchema>::new(
            Arc::new(AuthConfig::new(
                "organization-role-native-secret-at-least-32-characters",
            )),
            db,
        );
        for id in ["first-org", "second-org"] {
            let _ = store
                .create_organization(CreateOrganization {
                    id: Some(id.into()),
                    ..CreateOrganization::new(id, id)
                })
                .await
                .unwrap();
        }
        let outputs = Arc::new(AtomicUsize::new(0));
        let counter = outputs.clone();
        store
            .configure_organization_fields(OrganizationFields {
                organization_role: UserConfig {
                    additional_fields: Some(
                        [(
                            "permission".into(),
                            UserFieldConfig {
                                transform: Some(FieldTransforms {
                                    input: None,
                                    output: Some(UserFieldTransform::new(move |value| {
                                        let _ = counter.fetch_add(1, Ordering::SeqCst);
                                        Ok(value)
                                    })),
                                }),
                                ..Default::default()
                            },
                        )]
                        .into(),
                    ),
                },
                ..Default::default()
            })
            .unwrap();
        let mut ids = Vec::new();
        for organization_id in ["first-org", "second-org"] {
            ids.push(
                store
                    .create_organization_role(CreateOrganizationRole {
                        organization_id: organization_id.into(),
                        role: "editor".into(),
                        permission: FieldMap::new().into(),
                        additional_fields: FieldMap::new(),
                    })
                    .await
                    .unwrap()
                    .id,
            );
        }
        outputs.store(0, Ordering::SeqCst);
        let first: FieldMap = [
            ("organizationId".into(), "first-org".into()),
            ("role".into(), "editor".into()),
        ]
        .into();
        assert_eq!(
            store
                .update_organization_roles(
                    &first,
                    UpdateOrganizationRole {
                        role: Some("writer".into()),
                        ..Default::default()
                    }
                )
                .await
                .unwrap(),
            1
        );
        assert_eq!(outputs.load(Ordering::SeqCst), 0);
        let updated = store
            .update_organization_role_value(
                &ids.first().unwrap().field_value(),
                UpdateOrganizationRole {
                    additional_fields: [("id".into(), FieldValue::Number(23.0))].into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_ne!(updated.id, *ids.first().unwrap());
        assert_eq!(updated.role, "writer");
        assert_eq!(outputs.load(Ordering::SeqCst), 1);
        let updated_id: FieldMap = [("id".into(), FieldValue::Number(23.0))].into();
        let mismatched: FieldMap = [
            ("organizationId".into(), "second-org".into()),
            ("id".into(), FieldValue::Number(23.0)),
        ]
        .into();
        store
            .delete_organization_role_by_fields(&mismatched)
            .await
            .unwrap();
        assert!(
            store
                .find_organization_role_by_fields(&updated_id)
                .await
                .unwrap()
                .is_some()
        );
        let first: FieldMap = [
            ("organizationId".into(), "first-org".into()),
            ("id".into(), FieldValue::Number(23.0)),
        ]
        .into();
        store
            .delete_organization_role_by_fields(&first)
            .await
            .unwrap();
        assert!(
            store
                .find_organization_role_by_fields(&updated_id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .get_organization_role(ids.last().unwrap().typed().unwrap())
                .await
                .unwrap()
                .unwrap()
                .role,
            "editor"
        );
    }
}
