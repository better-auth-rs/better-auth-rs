use super::id_filter::IdColumn;
use async_trait::async_trait;
use better_auth_core::store::schema::resolve_field_name;
use chrono::Utc;
use sea_orm::{
    ColumnTrait, DatabaseBackend, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, Select,
};

use better_auth_core::store::{ListOrganizationMembersParams, MemberStore};

use crate::error::{AuthError, AuthResult};
use crate::schema::AuthSchema;
use crate::types_org::{CreateMember, Member};

use super::organization_models::{self as models, Entity, values};
use super::{SeaOrmStore, map_db_err};
use crate::SeaOrmOrganizationModel;
use better_auth_core::{FieldValue, SchemaField};
use sea_orm::sea_query::{BinOper, Expr, ExprTrait};

fn member_column<M: SeaOrmOrganizationModel>(
    field: &str,
    config: &better_auth_core::user_fields::UserConfig,
) -> Option<M::Column> {
    let name = match field {
        "organizationId" => "organization_id",
        "userId" => "user_id",
        "createdAt" => "created_at",
        other => other,
    };
    M::column(resolve_field_name(
        config
            .fields()
            .get(field)
            .and_then(|field| field.field_name.as_deref()),
        name,
    ))
    .ok()
}

fn bind_member_filter(
    params: &ListOrganizationMembersParams,
    config: &better_auth_core::user_fields::UserConfig,
    backend: DatabaseBackend,
    policy: &better_auth_core::id::IdGeneration,
    runtime: &better_auth_core::plugin_runtime::ModelFields,
) -> AuthResult<Option<(super::value_filter::BoundQueryField, bool)>> {
    let (Some(field), Some(value)) = (params.filter_field.as_deref(), params.filter_value.as_ref())
    else {
        return Ok(None);
    };
    let operator = params.filter_operator.as_deref().unwrap_or("eq");
    if operator == "in" && value.as_array().is_none() {
        return Err(better_auth_core::AuthError::internal(
            "Value must be an array",
        ));
    }
    let schema = better_auth_core::store::MemberUser::field_schema(config);
    let before =
        runtime.runtime_fields(better_auth_core::store::schema::EntityRole::Member, &schema)?;
    let (logical, _) = super::value_filter::query_field_name(
        better_auth_core::store::schema::EntityRole::Member,
        &before,
        field,
    )?;
    let id_field = logical == "id"
        || before
            .fields()
            .get(logical)
            .is_some_and(|field| field.references_id());
    let bound = super::value_filter::bind_factory_query_field(
        runtime,
        better_auth_core::store::schema::EntityRole::Member,
        &schema,
        field,
        value,
        policy,
        backend,
    )?;
    Ok(Some((bound, id_field)))
}

fn apply_member_filter<M: SeaOrmOrganizationModel>(
    mut query: Select<Entity<M>>,
    params: &ListOrganizationMembersParams,
    config: &better_auth_core::user_fields::UserConfig,
    backend: DatabaseBackend,
    policy: &better_auth_core::id::IdGeneration,
    bound: Option<(super::value_filter::BoundQueryField, bool)>,
) -> AuthResult<Select<Entity<M>>> {
    use better_auth_core::FieldValue as Value;
    let Some((bound, id_field)) = bound else {
        return Ok(query);
    };
    let operator = params.filter_operator.as_deref().unwrap_or("eq");
    let schema = better_auth_core::store::MemberUser::field_schema(config);
    let (column, bound) =
        bound.resolve(better_auth_core::store::schema::EntityRole::Member, &schema)?;
    let column = M::column(&column)?;
    let value = &bound;
    let id_column = (id_field
        && !matches!(
            column.def().get_column_type(),
            sea_orm::ColumnType::String(_)
                | sea_orm::ColumnType::Text
                | sea_orm::ColumnType::Char(_)
        ))
    .then_some(column);
    let column = Expr::col(column);
    let convert = |value: &Value| -> AuthResult<sea_orm::sea_query::SimpleExpr> {
        if let (Value::String(value), Some(column)) = (value, id_column) {
            return column.id_parameter(value, policy, backend);
        }
        super::record_bindings::parameter(value.clone(), backend)
    };
    if matches!(operator, "in" | "not_in") {
        // The adapter serializes the complete JSON value before Kysely constructs membership lists.
        let values = value
            .as_array()
            .unwrap_or_else(|| std::slice::from_ref(value));
        let values = values.iter().map(convert).collect::<AuthResult<Vec<_>>>()?;
        return Ok(query.filter(super::value_filter::membership(
            column,
            values,
            operator == "not_in",
        )));
    }
    let raw_value = value;
    let value = convert(value)?;
    query = match operator {
        "eq" => query.filter(column.eq(value)),
        "ne" => query.filter(column.ne(value)),
        "gt" => query.filter(column.gt(value)),
        "gte" => query.filter(column.gte(value)),
        "lt" => query.filter(column.lt(value)),
        "lte" => query.filter(column.lte(value)),
        "contains" | "starts_with" | "ends_with" => {
            let (prefix, suffix) = match operator {
                "starts_with" => ("", "%"),
                "ends_with" => ("%", ""),
                _ => ("%", "%"),
            };
            let pattern = super::value_filter::like_pattern(raw_value, prefix, suffix, backend)?;
            query.filter(column.binary(BinOper::Like, pattern))
        }
        _ => query,
    };
    Ok(query)
}

fn apply_member_sort<M: SeaOrmOrganizationModel>(
    query: Select<Entity<M>>,
    params: &ListOrganizationMembersParams,
    config: &better_auth_core::user_fields::UserConfig,
) -> AuthResult<Select<Entity<M>>> {
    let column = params
        .sort_by
        .as_deref()
        .and_then(|field| member_column::<M>(field, config))
        .unwrap_or(M::column("created_at")?);
    let column = Expr::col(column);
    Ok(if params.sort_direction.as_deref() == Some("desc") {
        query.order_by_desc(column)
    } else {
        query.order_by_asc(column)
    })
}

#[async_trait]
impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> MemberStore
    for SeaOrmStore<S, O, P>
where
    S: AuthSchema + Send + Sync,
    S::User: crate::SeaOrmUserModel,
    S::Session: crate::SeaOrmSessionModel,
    S::Account: crate::SeaOrmAccountModel,
    S::Verification: crate::SeaOrmVerificationModel,
{
    async fn insert_member(&self, record: Member) -> AuthResult<Member> {
        let config = self.organization_fields()?.member;
        let core = models::with_id(
            models::values([
                ("organization_id", record.organization_id.into_field_value()),
                ("user_id", record.user_id.into_field_value()),
                ("role", record.role.into_field_value()),
                ("created_at", record.created_at.into_field_value()),
            ]),
            (!record.id.is_undefined()).then(|| record.id.field_value()),
        );
        let row = models::active::<O::Member>(
            core,
            record.additional_fields,
            &config,
            Some("member"),
            self.connection().get_database_backend(),
            self.config().advanced.database.generate_id(),
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::Member,
            ),
        )
        .await?
        .insert(
            self.connection(),
            super::create_readback::CreateReadback {
                schema: &config,
                policy: self.config().advanced.database.generate_id(),
                scope: super::create_readback::ReadbackScope::Direct(self.connection()),
                column: O::Member::column,
            },
        )
        .await?
        .ok_or_else(|| AuthError::internal("Member creation returned no record"))?;
        models::record(
            &row,
            &config,
            self.connection().get_database_backend(),
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::Member,
            ),
        )
        .await
    }

    async fn create_member(&self, member: CreateMember) -> AuthResult<Member> {
        self.create_member_with_connection(
            self.connection(),
            super::create_readback::ReadbackScope::Direct(self.connection()),
            member,
        )
        .await
    }

    async fn get_member_with_user(
        &self,
        organization_id: &str,
        user_id: &str,
    ) -> AuthResult<Option<better_auth_core::store::MemberUser>> {
        let query =
            Entity::<O::Member>::find().filter(self.organization_fields_equal::<O::Member>(
                better_auth_core::store::schema::EntityRole::Member,
                [
                    ("organizationId", &organization_id.into()),
                    ("userId", &user_id.into()),
                ],
            )?);
        self.read_member_user(query, false).await
    }
    async fn get_member_with_user_value(
        &self,
        organization_id: &FieldValue,
        user_id: &FieldValue,
    ) -> AuthResult<Option<better_auth_core::store::MemberUser>> {
        let query =
            Entity::<O::Member>::find().filter(self.organization_fields_equal::<O::Member>(
                better_auth_core::store::schema::EntityRole::Member,
                [("organizationId", organization_id), ("userId", user_id)],
            )?);
        self.read_member_user(query, false).await
    }
    async fn get_member_by_id_with_user(
        &self,
        id: &str,
    ) -> AuthResult<Option<better_auth_core::store::MemberUser>> {
        let query =
            Entity::<O::Member>::find().filter(self.organization_field_equals::<O::Member>(
                better_auth_core::store::schema::EntityRole::Member,
                "id",
                &id.into(),
            )?);
        self.read_member_user(query, true).await
    }

    async fn get_member(&self, organization_id: &str, user_id: &str) -> AuthResult<Option<Member>> {
        let row = Entity::<O::Member>::find()
            .filter(self.organization_fields_equal::<O::Member>(
                better_auth_core::store::schema::EntityRole::Member,
                [
                    ("organizationId", &organization_id.into()),
                    ("userId", &user_id.into()),
                ],
            )?)
            .one(self.connection())
            .await
            .map_err(map_db_err)?;
        match row {
            Some(row) => models::record(
                &row,
                &self.organization_fields()?.member,
                self.connection().get_database_backend(),
                (
                    &self.model_fields,
                    better_auth_core::store::schema::EntityRole::Member,
                ),
            )
            .await
            .map(Some),
            None => Ok(None),
        }
    }

    async fn get_member_value(
        &self,
        organization_id: &FieldValue,
        user_id: &FieldValue,
    ) -> AuthResult<Option<Member>> {
        self.get_member_value_with_connection(self.connection(), organization_id, user_id)
            .await
    }

    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<Member>> {
        let row = Entity::<O::Member>::find()
            .filter(self.organization_field_equals::<O::Member>(
                better_auth_core::store::schema::EntityRole::Member,
                "id",
                &id.into(),
            )?)
            .one(self.connection())
            .await
            .map_err(map_db_err)?;
        match row {
            Some(row) => models::record(
                &row,
                &self.organization_fields()?.member,
                self.connection().get_database_backend(),
                (
                    &self.model_fields,
                    better_auth_core::store::schema::EntityRole::Member,
                ),
            )
            .await
            .map(Some),
            None => Ok(None),
        }
    }

    async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<Member> {
        self.update_member_role_value(&member_id.into(), role).await
    }
    async fn update_member_role_value(
        &self,
        member_id: &better_auth_core::FieldValue,
        role: &str,
    ) -> AuthResult<Member> {
        self.update_organization_model::<O::Member>(
            self.connection(),
            better_auth_core::store::schema::EntityRole::Member,
            member_id,
            values([("role", (role).to_owned().into_field())]),
            Default::default(),
            &self.organization_fields()?.member,
        )
        .await
    }

    async fn delete_member(&self, member_id: &str) -> AuthResult<()> {
        self.delete_member_value(&member_id.into()).await
    }
    async fn delete_member_value(
        &self,
        member_id: &better_auth_core::FieldValue,
    ) -> AuthResult<()> {
        use sea_orm::TransactionTrait;
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        let result = self.delete_member_with_connection(&tx, member_id).await?;
        tx.commit().await.map_err(map_db_err)?;
        Ok(result)
    }

    async fn delete_member_for_user(
        &self,
        member_id: &str,
        organization_id: &str,
        user_id: &str,
    ) -> AuthResult<()> {
        self.delete_member_for_user_value(
            &member_id.into(),
            &organization_id.into(),
            &user_id.into(),
        )
        .await
    }
    async fn delete_member_for_user_value(
        &self,
        member_id: &better_auth_core::FieldValue,
        organization_id: &better_auth_core::FieldValue,
        user_id: &better_auth_core::FieldValue,
    ) -> AuthResult<()> {
        use sea_orm::TransactionTrait;
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        self.delete_member_for_user_with_connection(&tx, member_id, organization_id, user_id)
            .await?;
        tx.commit().await.map_err(map_db_err)
    }

    async fn list_organization_members(&self, organization_id: &str) -> AuthResult<Vec<Member>> {
        self.list_organization_members_value(&organization_id.into())
            .await
    }

    async fn list_organization_members_value(
        &self,
        organization_id: &better_auth_core::FieldValue,
    ) -> AuthResult<Vec<Member>> {
        let rows = Entity::<O::Member>::find()
            .filter(self.organization_field_equals::<O::Member>(
                better_auth_core::store::schema::EntityRole::Member,
                "organizationId",
                organization_id,
            )?)
            .order_by_asc(O::Member::column("created_at")?)
            .all(self.connection())
            .await
            .map_err(map_db_err)?;
        models::project::<O::Member>(
            rows,
            &self.organization_fields()?.member,
            self.connection().get_database_backend(),
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::Member,
            ),
        )
        .await
    }

    async fn query_organization_members(
        &self,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<(Vec<Member>, usize)> {
        let organization = self.bind_organization_query_field(
            better_auth_core::store::schema::EntityRole::Member,
            "organizationId",
            &params.organization_id.field_value(),
        )?;
        let filter = bind_member_filter(
            params,
            &self.organization_fields()?.member,
            self.connection().get_database_backend(),
            self.config().advanced.database.generate_id(),
            &self.model_fields,
        )?;
        let (column, value) = self.resolve_organization_query_field::<O::Member>(
            better_auth_core::store::schema::EntityRole::Member,
            organization,
        )?;
        let base_query = Entity::<O::Member>::find().filter(super::value_filter::equals(
            column,
            &value,
            self.connection().get_database_backend(),
        )?);
        let filtered_query = apply_member_filter::<O::Member>(
            base_query,
            params,
            &self.organization_fields()?.member,
            self.connection().get_database_backend(),
            self.config().advanced.database.generate_id(),
            filter,
        )?;
        let total = filtered_query
            .clone()
            .count(self.connection())
            .await
            .map_err(map_db_err)? as usize;

        let mut query = apply_member_sort::<O::Member>(
            filtered_query,
            params,
            &self.organization_fields()?.member,
        )?;
        let (limit, offset) = super::pagination::sql_pagination(
            self.connection().get_database_backend(),
            params.limit,
            params.offset,
        )?;
        let unbounded_offset = if limit.is_none() {
            offset.unwrap_or(0)
        } else {
            0
        };
        if let Some(offset) = offset.filter(|_| limit.is_some()) {
            query = query.offset(offset);
        }
        if let Some(limit) = limit {
            query = query.limit(limit);
        }

        let rows = query.all(self.connection()).await.map_err(map_db_err)?;
        let skip = std::cmp::min(unbounded_offset, rows.len() as u64) as usize;
        let rows = rows.into_iter().skip(skip).collect();
        Ok((
            models::project::<O::Member>(
                rows,
                &self.organization_fields()?.member,
                self.connection().get_database_backend(),
                (
                    &self.model_fields,
                    better_auth_core::store::schema::EntityRole::Member,
                ),
            )
            .await?,
            total,
        ))
    }

    async fn count_organization_members(&self, organization_id: &str) -> AuthResult<i64> {
        self.count_organization_members_with_connection(
            self.connection(),
            &(organization_id).to_owned().into_field(),
        )
        .await
    }

    async fn count_organization_members_value(
        &self,
        organization_id: &FieldValue,
    ) -> AuthResult<i64> {
        self.count_organization_members_with_connection(self.connection(), organization_id)
            .await
    }
    async fn count_organization_owners(&self, organization_id: &str) -> AuthResult<i64> {
        Entity::<O::Member>::find()
            .filter(self.organization_fields_equal::<O::Member>(
                better_auth_core::store::schema::EntityRole::Member,
                [
                    ("organizationId", &organization_id.into()),
                    ("role", &"owner".into()),
                ],
            )?)
            .count(self.connection())
            .await
            .map(|count| count as i64)
            .map_err(map_db_err)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use better_auth_core::config::AuthConfig;
    use better_auth_core::store::{
        ListOrganizationMembersParams, MemberStore, OrganizationStore, UserStore,
    };
    use better_auth_core::types::{CreateMember, CreateOrganization, CreateUser};

    use crate::Database;
    use crate::store::__private_test_support::bundled_schema::BundledSchema;
    use crate::store::__private_test_support::migrator::run_migrations;

    use super::SeaOrmStore;

    async fn test_store() -> SeaOrmStore<BundledSchema> {
        let database = Database::connect("sqlite::memory:")
            .await
            .expect("sqlite test database should connect");
        run_migrations(&database)
            .await
            .expect("sqlite test migrations should run");
        SeaOrmStore::new(
            Arc::new(AuthConfig::new("test-secret-key-at-least-32-chars-long")),
            database,
        )
    }

    #[tokio::test]
    async fn member_patterns_keep_utf16_until_the_driver_binds_the_complete_pattern()
    -> better_auth_core::AuthResult<()> {
        use crate::store::{entities::member, map_db_err, record_bindings::parameter};
        use better_auth_core::{
            FieldValue, Utf16String, id::IdGeneration, user_fields::UserConfig,
        };
        use sea_orm::{
            ConnectOptions, ConnectionTrait, EntityTrait, QuerySelect, QueryTrait, sea_query::Query,
        };

        for encoding in ["UTF-8", "UTF-16le", "UTF-16be"] {
            let mut options = ConnectOptions::new("sqlite::memory:");
            let _ = options.max_connections(1);
            let database = Database::connect(options).await.map_err(map_db_err)?;
            let _ = database
                .execute_unprepared(&format!("PRAGMA encoding = '{encoding}'"))
                .await
                .map_err(map_db_err)?;
            let _ = database
                .execute_unprepared("CREATE TABLE member (id TEXT, role TEXT)")
                .await
                .map_err(map_db_err)?;
            for (operator, units, actual, matches) in [
                ("contains", vec![0xd800], "x\u{10025}", true),
                ("contains", vec![0xd800], "x\u{10025}y", false),
                ("starts_with", vec![0xd800], "\u{10025}", true),
                ("starts_with", vec![0xd800], "\u{10025}x", false),
                ("ends_with", vec![0xd800], "x\u{fffd}", true),
                ("ends_with", vec![0xd800], "x\u{fffd}y", false),
                ("contains", vec![0xfeff, 0x41], "x\u{feff}A", true),
                ("contains", vec![0xfeff, 0x41], "xA", false),
                ("starts_with", vec![0xfffe], "\u{2500}", true),
                ("starts_with", vec![0xfffe], "plain", false),
                ("starts_with", vec![0x5f], "x", true),
                ("starts_with", vec![0x5f], "", false),
                ("contains", vec![0x5c, 0x5f], "\\x", true),
                ("contains", vec![0x5c, 0x5f], "x", false),
            ] {
                let _ = database
                    .execute_unprepared("DELETE FROM member")
                    .await
                    .map_err(map_db_err)?;
                let insert = Query::insert()
                    .into_table(member::Entity)
                    .columns([member::Column::Id, member::Column::Role])
                    .values_panic([
                        parameter("member".into(), sea_orm::DbBackend::Sqlite)?,
                        parameter(actual.into(), sea_orm::DbBackend::Sqlite)?,
                    ])
                    .to_owned();
                let _ = database
                    .execute_raw(sea_orm::DbBackend::Sqlite.build(&insert))
                    .await
                    .map_err(map_db_err)?;
                let params = ListOrganizationMembersParams {
                    filter_field: Some("role".into()),
                    filter_value: Some(FieldValue::Utf16String(Utf16String::from_units(units))),
                    filter_operator: Some(operator.into()),
                    ..Default::default()
                };
                let filter = super::bind_member_filter(
                    &params,
                    &UserConfig::default(),
                    sea_orm::DbBackend::Sqlite,
                    &IdGeneration::Random,
                    &better_auth_core::plugin_runtime::ModelFields::default(),
                )?;
                let query = super::apply_member_filter::<member::Model>(
                    member::Entity::find()
                        .select_only()
                        .column(member::Column::Id),
                    &params,
                    &UserConfig::default(),
                    sea_orm::DbBackend::Sqlite,
                    &IdGeneration::Random,
                    filter,
                )?;
                let rows = database
                    .query_all_raw(query.build(sea_orm::DbBackend::Sqlite))
                    .await
                    .map_err(map_db_err)?;
                let ids = rows
                    .iter()
                    .map(|row| row.try_get::<String>("", "id").map_err(map_db_err))
                    .collect::<better_auth_core::AuthResult<Vec<_>>>()?;
                assert_eq!(
                    ids,
                    if matches {
                        vec!["member"]
                    } else {
                        Vec::<&str>::new()
                    },
                    "{encoding}: {operator}, {actual:?}"
                );
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn query_organization_members_applies_filter_sort_and_pagination() {
        let store = test_store().await;
        let org_id = "org-1".to_string();
        let _organization = store
            .create_organization(CreateOrganization {
                additional_fields: Default::default(),
                id: Some(org_id.clone()),
                name: "Org".to_string().into(),
                slug: "org".to_string().into(),
                logo: None.into(),
                metadata: None.into(),
            })
            .await
            .expect("organization should be created");
        let _owner = store
            .create_user(CreateUser {
                name: Some("Fixture".into()).into(),
                id: Some("user-owner".to_string()),
                email: Some("owner@example.com".to_string()),
                ..CreateUser::default()
            })
            .await
            .expect("owner should be created");
        let _member = store
            .create_user(CreateUser {
                name: Some("Fixture".into()).into(),
                id: Some("user-member".to_string()),
                email: Some("member@example.com".to_string()),
                ..CreateUser::default()
            })
            .await
            .expect("member should be created");
        let _admin = store
            .create_user(CreateUser {
                name: Some("Fixture".into()).into(),
                id: Some("user-admin".to_string()),
                email: Some("admin@example.com".to_string()),
                ..CreateUser::default()
            })
            .await
            .expect("admin should be created");

        let _ = store
            .create_member(CreateMember::new(&org_id, "user-owner", "owner"))
            .await
            .expect("owner should be created");
        let _ = store
            .create_member(CreateMember::new(&org_id, "user-member", "member"))
            .await
            .expect("member should be created");
        let _ = store
            .create_member(CreateMember::new(&org_id, "user-admin", "admin"))
            .await
            .expect("admin should be created");

        let params = ListOrganizationMembersParams {
            organization_id: org_id.into(),
            limit: Some(1.0),
            offset: Some(1.0),
            sort_by: Some("role".to_string()),
            sort_direction: Some("asc".to_string()),
            filter_field: Some("role".to_string()),
            filter_value: Some("owner".into()),
            filter_operator: Some("ne".to_string()),
        };

        let (members, total) = store
            .query_organization_members(&params)
            .await
            .expect("member query should succeed");

        assert_eq!(total, 2);
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].role, "member");
    }
}

impl<
    S: better_auth_core::AuthSchema,
    O: crate::SeaOrmOrganizationSchema,
    P: crate::SeaOrmPluginSchema,
> SeaOrmStore<S, O, P>
{
    pub(super) async fn create_member_with_connection<C: sea_orm::ConnectionTrait>(
        &self,
        db: &C,
        scope: super::create_readback::ReadbackScope<'_>,
        member: CreateMember,
    ) -> AuthResult<Member> {
        let mut core = values([
            ("organization_id", member.organization_id.into_field_value()),
            ("user_id", member.user_id.into_field_value()),
            ("created_at", FieldValue::Date(Utc::now().into())),
        ]);
        if let Some(role) = Some(member.role.field_value()).filter(|value| !value.is_undefined()) {
            let _ = core.insert("role".into(), role);
        }
        models::insert::<O::Member, _>(
            db,
            scope,
            core,
            member.additional_fields,
            &self.organization_fields()?.member,
            self.config().advanced.database.generate_id(),
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::Member,
                "member",
            ),
        )
        .await
    }

    pub(super) async fn get_member_value_with_connection<C: sea_orm::ConnectionTrait>(
        &self,
        db: &C,
        organization_id: &FieldValue,
        user_id: &FieldValue,
    ) -> AuthResult<Option<Member>> {
        let row = Entity::<O::Member>::find()
            .filter(self.organization_fields_equal::<O::Member>(
                better_auth_core::store::schema::EntityRole::Member,
                [("organizationId", organization_id), ("userId", user_id)],
            )?)
            .one(db)
            .await
            .map_err(map_db_err)?;
        match row {
            Some(row) => models::record(
                &row,
                &self.organization_fields()?.member,
                db.get_database_backend(),
                (
                    &self.model_fields,
                    better_auth_core::store::schema::EntityRole::Member,
                ),
            )
            .await
            .map(Some),
            None => Ok(None),
        }
    }

    pub(super) async fn count_organization_members_with_connection<C: sea_orm::ConnectionTrait>(
        &self,
        db: &C,
        organization_id: &FieldValue,
    ) -> AuthResult<i64> {
        Entity::<O::Member>::find()
            .filter(self.organization_field_equals::<O::Member>(
                better_auth_core::store::schema::EntityRole::Member,
                "organizationId",
                organization_id,
            )?)
            .count(db)
            .await
            .map(|count| count as i64)
            .map_err(map_db_err)
    }

    pub(super) async fn delete_member_with_connection<C: sea_orm::ConnectionTrait>(
        &self,
        db: &C,
        member_id: &better_auth_core::FieldValue,
    ) -> AuthResult<()> {
        let Some(member) = Entity::<O::Member>::find()
            .filter(self.organization_field_equals::<O::Member>(
                better_auth_core::store::schema::EntityRole::Member,
                "id",
                member_id,
            )?)
            .one(db)
            .await
            .map_err(map_db_err)?
        else {
            return Ok(());
        };
        let member = models::record(
            &member,
            &self.organization_fields()?.member,
            db.get_database_backend(),
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::Member,
            ),
        )
        .await?;
        self.delete_member_for_user_with_connection(
            db,
            member_id,
            &member.organization_id.field_value(),
            &member.user_id.field_value(),
        )
        .await
    }

    pub(super) async fn delete_member_for_user_with_connection<C: sea_orm::ConnectionTrait>(
        &self,
        db: &C,
        member_id: &better_auth_core::FieldValue,
        organization_id: &better_auth_core::FieldValue,
        user_id: &better_auth_core::FieldValue,
    ) -> AuthResult<()> {
        let _ = Entity::<O::Member>::delete_many()
            .filter(self.organization_field_equals::<O::Member>(
                better_auth_core::store::schema::EntityRole::Member,
                "id",
                member_id,
            )?)
            .exec(db)
            .await
            .map_err(map_db_err)?;
        let teams = Entity::<O::Team>::find()
            .filter(self.organization_field_equals::<O::Team>(
                better_auth_core::store::schema::EntityRole::Team,
                "organizationId",
                organization_id,
            )?)
            .limit(super::pagination::default_limit(
                &self.config,
                db.get_database_backend(),
            )?)
            .all(db)
            .await
            .map_err(map_db_err)?;
        let teams = models::project::<O::Team>(
            teams,
            &self.organization_fields()?.team,
            db.get_database_backend(),
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::Team,
            ),
        )
        .await?;
        for team in teams {
            self.model_fields
                .begin_id_query(better_auth_core::store::schema::EntityRole::Team)?;
            let _ = Entity::<O::Team>::update_many()
                .col_expr(
                    O::Team::column("member_count")?,
                    Expr::col(O::Team::column("member_count")?),
                )
                .filter(super::value_filter::equals_id(
                    O::Team::column("id")?,
                    &team.id.field_value(),
                    self.config().advanced.database.generate_id(),
                    self.connection().get_database_backend(),
                )?)
                .exec(db)
                .await
                .map_err(map_db_err)?;
            let deleted = Entity::<O::TeamMember>::delete_many()
                .filter(self.organization_fields_equal::<O::TeamMember>(
                    better_auth_core::store::schema::EntityRole::TeamMember,
                    [("teamId", &team.id.field_value()), ("userId", user_id)],
                )?)
                .exec(db)
                .await
                .map_err(map_db_err)?;
            super::team_capacity::release::<O::Team, _>(
                db,
                super::create_readback::ReadbackScope::Transaction,
                &team.id.field_value(),
                deleted.rows_affected,
                &self.organization_fields()?.team,
                self.config().advanced.database.generate_id(),
                (
                    &self.model_fields,
                    better_auth_core::store::schema::EntityRole::Team,
                ),
            )
            .await?;
        }
        Ok(())
    }
}
