use super::id_filter::IdColumn;
use async_trait::async_trait;
use better_auth_core::store::schema::resolve_field_name;
use chrono::Utc;
use sea_orm::{
    ColumnTrait, DatabaseBackend, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, Select,
};

use better_auth_core::store::{ListOrganizationMembersParams, MemberStore};

use crate::error::AuthResult;
use crate::schema::AuthSchema;
use crate::types_org::{CreateMember, Member};

use super::organization_models::{self as models, Entity, values};
use super::{SeaOrmStore, map_db_err};
use crate::SeaOrmOrganizationModel;
use better_auth_core::{FieldValue, SchemaField};
use sea_orm::sea_query::{Expr, ExprTrait, SimpleExpr};

fn member_expression(
    column: impl ColumnTrait,
    field: &str,
    config: &better_auth_core::user_fields::UserConfig,
    backend: DatabaseBackend,
) -> SimpleExpr {
    if backend == DatabaseBackend::Sqlite
        && config.fields().get(field).is_some_and(|field| {
            matches!(
                field.field_type,
                better_auth_core::user_fields::UserFieldType::Json
            )
        })
        && matches!(
            column.def().get_column_type(),
            sea_orm::ColumnType::Json | sea_orm::ColumnType::JsonBinary
        )
    {
        Expr::cust_with_expr("json_extract(?, '$')", Expr::col(column))
    } else {
        Expr::col(column)
    }
}

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

fn apply_member_filter<M: SeaOrmOrganizationModel>(
    mut query: Select<Entity<M>>,
    params: &ListOrganizationMembersParams,
    config: &better_auth_core::user_fields::UserConfig,
    backend: DatabaseBackend,
    policy: &better_auth_core::id::IdGeneration,
) -> AuthResult<Select<Entity<M>>> {
    use better_auth_core::FieldValue as Value;
    use better_auth_core::user_fields::UserFieldType;
    let (Some(field), Some(value)) = (params.filter_field.as_deref(), params.filter_value.as_ref())
    else {
        return Ok(query);
    };
    let Some(column) = member_column::<M>(field, config) else {
        return Ok(query);
    };
    let id_field = matches!(
        M::core_field_name(&column),
        Some("id" | "organizationId" | "userId")
    ) || config
        .fields()
        .get(field)
        .is_some_and(|field| field.references_id());
    let id_column = (id_field
        && !matches!(
            column.def().get_column_type(),
            sea_orm::ColumnType::String(_)
                | sea_orm::ColumnType::Text
                | sea_orm::ColumnType::Char(_)
        ))
    .then_some(column);
    let column = member_expression(column, field, config, backend);
    let field_type = config.fields().get(field).map(|field| &field.field_type);
    let normalize_number = |value: &Value| match value {
        Value::String(value) if matches!(field_type, Some(UserFieldType::Number)) => {
            better_auth_core::organization_fields::numeric_filter(value)
                .map_or_else(|| Value::String(value.clone()), Value::Number)
        }
        value => value.clone(),
    };
    let convert =
        |value: &Value, number_strings: bool| -> AuthResult<sea_orm::sea_query::SimpleExpr> {
            if let (Value::String(value), Some(column)) = (value, id_column) {
                return Ok(column.id_value(value, policy)?.into());
            }
            let value = match value {
                Value::String(value)
                    if number_strings && matches!(field_type, Some(UserFieldType::Boolean)) =>
                {
                    Value::Bool(value == "true")
                }
                value if number_strings => normalize_number(value),
                value => value.clone(),
            };
            super::record_bindings::parameter(value, backend)
        };
    let operator = params.filter_operator.as_deref().unwrap_or("eq");
    if matches!(operator, "in" | "not_in") {
        let values = value
            .as_array()
            .ok_or_else(|| better_auth_core::AuthError::internal("Value must be an array"))?;
        let number_strings = matches!(field_type, Some(UserFieldType::Number))
            && values.iter().all(|value| {
                value
                    .as_str()
                    .and_then(better_auth_core::organization_fields::numeric_filter)
                    .is_some()
            });
        let values = values
            .iter()
            .map(|value| convert(value, number_strings))
            .collect::<AuthResult<Vec<_>>>()?;
        return Ok(query.filter(if operator == "in" {
            column.is_in(values)
        } else {
            column.is_not_in(values)
        }));
    }
    let raw_value = value;
    let value = if field == "createdAt" {
        let Some(parsed) = value
            .as_str()
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        else {
            return Ok(query.filter(Expr::value(false)));
        };
        super::record_bindings::parameter(
            if backend == DatabaseBackend::Sqlite {
                super::record_bindings::sqlite_date(parsed.with_timezone(&Utc).into())?
            } else {
                Value::Date(parsed.with_timezone(&Utc).into())
            },
            backend,
        )?
    } else {
        convert(value, true)?
    };
    query = match operator {
        "eq" => query.filter(column.eq(value)),
        "ne" => query.filter(column.ne(value)),
        "gt" => query.filter(column.gt(value)),
        "gte" => query.filter(column.gte(value)),
        "lt" => query.filter(column.lt(value)),
        "lte" => query.filter(column.lte(value)),
        "contains" | "starts_with" | "ends_with" => {
            let pattern = super::record_bindings::utf16_string(
                &normalize_number(raw_value).display_utf16()?,
                backend,
            );
            let pattern = match operator {
                "starts_with" => format!("{pattern}%"),
                "ends_with" => format!("%{pattern}"),
                _ => format!("%{pattern}%"),
            };
            query.filter(column.like(pattern))
        }
        _ => query,
    };
    Ok(query)
}

fn apply_member_sort<M: SeaOrmOrganizationModel>(
    query: Select<Entity<M>>,
    params: &ListOrganizationMembersParams,
    config: &better_auth_core::user_fields::UserConfig,
    backend: DatabaseBackend,
) -> AuthResult<Select<Entity<M>>> {
    let column = params
        .sort_by
        .as_deref()
        .and_then(|field| member_column::<M>(field, config))
        .unwrap_or(M::column("created_at")?);
    let column = member_expression(
        column,
        params.sort_by.as_deref().unwrap_or("createdAt"),
        config,
        backend,
    );
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
        let core = self.create_fields(
            "member",
            if record.id.is_undefined() {
                None
            } else {
                Some(record.id.typed()?.clone())
            },
            models::values([
                ("organization_id", record.organization_id.into_field_value()),
                ("user_id", record.user_id.into_field_value()),
                ("role", record.role.into_field_value()),
                ("created_at", record.created_at.into_field_value()),
            ]),
        )?;
        models::active::<O::Member>(
            core,
            record.additional_fields,
            &config,
            true,
            self.connection().get_database_backend(),
            self.config().advanced.database.generate_id(),
        )
        .await?
        .insert(self.connection())
        .await?
        .record(&config, self.connection().get_database_backend())
        .await
    }

    async fn create_member(&self, member: CreateMember) -> AuthResult<Member> {
        self.create_member_with_connection(self.connection(), member)
            .await
    }

    async fn get_member_with_user(
        &self,
        organization_id: &str,
        user_id: &str,
    ) -> AuthResult<Option<better_auth_core::store::MemberUser>> {
        let query = Entity::<O::Member>::find()
            .filter(O::Member::column("organization_id")?.eq_id(
                organization_id,
                self.config().advanced.database.generate_id(),
            )?)
            .filter(
                O::Member::column("user_id")?
                    .eq_id(user_id, self.config().advanced.database.generate_id())?,
            );
        self.read_member_user(query, false).await
    }
    async fn get_member_with_user_value(
        &self,
        organization_id: &FieldValue,
        user_id: &FieldValue,
    ) -> AuthResult<Option<better_auth_core::store::MemberUser>> {
        let query = Entity::<O::Member>::find()
            .filter(super::value_filter::equals_id(
                O::Member::column("organization_id")?,
                organization_id,
                self.config().advanced.database.generate_id(),
                self.connection().get_database_backend(),
            )?)
            .filter(super::value_filter::equals_id(
                O::Member::column("user_id")?,
                user_id,
                self.config().advanced.database.generate_id(),
                self.connection().get_database_backend(),
            )?);
        self.read_member_user(query, false).await
    }
    async fn get_member_by_id_with_user(
        &self,
        id: &str,
    ) -> AuthResult<Option<better_auth_core::store::MemberUser>> {
        let query = Entity::<O::Member>::find().filter(
            O::Member::column("id")?.eq_id(id, self.config().advanced.database.generate_id())?,
        );
        self.read_member_user(query, true).await
    }

    async fn get_member(&self, organization_id: &str, user_id: &str) -> AuthResult<Option<Member>> {
        let row = Entity::<O::Member>::find()
            .filter(O::Member::column("organization_id")?.eq_id(
                organization_id,
                self.config().advanced.database.generate_id(),
            )?)
            .filter(
                O::Member::column("user_id")?
                    .eq_id(user_id, self.config().advanced.database.generate_id())?,
            )
            .one(self.connection())
            .await
            .map_err(map_db_err)?;
        match row {
            Some(row) => row
                .record(
                    &self.organization_fields()?.member,
                    self.connection().get_database_backend(),
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
            .filter(
                O::Member::column("id")?
                    .eq_id(id, self.config().advanced.database.generate_id())?,
            )
            .one(self.connection())
            .await
            .map_err(map_db_err)?;
        match row {
            Some(row) => row
                .record(
                    &self.organization_fields()?.member,
                    self.connection().get_database_backend(),
                )
                .await
                .map(Some),
            None => Ok(None),
        }
    }

    async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<Member> {
        models::update::<O::Member, _>(
            self.connection(),
            member_id,
            values([("role", (role).to_owned().into_field())]),
            Default::default(),
            &self.organization_fields()?.member,
            self.config().advanced.database.generate_id(),
        )
        .await
    }

    async fn delete_member(&self, member_id: &str) -> AuthResult<()> {
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
        use sea_orm::TransactionTrait;
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        self.delete_member_for_user_with_connection(&tx, member_id, organization_id, user_id)
            .await?;
        tx.commit().await.map_err(map_db_err)
    }

    async fn list_organization_members(&self, organization_id: &str) -> AuthResult<Vec<Member>> {
        let rows = Entity::<O::Member>::find()
            .filter(O::Member::column("organization_id")?.eq_id(
                organization_id,
                self.config().advanced.database.generate_id(),
            )?)
            .order_by_asc(O::Member::column("created_at")?)
            .all(self.connection())
            .await
            .map_err(map_db_err)?;
        models::project::<O::Member>(
            rows,
            &self.organization_fields()?.member,
            self.connection().get_database_backend(),
        )
        .await
    }

    async fn query_organization_members(
        &self,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<(Vec<Member>, usize)> {
        let base_query =
            Entity::<O::Member>::find().filter(O::Member::column("organization_id")?.eq_id(
                &params.organization_id,
                self.config().advanced.database.generate_id(),
            )?);
        let filtered_query = apply_member_filter::<O::Member>(
            base_query,
            params,
            &self.organization_fields()?.member,
            self.connection().get_database_backend(),
            self.config().advanced.database.generate_id(),
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
            self.connection().get_database_backend(),
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
            .filter(O::Member::column("organization_id")?.eq_id(
                organization_id,
                self.config().advanced.database.generate_id(),
            )?)
            .filter(O::Member::column("role")?.eq("owner"))
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
            organization_id: org_id,
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
        member: CreateMember,
    ) -> AuthResult<Member> {
        let mut core = self.create_fields(
            "member",
            None,
            values([
                ("organization_id", member.organization_id.into_field_value()),
                ("user_id", member.user_id.into_field_value()),
                ("created_at", FieldValue::Date(Utc::now().into())),
            ]),
        )?;
        if let Some(role) = Some(member.role.field_value()).filter(|value| !value.is_undefined()) {
            let _ = core.insert("role".into(), role);
        }
        models::insert::<O::Member, _>(
            db,
            core,
            member.additional_fields,
            &self.organization_fields()?.member,
            self.config().advanced.database.generate_id(),
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
            .filter(super::value_filter::equals_id(
                O::Member::column("organization_id")?,
                organization_id,
                self.config().advanced.database.generate_id(),
                self.connection().get_database_backend(),
            )?)
            .filter(super::value_filter::equals_id(
                O::Member::column("user_id")?,
                user_id,
                self.config().advanced.database.generate_id(),
                self.connection().get_database_backend(),
            )?)
            .one(db)
            .await
            .map_err(map_db_err)?;
        match row {
            Some(row) => row
                .record(
                    &self.organization_fields()?.member,
                    db.get_database_backend(),
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
            .filter(super::value_filter::equals_id(
                O::Member::column("organization_id")?,
                organization_id,
                self.config().advanced.database.generate_id(),
                self.connection().get_database_backend(),
            )?)
            .count(db)
            .await
            .map(|count| count as i64)
            .map_err(map_db_err)
    }

    pub(super) async fn delete_member_with_connection<C: sea_orm::ConnectionTrait>(
        &self,
        db: &C,
        member_id: &str,
    ) -> AuthResult<()> {
        let Some(member) = Entity::<O::Member>::find()
            .filter(
                O::Member::column("id")?
                    .eq_id(member_id, self.config().advanced.database.generate_id())?,
            )
            .one(db)
            .await
            .map_err(map_db_err)?
        else {
            return Ok(());
        };
        let member = member
            .record(
                &self.organization_fields()?.member,
                db.get_database_backend(),
            )
            .await?;
        self.delete_member_for_user_with_connection(
            db,
            member_id,
            member.organization_id.typed()?,
            member.user_id.typed()?,
        )
        .await
    }

    pub(super) async fn delete_member_for_user_with_connection<C: sea_orm::ConnectionTrait>(
        &self,
        db: &C,
        member_id: &str,
        organization_id: &str,
        user_id: &str,
    ) -> AuthResult<()> {
        let _ = Entity::<O::Member>::delete_many()
            .filter(
                O::Member::column("id")?
                    .eq_id(member_id, self.config().advanced.database.generate_id())?,
            )
            .exec(db)
            .await
            .map_err(map_db_err)?;
        let teams = Entity::<O::Team>::find()
            .filter(O::Team::column("organization_id")?.eq_id(
                organization_id,
                self.config().advanced.database.generate_id(),
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
        )
        .await?;
        for team in teams {
            let _ = Entity::<O::Team>::update_many()
                .col_expr(
                    O::Team::column("member_count")?,
                    Expr::col(O::Team::column("member_count")?),
                )
                .filter(O::Team::column("id")?.eq_id(
                    team.id.typed()?,
                    self.config().advanced.database.generate_id(),
                )?)
                .exec(db)
                .await
                .map_err(map_db_err)?;
            let deleted = Entity::<O::TeamMember>::delete_many()
                .filter(O::TeamMember::column("team_id")?.eq_id(
                    team.id.typed()?,
                    self.config().advanced.database.generate_id(),
                )?)
                .filter(
                    O::TeamMember::column("user_id")?
                        .eq_id(user_id, self.config().advanced.database.generate_id())?,
                )
                .exec(db)
                .await
                .map_err(map_db_err)?;
            super::team_capacity::release::<O::Team, _>(
                db,
                team.id.typed()?,
                deleted.rows_affected,
                &self.organization_fields()?.team,
                self.config().advanced.database.generate_id(),
            )
            .await?;
        }
        Ok(())
    }
}
