use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ColumnTrait, DatabaseBackend, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, Select,
};
use uuid::Uuid;

use better_auth_core::store::{ListOrganizationMembersParams, MemberStore};

use crate::error::AuthResult;
use crate::schema::AuthSchema;
use crate::types_org::{CreateMember, Member};

use super::organization_models::{self as models, Entity, values};
use super::{SeaOrmStore, map_db_err};
use crate::SeaOrmOrganizationModel;
use sea_orm::sea_query::{Expr, ExprTrait, SimpleExpr};
use serde_json::json;

fn member_expression(
    column: impl ColumnTrait,
    field: &str,
    config: &better_auth_core::user_fields::UserConfig,
    backend: DatabaseBackend,
) -> SimpleExpr {
    if backend == DatabaseBackend::Sqlite
        && config.additional_fields.get(field).is_some_and(|field| {
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
    M::column(
        config
            .additional_fields
            .get(field)
            .and_then(|field| field.field_name.as_deref())
            .unwrap_or(name),
    )
    .ok()
}

fn apply_member_filter<M: SeaOrmOrganizationModel>(
    mut query: Select<Entity<M>>,
    params: &ListOrganizationMembersParams,
    config: &better_auth_core::user_fields::UserConfig,
    backend: DatabaseBackend,
) -> AuthResult<Select<Entity<M>>> {
    use better_auth_core::user_fields::UserFieldType;
    use serde_json::Value;
    let (Some(field), Some(value)) = (params.filter_field.as_deref(), params.filter_value.as_ref())
    else {
        return Ok(query);
    };
    let Some(column) = member_column::<M>(field, config) else {
        return Ok(query);
    };
    let column = member_expression(column, field, config, backend);
    let field_type = config
        .additional_fields
        .get(field)
        .map(|field| &field.field_type);
    let convert = |value: &Value, number_strings: bool| -> sea_orm::Value {
        match value {
            Value::String(value)
                if number_strings && matches!(field_type, Some(UserFieldType::Boolean)) =>
            {
                (value == "true").into()
            }
            Value::String(value)
                if number_strings && matches!(field_type, Some(UserFieldType::Number)) =>
            {
                better_auth_core::organization_fields::numeric_filter(value)
                    .map_or_else(|| value.as_str().into(), Into::into)
            }
            Value::String(value) => value.as_str().into(),
            Value::Bool(value) => (*value).into(),
            Value::Number(value) => {
                if let Some(value) = value.as_i64() {
                    value.into()
                } else if let Some(value) = value.as_u64() {
                    value.into()
                } else {
                    value.as_f64().into()
                }
            }
            value => sea_orm::Value::Json(Some(Box::new(value.clone()))),
        }
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
        let values: Vec<_> = values
            .iter()
            .map(|value| convert(value, number_strings))
            .collect();
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
            return Ok(query.filter(M::column("id")?.eq("__better_auth_never_matches__")));
        };
        sea_orm::Value::ChronoDateTimeUtc(Some(parsed.with_timezone(&Utc)))
    } else {
        convert(value, true)
    };
    query = match operator {
        "eq" => query.filter(column.eq(value)),
        "ne" => query.filter(column.ne(value)),
        "gt" => query.filter(column.gt(value)),
        "gte" => query.filter(column.gte(value)),
        "lt" => query.filter(column.lt(value)),
        "lte" => query.filter(column.lte(value)),
        "contains" | "starts_with" | "ends_with" => {
            let pattern = match value {
                sea_orm::Value::Double(Some(value)) => value.to_string(),
                sea_orm::Value::Bool(Some(value)) if backend != DatabaseBackend::Postgres => {
                    u8::from(value).to_string()
                }
                sea_orm::Value::Bool(Some(value)) => value.to_string(),
                _ => raw_value
                    .as_str()
                    .map_or_else(|| raw_value.to_string(), str::to_owned),
            };
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
{
    async fn create_member(&self, member: CreateMember) -> AuthResult<Member> {
        let mut core = values([
            ("id", json!(Uuid::new_v4().to_string())),
            ("organization_id", json!(member.organization_id)),
            ("user_id", json!(member.user_id)),
            ("created_at", json!(Utc::now())),
        ]);
        if let Some(role) = member.role.json()? {
            let _ = core.insert("role".into(), role);
        }
        models::insert::<O::Member, _>(
            self.connection(),
            core,
            member.additional_fields,
            &self.organization_fields()?.member,
        )
        .await
    }

    async fn get_member(&self, organization_id: &str, user_id: &str) -> AuthResult<Option<Member>> {
        Entity::<O::Member>::find()
            .filter(O::Member::column("organization_id")?.eq(organization_id))
            .filter(O::Member::column("user_id")?.eq(user_id))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
            .map(|row| row.record(&self.organization_fields()?.member))
            .transpose()
    }

    async fn get_member_value(
        &self,
        organization_id: &serde_json::Value,
        user_id: &serde_json::Value,
    ) -> AuthResult<Option<Member>> {
        Entity::<O::Member>::find()
            .filter(super::value_filter::equals(
                O::Member::column("organization_id")?,
                organization_id,
            ))
            .filter(super::value_filter::equals(
                O::Member::column("user_id")?,
                user_id,
            ))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
            .map(|row| row.record(&self.organization_fields()?.member))
            .transpose()
    }

    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<Member>> {
        Entity::<O::Member>::find()
            .filter(O::Member::column("id")?.eq(id))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
            .map(|row| row.record(&self.organization_fields()?.member))
            .transpose()
    }

    async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<Member> {
        models::update::<O::Member, _>(
            self.connection(),
            member_id,
            values([("role", json!(role))]),
            Default::default(),
            &self.organization_fields()?.member,
        )
        .await
    }

    async fn delete_member(&self, member_id: &str) -> AuthResult<()> {
        use sea_orm::{TransactionTrait, sea_query::Expr};
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        if let Some(member) = Entity::<O::Member>::find()
            .filter(O::Member::column("id")?.eq(member_id))
            .one(&tx)
            .await
            .map_err(map_db_err)?
        {
            let member = member.record(&self.organization_fields()?.member)?;
            let teams = Entity::<O::Team>::find()
                .filter(
                    O::Team::column("organization_id")?.eq(member.organization_id.typed()?.clone()),
                )
                .all(&tx)
                .await
                .map_err(map_db_err)?;
            for team in teams {
                let team = team.record(&self.organization_fields()?.team)?;
                let _ = Entity::<O::Team>::update_many()
                    .col_expr(
                        O::Team::column("member_count")?,
                        Expr::col(O::Team::column("member_count")?),
                    )
                    .filter(O::Team::column("id")?.eq(&team.id))
                    .exec(&tx)
                    .await
                    .map_err(map_db_err)?;
                let deleted = Entity::<O::TeamMember>::delete_many()
                    .filter(O::TeamMember::column("team_id")?.eq(&team.id))
                    .filter(O::TeamMember::column("user_id")?.eq(member.user_id.typed()?.clone()))
                    .exec(&tx)
                    .await
                    .map_err(map_db_err)?;
                super::team_capacity::release::<O::Team, _>(
                    &tx,
                    &team.id,
                    deleted.rows_affected,
                    &self.organization_fields()?.team,
                )
                .await?;
            }
            let _ = Entity::<O::Member>::delete_many()
                .filter(O::Member::column("id")?.eq(member_id))
                .exec(&tx)
                .await
                .map_err(map_db_err)?;
        }
        tx.commit().await.map_err(map_db_err)
    }

    async fn list_organization_members(&self, organization_id: &str) -> AuthResult<Vec<Member>> {
        Entity::<O::Member>::find()
            .filter(O::Member::column("organization_id")?.eq(organization_id))
            .order_by_asc(O::Member::column("created_at")?)
            .all(self.connection())
            .await
            .map_err(map_db_err)
            .and_then(|rows| {
                models::project::<O::Member>(rows, &self.organization_fields()?.member)
            })
    }

    async fn query_organization_members(
        &self,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<(Vec<Member>, usize)> {
        let base_query = Entity::<O::Member>::find()
            .filter(O::Member::column("organization_id")?.eq(&params.organization_id));
        let filtered_query = apply_member_filter::<O::Member>(
            base_query,
            params,
            &self.organization_fields()?.member,
            self.connection().get_database_backend(),
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

        query
            .all(self.connection())
            .await
            .map_err(map_db_err)
            .and_then(|rows| {
                let skip = std::cmp::min(unbounded_offset, rows.len() as u64) as usize;
                let rows = rows.into_iter().skip(skip).collect();
                Ok((
                    models::project::<O::Member>(rows, &self.organization_fields()?.member)?,
                    total,
                ))
            })
    }

    async fn count_organization_members(&self, organization_id: &str) -> AuthResult<i64> {
        Entity::<O::Member>::find()
            .filter(O::Member::column("organization_id")?.eq(organization_id))
            .count(self.connection())
            .await
            .map(|count| count as i64)
            .map_err(map_db_err)
    }

    async fn count_organization_owners(&self, organization_id: &str) -> AuthResult<i64> {
        Entity::<O::Member>::find()
            .filter(O::Member::column("organization_id")?.eq(organization_id))
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
                id: Some("user-owner".to_string()),
                email: Some("owner@example.com".to_string()),
                ..CreateUser::default()
            })
            .await
            .expect("owner should be created");
        let _member = store
            .create_user(CreateUser {
                id: Some("user-member".to_string()),
                email: Some("member@example.com".to_string()),
                ..CreateUser::default()
            })
            .await
            .expect("member should be created");
        let _admin = store
            .create_user(CreateUser {
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
