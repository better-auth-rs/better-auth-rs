use super::id_filter::IdColumn;
use super::instrumentation::database_operation;
use super::plugin_models::Entity;
use super::{SeaOrmStore, map_db_err};
use crate::{SeaOrmPluginModel, schema::AuthSchema};
use better_auth_core::{
    AuthResult, DeviceCode, DeviceCodeOwnership, DeviceCodeWhere, SchemaValue, WhereMode,
    WhereOperator, user_fields::UserFieldType,
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, QueryFilter, QuerySelect,
    sea_query::{Condition, ExprTrait, Func, SimpleExpr, extension::postgres::PgExpr},
};
use serde_json::Value;

fn candidate(value: Value, numeric: bool) -> sea_orm::Value {
    match value {
        Value::Null if numeric => sea_orm::Value::Double(None),
        Value::Null => sea_orm::Value::String(None),
        Value::String(value) => value.into(),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                value.into()
            } else if let Some(value) = value.as_u64() {
                value.into()
            } else {
                value.as_f64().into()
            }
        }
        Value::Bool(value) => value.into(),
        value @ (Value::Array(_) | Value::Object(_)) => sea_orm::Value::Json(Some(Box::new(value))),
    }
}

fn ownership_predicate(
    column: impl ColumnTrait,
    query: DeviceCodeWhere,
    numeric: bool,
    backend: DbBackend,
) -> AuthResult<SimpleExpr> {
    let insensitive = query.mode == WhereMode::Insensitive
        && (query.value.is_string()
            || query
                .value
                .as_array()
                .is_some_and(|values| values.iter().all(Value::is_string)));
    let column = column.into_expr();
    let lower = |value: Value| match value {
        Value::String(value) if insensitive => Value::String(value.to_lowercase()),
        value => value,
    };
    Ok(match query.operator {
        WhereOperator::Eq | WhereOperator::Ne if query.value.is_null() => {
            if query.operator == WhereOperator::Eq {
                column.is_null()
            } else {
                column.is_not_null()
            }
        }
        WhereOperator::Eq | WhereOperator::Ne => {
            let column = if insensitive {
                Func::lower(column).into()
            } else {
                column
            };
            let value = candidate(lower(query.value), numeric);
            if query.operator == WhereOperator::Eq {
                column.eq(value)
            } else {
                column.ne(value)
            }
        }
        WhereOperator::In | WhereOperator::NotIn => {
            let column = if insensitive {
                Func::lower(column).into()
            } else {
                column
            };
            let values = match query.value {
                Value::Array(values) => values,
                value => vec![value],
            };
            let values = values
                .into_iter()
                .map(|value| candidate(lower(value), numeric));
            if query.operator == WhereOperator::In {
                column.is_in(values)
            } else {
                column.is_not_in(values)
            }
        }
        WhereOperator::Lt => column.lt(candidate(query.value, numeric)),
        WhereOperator::Lte => column.lte(candidate(query.value, numeric)),
        WhereOperator::Gt => column.gt(candidate(query.value, numeric)),
        WhereOperator::Gte => column.gte(candidate(query.value, numeric)),
        WhereOperator::Contains | WhereOperator::StartsWith | WhereOperator::EndsWith => {
            let text = SchemaValue::<Value>::Dynamic(query.value).display_string()?;
            let pattern = match query.operator {
                WhereOperator::Contains => format!("%{text}%"),
                WhereOperator::StartsWith => format!("{text}%"),
                _ => format!("%{text}"),
            };
            if insensitive && backend == DbBackend::Postgres {
                column.ilike(pattern)
            } else if insensitive {
                Func::lower(column).binary(sea_orm::sea_query::BinOper::Like, Func::lower(pattern))
            } else {
                column.like(pattern)
            }
        }
    })
}

impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmStore<S, O, P>
{
    pub(super) async fn consume_device_code_row(
        &self,
        connection: &impl ConnectionTrait,
        expected: &DeviceCode,
        ownership: &DeviceCodeOwnership,
    ) -> AuthResult<Option<P::DeviceCode>> {
        let policy = self.config().advanced.database.generate_id();
        let user = P::DeviceCode::column("user_id")?;
        let client = P::DeviceCode::column("client_id")?;
        let (mut query, field) = self.model_fields.device_code_ownership_query(ownership)?;
        let backend = connection.get_database_backend();
        query.value = field.adapter_input(query.value, backend == DbBackend::Postgres, false)?;
        if backend != DbBackend::Postgres
            && matches!(field.field_type, UserFieldType::Boolean)
            && let Value::Bool(value) = query.value
        {
            query.value = Value::from(i64::from(value));
        }
        let ownership = ownership_predicate(
            P::DeviceCode::column(&query.field)?,
            query,
            matches!(field.field_type, UserFieldType::Number),
            backend,
        )?;
        let filter = Condition::all()
            .add(P::DeviceCode::column("id")?.eq_id(expected.id.typed()?, policy)?)
            .add(P::DeviceCode::column("device_code")?.eq(&expected.device_code))
            .add(super::value_filter::equals(
                client,
                &expected
                    .client_id
                    .json()?
                    .unwrap_or(serde_json::Value::Null),
            ))
            .add(match &expected.user_id {
                Some(id) => user.eq_id(id, policy)?,
                None => user.is_null(),
            })
            .add(user.is_not_null())
            .add(P::DeviceCode::column("status")?.eq(&expected.status))
            .add(P::DeviceCode::column("status")?.eq("approved"))
            .add(ownership);
        database_operation::<Entity<P::DeviceCode>, _>(self.config(), "consumeOne", async {
            let query = Entity::<P::DeviceCode>::delete_many().filter(filter.clone());
            if connection.support_returning() {
                return query
                    .exec_with_returning(connection)
                    .await
                    .map(|rows| rows.into_iter().next())
                    .map_err(map_db_err);
            }
            // Callers keep the MySQL row lock and deletion in the same transaction.
            let row = Entity::<P::DeviceCode>::find()
                .filter(filter)
                .lock_exclusive()
                .one(connection)
                .await
                .map_err(map_db_err)?;
            if row.is_none() {
                return Ok(None);
            }
            let deleted = query.exec(connection).await.map_err(map_db_err)?;
            Ok(if deleted.rows_affected == 1 {
                row
            } else {
                None
            })
        })
        .await
    }

    pub(super) async fn project_consumed_device_code(
        &self,
        row: Option<P::DeviceCode>,
    ) -> AuthResult<Option<DeviceCode>> {
        Ok(self
            .project_device_code_models(row.into_iter().collect())
            .await?
            .pop())
    }
}
