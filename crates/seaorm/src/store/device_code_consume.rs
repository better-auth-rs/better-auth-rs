use super::id_filter::IdColumn;
use super::instrumentation::database_operation;
use super::plugin_models::Entity;
use super::{SeaOrmStore, map_db_err};
use crate::{SeaOrmPluginModel, schema::AuthSchema};
use better_auth_core::FieldValue as Value;
use better_auth_core::{
    AuthResult, DeviceCode, DeviceCodeOwnership, DeviceCodeWhere, FieldValue, WhereMode,
    WhereOperator,
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, QueryFilter, QuerySelect,
    sea_query::{BinOper, Condition, ExprTrait, Func, SimpleExpr, extension::postgres::PgBinOper},
};

fn candidate(value: FieldValue, backend: DbBackend) -> AuthResult<SimpleExpr> {
    match value {
        FieldValue::Array(values) => values
            .iter()
            .cloned()
            .map(|value| super::record_bindings::parameter(value, backend))
            .collect::<AuthResult<Vec<_>>>()
            .map(SimpleExpr::Tuple),
        value => super::record_bindings::parameter(value, backend),
    }
}

fn ownership_predicate(
    column: impl ColumnTrait,
    query: DeviceCodeWhere,
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
        Value::Utf16String(value) if insensitive => {
            Value::String(super::record_bindings::utf16_string(&value, backend).to_lowercase())
        }
        value => value,
    };
    Ok(match query.operator {
        WhereOperator::Eq | WhereOperator::Ne if matches!(&query.value, Value::Null) => {
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
            let value = candidate(lower(query.value), backend)?;
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
                Value::Array(values) => values.iter().cloned().collect(),
                value => vec![value],
            };
            let values = values
                .into_iter()
                .map(|value| candidate(lower(value), backend))
                .collect::<AuthResult<Vec<_>>>()?;
            if query.operator == WhereOperator::In {
                column.is_in(values)
            } else {
                column.is_not_in(values)
            }
        }
        WhereOperator::Lt => column.lt(candidate(query.value, backend)?),
        WhereOperator::Lte => column.lte(candidate(query.value, backend)?),
        WhereOperator::Gt => column.gt(candidate(query.value, backend)?),
        WhereOperator::Gte => column.gte(candidate(query.value, backend)?),
        WhereOperator::Contains | WhereOperator::StartsWith | WhereOperator::EndsWith => {
            let text = super::record_bindings::utf16_string(&query.value.display_utf16()?, backend);
            let pattern = match query.operator {
                WhereOperator::Contains => format!("%{text}%"),
                WhereOperator::StartsWith => format!("{text}%"),
                _ => format!("%{text}"),
            };
            let pattern = candidate(Value::String(pattern), backend)?;
            if insensitive && backend == DbBackend::Postgres {
                column.binary(PgBinOper::ILike, pattern)
            } else if insensitive {
                Func::lower(column).binary(BinOper::Like, Func::lower(pattern))
            } else {
                column.binary(BinOper::Like, pattern)
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
        let (mut query, field) = self
            .model_fields
            .device_code_ownership_query(ownership, policy)?;
        let backend = connection.get_database_backend();
        let original = query.value.clone();
        query.value =
            super::value_filter::adapter_query_value(query.value, &original, field, backend)?;
        let ownership = ownership_predicate(P::DeviceCode::column(&query.field)?, query, backend)?;
        let id = P::DeviceCode::column("id")?.eq_id(expected.id.typed()?, policy)?;
        let filter = Condition::all()
            .add(id.clone())
            .add(P::DeviceCode::column("device_code")?.eq(&expected.device_code))
            .add(super::value_filter::equals(
                client,
                &expected.client_id.field_value(),
                self.connection().get_database_backend(),
            )?)
            .add(match &expected.user_id {
                Some(id) => user.eq_id(id, policy)?,
                None => user.is_null(),
            })
            .add(user.is_not_null())
            .add(P::DeviceCode::column("status")?.eq(&expected.status))
            .add(P::DeviceCode::column("status")?.eq("approved"))
            .add(ownership);
        database_operation::<Entity<P::DeviceCode>, _>(self.config(), "consumeOne", async {
            if connection.support_returning() {
                return Entity::<P::DeviceCode>::delete_many()
                    .filter(filter)
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
            // Repeating the predicate in DELETE can turn MySQL SELECT coercion warnings into errors.
            let deleted = Entity::<P::DeviceCode>::delete_many()
                .filter(id)
                .exec(connection)
                .await
                .map_err(map_db_err)?;
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
