use super::instrumentation::database_operation;
use super::plugin_models::Entity;
use super::record_bindings::Binding;
use super::{SeaOrmStore, map_db_err};
use crate::{SeaOrmPluginModel, schema::AuthSchema};
use better_auth_core::FieldValue as Value;
use better_auth_core::{
    AuthError, AuthResult, DeviceCode, DeviceCodeOwnership, DeviceCodeWhere, FieldValue, WhereMode,
    WhereOperator, store::schema::EntityRole,
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, IdenStatic, Iterable, QueryFilter,
    QueryResult, QuerySelect, QueryTrait,
    sea_query::{
        BinOper, Condition, Expr, ExprTrait, Func, Query, SimpleExpr,
        extension::postgres::PgBinOper,
    },
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
        Value::Utf16String(value) if insensitive => value.to_lowercase().into(),
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
            super::value_filter::membership(column, values, query.operator == WhereOperator::NotIn)
        }
        WhereOperator::Lt => column.lt(candidate(query.value, backend)?),
        WhereOperator::Lte => column.lte(candidate(query.value, backend)?),
        WhereOperator::Gt => column.gt(candidate(query.value, backend)?),
        WhereOperator::Gte => column.gte(candidate(query.value, backend)?),
        WhereOperator::Contains | WhereOperator::StartsWith | WhereOperator::EndsWith => {
            let (prefix, suffix) = match query.operator {
                WhereOperator::Contains => ("%", "%"),
                WhereOperator::StartsWith => ("", "%"),
                _ => ("%", ""),
            };
            let pattern = super::value_filter::like_pattern(&query.value, prefix, suffix, backend)?;
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

fn stored_equals(
    column: impl ColumnTrait,
    value: FieldValue,
    backend: DbBackend,
) -> AuthResult<SimpleExpr> {
    if value.is_null() {
        return Ok(column.is_null());
    }
    let value = Binding::for_column(column, value).bind(backend)?;
    Ok(column.into_expr().eq(column.save_as(value)))
}

impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmStore<S, O, P>
{
    pub(super) async fn consume_device_code_row(
        &self,
        connection: &impl ConnectionTrait,
        expected: &DeviceCode,
        ownership: &DeviceCodeOwnership,
    ) -> AuthResult<Option<QueryResult>> {
        let policy = self.config().advanced.database.generate_id();
        let selected_id =
            self.bind_plugin_query_field(EntityRole::DeviceCode, "id", expected.id.field_value())?;
        let user = self.plugin_column::<P::DeviceCode>(EntityRole::DeviceCode, "userId")?;
        let (mut query, field, original) = self
            .model_fields
            .device_code_ownership_query(ownership, policy)?;
        let backend = connection.get_database_backend();
        query.value =
            super::value_filter::adapter_query_value(query.value, &original, field, backend)?;
        let approved =
            self.bind_plugin_query_field(EntityRole::DeviceCode, "status", "approved".into())?;
        let selected_id =
            self.resolve_plugin_equals::<P::DeviceCode>(EntityRole::DeviceCode, selected_id)?;
        let fields = self
            .model_fields
            .plugin_fields(EntityRole::DeviceCode)
            .adapter_fields(&[]);
        query.field =
            super::value_filter::query_field_name(EntityRole::DeviceCode, &fields, &query.field)?
                .1
                .to_owned();
        let ownership = ownership_predicate(P::DeviceCode::column(&query.field)?, query, backend)?;
        let (bindings, unchanged) = expected.consumption_bindings()?;
        let mut filter = Condition::all().add(selected_id);
        for name in ["id", "deviceCode", "clientId", "userId", "status"] {
            let value = bindings.get(name).ok_or_else(|| {
                AuthError::internal(format!("Device consumption binding {name} is missing"))
            })?;
            let column = self.plugin_column::<P::DeviceCode>(EntityRole::DeviceCode, name)?;
            filter = filter.add(stored_equals(column, value.clone(), backend)?);
        }
        let filter = filter
            .add(user.is_not_null())
            .add(self.resolve_plugin_equals::<P::DeviceCode>(EntityRole::DeviceCode, approved)?)
            .add(ownership)
            .add(Expr::value(unchanged));
        database_operation::<Entity<P::DeviceCode>, _>(self.config(), "consumeOne", async {
            if connection.support_returning() {
                let mut query = Entity::<P::DeviceCode>::delete_many()
                    .filter(filter)
                    .into_query();
                let _ = query.returning(
                    Query::returning().exprs(
                        <P::DeviceCode as SeaOrmPluginModel>::Column::iter()
                            .map(|column| column.select_as(column.into_returning_expr(backend))),
                    ),
                );
                return connection
                    .query_one_raw(backend.build(&query))
                    .await
                    .map_err(map_db_err);
            }
            // Callers keep the MySQL row lock and deletion in the same transaction.
            let query = Entity::<P::DeviceCode>::find()
                .filter(filter)
                .lock_exclusive();
            let Some(row) = connection
                .query_one_raw(query.build(backend))
                .await
                .map_err(map_db_err)?
            else {
                return Ok(None);
            };
            let primary = self.plugin_column::<P::DeviceCode>(EntityRole::DeviceCode, "id")?;
            let id = stored_equals(
                primary,
                super::plugin_rows::value(&row, primary.as_str())?,
                backend,
            )?;
            // Repeating the predicate in DELETE can turn MySQL SELECT coercion warnings into errors.
            let deleted = Entity::<P::DeviceCode>::delete_many()
                .filter(id)
                .exec(connection)
                .await
                .map_err(map_db_err)?;
            Ok(if deleted.rows_affected == 1 {
                Some(row)
            } else {
                None
            })
        })
        .await
    }

    pub(super) async fn project_consumed_device_code(
        &self,
        row: Option<QueryResult>,
    ) -> AuthResult<Option<DeviceCode>> {
        Ok(self
            .project_device_code_models(row.into_iter().collect())
            .await?
            .pop())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{entities::device_code, record_bindings::parameter};
    use better_auth_core::Utf16String;
    use sea_orm::{ConnectOptions, Database, sea_query::Alias};

    #[tokio::test]
    async fn ownership_queries_lowercase_before_binding_and_keep_complete_like_patterns()
    -> AuthResult<()> {
        for encoding in ["UTF-8", "UTF-16le", "UTF-16be"] {
            let mut options = ConnectOptions::new("sqlite::memory:");
            let _ = options.max_connections(1);
            let database = Database::connect(options).await.map_err(map_db_err)?;
            let _ = database
                .execute_unprepared(&format!("PRAGMA encoding = '{encoding}'"))
                .await
                .map_err(map_db_err)?;
            let _ = database
                .execute_unprepared("CREATE TABLE device_code (scope TEXT)")
                .await
                .map_err(map_db_err)?;
            for (operator, mode, units, actual, expected) in [
                (
                    WhereOperator::Eq,
                    WhereMode::Insensitive,
                    vec![0xd800, 0x41],
                    "\u{10061}",
                    i64::from(encoding == "UTF-8"),
                ),
                (
                    WhereOperator::Eq,
                    WhereMode::Insensitive,
                    vec![0xd800, 0x41],
                    "\u{10041}",
                    0,
                ),
                (
                    WhereOperator::In,
                    WhereMode::Insensitive,
                    vec![0xd800, 0x41],
                    "\u{10061}",
                    i64::from(encoding == "UTF-8"),
                ),
                (
                    WhereOperator::NotIn,
                    WhereMode::Insensitive,
                    vec![0xd800, 0x41],
                    "\u{10061}",
                    i64::from(encoding != "UTF-8"),
                ),
                (
                    WhereOperator::Contains,
                    WhereMode::Insensitive,
                    vec![0xd800],
                    "x\u{10025}",
                    1,
                ),
                (
                    WhereOperator::Contains,
                    WhereMode::Insensitive,
                    vec![0xd800],
                    "x\u{10025}y",
                    0,
                ),
                (
                    WhereOperator::Contains,
                    WhereMode::Sensitive,
                    vec![0xfeff, 0x41],
                    "xA",
                    0,
                ),
                (
                    WhereOperator::Contains,
                    WhereMode::Sensitive,
                    vec![0xfeff, 0x41],
                    "x\u{feff}A",
                    1,
                ),
            ] {
                let _ = database
                    .execute_unprepared("DELETE FROM device_code")
                    .await
                    .map_err(map_db_err)?;
                let insert = Query::insert()
                    .into_table(device_code::Entity)
                    .columns([device_code::Column::Scope])
                    .values_panic([parameter(actual.into(), DbBackend::Sqlite)?])
                    .to_owned();
                let _ = database
                    .execute_raw(DbBackend::Sqlite.build(&insert))
                    .await
                    .map_err(map_db_err)?;
                let value = FieldValue::Utf16String(Utf16String::from_units(units));
                let value = if matches!(operator, WhereOperator::In | WhereOperator::NotIn) {
                    vec![value].into()
                } else {
                    value
                };
                let predicate = ownership_predicate(
                    device_code::Column::Scope,
                    DeviceCodeWhere {
                        field: "scope".into(),
                        operator,
                        mode,
                        value,
                    },
                    DbBackend::Sqlite,
                )?;
                let query = Query::select()
                    .expr_as(predicate, Alias::new("matched"))
                    .from(device_code::Entity)
                    .to_owned();
                let row = database
                    .query_one_raw(DbBackend::Sqlite.build(&query))
                    .await
                    .map_err(map_db_err)?
                    .ok_or_else(|| {
                        AuthError::internal("Device ownership observation is missing")
                    })?;
                assert_eq!(
                    row.try_get::<i64>("", "matched").map_err(map_db_err)?,
                    expected,
                    "{encoding}: {operator:?}, {actual:?}"
                );
            }
        }
        Ok(())
    }
}
