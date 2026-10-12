use super::instrumentation::database_operation;
use super::plugin_models::Entity;
use super::record_bindings::Binding;
use super::value_filter::QueryPredicate;
use super::{SeaOrmStore, map_db_err};
use crate::schema::AuthSchema;
use crate::store::query_compile::{Compile, Execute};
use better_auth_core::{
    AuthError, AuthResult, DeviceCode, DeviceCodeOwnership, FieldValue, store::schema::EntityRole,
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, IdenStatic, QueryFilter, QueryResult,
    QuerySelect, QueryTrait,
    sea_query::{Condition, Expr, ExprTrait, Query, SimpleExpr},
};

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
        let selected_id =
            self.bind_plugin_query_field(EntityRole::DeviceCode, "id", expected.id.field_value())?;
        let query = ownership.query();
        better_auth_core::query::validate_where_operand(query.operator, &query.value)?;
        let ownership_value =
            self.bind_plugin_query_field(EntityRole::DeviceCode, &query.field, query.value)?;
        let backend = connection.get_database_backend();
        let approved =
            self.bind_plugin_query_field(EntityRole::DeviceCode, "status", "approved".into())?;
        let (id_column, selected_id) =
            self.resolve_plugin_query_field::<P::DeviceCode>(EntityRole::DeviceCode, selected_id)?;
        let (ownership_column, ownership_value) = self
            .resolve_plugin_query_field::<P::DeviceCode>(EntityRole::DeviceCode, ownership_value)?;
        let (status_column, approved) =
            self.resolve_plugin_query_field::<P::DeviceCode>(EntityRole::DeviceCode, approved)?;
        let user = self.plugin_column::<P::DeviceCode>(EntityRole::DeviceCode, "userId")?;
        let selected_id = QueryPredicate::equals(id_column, selected_id).parse()?;
        let ownership = QueryPredicate::new(
            ownership_column,
            query.operator,
            query.mode,
            ownership_value,
        )
        .parse()?;
        let approved = QueryPredicate::equals(status_column, approved).parse()?;
        let selected_id = selected_id.encode(backend)?;
        let ownership = ownership.encode(backend)?;
        let approved = approved.encode(backend)?;
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
            .add(approved)
            .add(ownership)
            .add(Expr::value(unchanged));
        database_operation::<Entity<P::DeviceCode>, _>(self.config(), "consumeOne", async {
            if connection.support_returning() {
                let mut query = Entity::<P::DeviceCode>::delete_many()
                    .filter(filter)
                    .into_query();
                let _ = query.returning(Query::returning().all());
                return connection
                    .query_one_raw(crate::store::query_compile::build(backend, &query)?)
                    .await
                    .map_err(map_db_err);
            }
            // Callers keep the MySQL row lock and deletion in the same transaction.
            let query = super::plugin_rows::select_all::<Entity<P::DeviceCode>>().filter(filter);
            let query = if backend == sea_orm::DbBackend::MySql {
                query.limit(1)
            } else {
                query
            };
            let query = query.lock_exclusive();
            let Some(row) = connection
                .query_one_raw(query.compile(backend)?)
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
                .exec_native(connection)
                .await?;
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
    use better_auth_core::{Utf16String, WhereMode, WhereOperator};
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
                let predicate = super::super::value_filter::predicate(
                    device_code::Column::Scope,
                    operator,
                    mode,
                    value,
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
