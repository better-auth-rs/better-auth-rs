use crate::store::query_compile::{Compile, Execute};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, Iden, IdenStatic, Iterable, PrimaryKeyToColumn,
    QueryFilter, QueryResult, QuerySelect, QueryTrait,
    sea_query::{BinOper, Condition, ExprTrait, IntoCondition, Query, SimpleExpr},
};

use super::{
    map_db_err,
    record_write::{RecordUpdate, RecordWrite},
    value_filter::QueryPredicate,
};
use crate::error::{AuthError, AuthResult};

pub(super) async fn execute_update_returning_raw<E, C>(
    db: &C,
    query: RecordUpdate<E>,
    reselect: SimpleExpr,
) -> AuthResult<Option<QueryResult>>
where
    E: EntityTrait,
    C: ConnectionTrait,
{
    let mut reselect = updated_reselect_filter(&query, reselect);
    if db.get_database_backend() == sea_orm::DbBackend::MySql
        && let SimpleExpr::Binary(column, _, _) = &mut reselect
    {
        super::query_compile::unqualify_column(column);
    }
    execute_returning_raw(db, query.query, reselect).await
}

fn updated_reselect_filter<E: EntityTrait>(
    query: &RecordUpdate<E>,
    fallback: SimpleExpr,
) -> SimpleExpr {
    for primary in E::PrimaryKey::iter() {
        let column = primary.into_column();
        if let Some((_, value)) = query
            .query
            .as_query()
            .get_values()
            .iter()
            .rev()
            .find(|(stored, _)| stored.to_string() == column.to_string())
        {
            if query.source_is_null(column) {
                continue;
            }
            return column.into_expr().eq(value.as_ref().clone());
        }
    }
    // Callers select an original ID equality when available, otherwise the first where field.
    let SimpleExpr::Binary(column, operator @ (BinOper::Equal | BinOper::Is), _) = &fallback else {
        return fallback;
    };
    let Some(selected) = E::Column::iter().find(|candidate| candidate.into_expr() == **column)
    else {
        return fallback;
    };
    if E::PrimaryKey::iter()
        .any(|primary| primary.into_column().to_string() == selected.to_string())
        && *operator == BinOper::Equal
    {
        return fallback;
    }
    let Some((_, value)) = query
        .query
        .as_query()
        .get_values()
        .iter()
        .rev()
        .find(|(stored, _)| stored.to_string() == selected.to_string())
    else {
        return fallback;
    };
    if query.source_is_null(selected) {
        selected.is_null()
    } else {
        selected.into_expr().eq(value.as_ref().clone())
    }
}

pub(super) async fn execute_returning_raw<E, C>(
    db: &C,
    query: sea_orm::UpdateMany<E>,
    reselect: SimpleExpr,
) -> AuthResult<Option<QueryResult>>
where
    E: EntityTrait,
    C: ConnectionTrait,
{
    if db.support_returning() {
        return execute_with_returning(db, query).await;
    }
    if query.exec_native(db).await?.rows_affected == 0 {
        return Ok(None);
    }
    // Ordinary updates use the updated selector; guarded increments retain the locked ID.
    let backend = db.get_database_backend();
    let query = super::plugin_rows::select_all::<E>().filter(reselect);
    let query = if backend == sea_orm::DbBackend::MySql {
        query.limit(1)
    } else {
        query
    };
    db.query_one_raw(query.compile(backend)?)
        .await
        .map_err(map_db_err)
}

async fn execute_with_returning<E: EntityTrait>(
    db: &impl ConnectionTrait,
    query: sea_orm::UpdateMany<E>,
) -> AuthResult<Option<QueryResult>> {
    let mut query = query.into_query();
    let _ = query.returning(Query::returning().all());
    db.query_one_raw(crate::store::query_compile::build(
        db.get_database_backend(),
        &query,
    )?)
    .await
    .map_err(map_db_err)
}

pub(super) async fn increment_returning_raw<E>(
    db: &sea_orm::DbConn,
    write: RecordWrite<E>,
    predicates: Vec<QueryPredicate<E::Column>>,
) -> AuthResult<Option<QueryResult>>
where
    E: EntityTrait,
{
    use sea_orm::TransactionTrait;
    if db.get_database_backend() != sea_orm::DbBackend::MySql {
        return increment_returning_raw_with_connection(db, write, predicates).await;
    }
    let tx = db.begin().await.map_err(map_db_err)?;
    let result = increment_returning_raw_with_connection(&tx, write, predicates).await;
    if result.is_ok() {
        tx.commit().await.map_err(map_db_err)?;
    } else {
        tx.rollback().await.map_err(map_db_err)?;
    }
    result
}

fn increment_target<E: EntityTrait>(
    primary: E::Column,
    filter: impl IntoCondition,
) -> sea_orm::Select<E> {
    E::find()
        .select_only()
        .column(primary)
        .filter(filter)
        .limit(1)
}

fn compile_increment<E: EntityTrait>(
    primary: E::Column,
    write: RecordWrite<E>,
    predicates: Vec<QueryPredicate<E::Column>>,
    backend: sea_orm::DbBackend,
) -> AuthResult<sea_orm::UpdateMany<E>> {
    // Kysely constructs the target WHERE, SET, and outer WHERE before encoding the final UPDATE.
    let target_predicates = predicates
        .iter()
        .cloned()
        .map(QueryPredicate::parse)
        .collect::<AuthResult<Vec<_>>>()?;
    let write = write.parse_update()?;
    let predicates = predicates
        .into_iter()
        .map(QueryPredicate::parse)
        .collect::<AuthResult<Vec<_>>>()?;
    let update = write.encode(E::update_many(), backend)?;
    // Driver encoding follows SQL order: SET, outer WHERE, then the target subquery WHERE.
    let filter = predicates
        .into_iter()
        .try_fold(Condition::all(), |condition, predicate| {
            Ok::<_, AuthError>(condition.add(predicate.encode(backend)?))
        })?;
    let target_filter = target_predicates
        .into_iter()
        .try_fold(Condition::all(), |condition, predicate| {
            Ok::<_, AuthError>(condition.add(predicate.encode(backend)?))
        })?;
    let target = increment_target::<E>(primary, target_filter);
    Ok(update
        .query
        .filter(filter)
        .filter(primary.in_subquery(target.into_query())))
}

/// The caller must hold a transaction when the connection uses MySQL.
pub(super) async fn increment_returning_raw_with_connection<E, C>(
    db: &C,
    write: RecordWrite<E>,
    predicates: Vec<QueryPredicate<E::Column>>,
) -> AuthResult<Option<QueryResult>>
where
    E: EntityTrait,
    C: ConnectionTrait,
{
    let primary = E::PrimaryKey::iter()
        .next()
        .ok_or_else(|| AuthError::config("An auth model requires a primary key"))?
        .into_column();
    let backend = db.get_database_backend();
    if backend != sea_orm::DbBackend::MySql {
        return execute_with_returning(db, compile_increment(primary, write, predicates, backend)?)
            .await;
    }
    let filter = super::value_filter::all(predicates.iter().cloned(), backend)?;
    let target = increment_target::<E>(primary, filter);
    let Some(target) = db
        .query_one_raw(target.lock_exclusive().compile(backend)?)
        .await
        .map_err(map_db_err)?
    else {
        return Ok(None);
    };
    let value = super::plugin_rows::value(&target, primary.as_str())?;
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    let query = write.update_where(backend, predicates)?.query;
    let value = super::record_bindings::Binding::for_column(primary, value).bind(backend)?;
    let selected_id = primary.into_expr().eq(primary.save_as(value));
    // Keep the original guards in UPDATE, then read by the locked ID even if SET changes the ID.
    execute_returning_raw(db, query.filter(selected_id.clone()), selected_id).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::mysql_query::materialize_for_test;
    use crate::store::{entities::api_key, record_write::RecordWrite};
    use better_auth_core::FieldValue;
    use sea_orm::DbBackend;

    #[test]
    fn mysql_reselect_uses_the_assigned_primary_key_after_physical_overrides() -> AuthResult<()> {
        for (replacement, expected) in [
            (None, "before"),
            (Some(FieldValue::Undefined), "before"),
            (Some(FieldValue::Null), "before"),
            (Some("after".into()), "after"),
        ] {
            let mut fields = RecordWrite::<api_key::Entity>::default();
            fields.field(api_key::Column::Name, "other-field".into());
            if let Some(value) = replacement {
                if !value.is_undefined() {
                    fields.field(api_key::Column::Id, "overridden".into());
                }
                fields.field(api_key::Column::Id, value);
            }
            let (query, filter) = fields.update_where_returning(
                DbBackend::MySql,
                [crate::store::value_filter::QueryPredicate::equals(
                    api_key::Column::Id,
                    "before".into(),
                )],
            )?;
            let statement = Query::select()
                .column(api_key::Column::Id)
                .from(api_key::Entity)
                .and_where(updated_reselect_filter(&query, filter))
                .to_owned();
            let statement = crate::store::query_compile::build(DbBackend::MySql, &statement)
                .and_then(materialize_for_test)?
                .sql;
            assert_eq!(
                statement,
                format!("select `id` from `api_keys` where `api_keys`.`id` = '{expected}'")
            );
        }
        Ok(())
    }

    #[test]
    fn mysql_reselect_tracks_selected_field_assignments_and_keeps_id_precedence() -> AuthResult<()>
    {
        for (by_id, name, id, expected) in [
            (
                false,
                FieldValue::Undefined,
                None,
                "`api_keys`.`name` = 'before'",
            ),
            (false, "after".into(), None, "`api_keys`.`name` = 'after'"),
            (false, FieldValue::Null, None, "`api_keys`.`name` is null"),
            (
                false,
                "after".into(),
                Some(FieldValue::Null),
                "`api_keys`.`name` = 'after'",
            ),
            (
                false,
                "after".into(),
                Some("moved".into()),
                "`api_keys`.`id` = 'moved'",
            ),
            (true, "after".into(), None, "`api_keys`.`id` = 'before'"),
            (
                true,
                "after".into(),
                Some(FieldValue::Null),
                "`api_keys`.`id` = 'before'",
            ),
        ] {
            let mut fields = RecordWrite::<api_key::Entity>::default();
            fields.field(api_key::Column::Name, name);
            if let Some(id) = id {
                fields.field(api_key::Column::Id, id);
            }
            let column = if by_id {
                api_key::Column::Id
            } else {
                api_key::Column::Name
            };
            let (query, filter) = fields.update_where_returning(
                DbBackend::MySql,
                [crate::store::value_filter::QueryPredicate::equals(
                    column,
                    "before".into(),
                )],
            )?;
            let statement = Query::select()
                .column(api_key::Column::Id)
                .from(api_key::Entity)
                .and_where(updated_reselect_filter(&query, filter))
                .to_owned();
            let statement = crate::store::query_compile::build(DbBackend::MySql, &statement)
                .and_then(materialize_for_test)?
                .sql;
            assert_eq!(
                statement,
                format!("select `id` from `api_keys` where {expected}")
            );
        }
        Ok(())
    }

    #[test]
    fn mysql_reselect_distinguishes_source_null_from_invalid_date_after_binding() -> AuthResult<()>
    {
        for native_date in [false, true] {
            for (value, predicate) in [
                (FieldValue::Null, "is null"),
                (
                    FieldValue::Date(better_auth_core::FieldDate::invalid()),
                    "= NULL",
                ),
            ] {
                let mut fields = RecordWrite::<api_key::Entity>::default();
                fields.field(api_key::Column::Name, FieldValue::Null);
                if native_date {
                    fields.native_field(api_key::Column::Name, value);
                } else {
                    fields.field(api_key::Column::Name, value);
                }
                let (query, filter) = fields.update_where_returning(
                    DbBackend::MySql,
                    [crate::store::value_filter::QueryPredicate::equals(
                        api_key::Column::Name,
                        "before".into(),
                    )],
                )?;
                let statement = Query::select()
                    .column(api_key::Column::Id)
                    .from(api_key::Entity)
                    .and_where(updated_reselect_filter(&query, filter))
                    .to_owned();
                let statement = crate::store::query_compile::build(DbBackend::MySql, &statement)
                    .and_then(materialize_for_test)?
                    .sql;
                assert_eq!(
                    statement,
                    format!("select `id` from `api_keys` where `api_keys`.`name` {predicate}")
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "increment_target_tests.rs"]
mod increment_target_tests;

#[cfg(test)]
#[path = "increment_phase_tests.rs"]
mod increment_phase_tests;
