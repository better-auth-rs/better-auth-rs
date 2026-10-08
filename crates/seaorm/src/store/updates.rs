use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, FromQueryResult, Iden, IdenStatic, Iterable,
    PrimaryKeyToColumn, QueryFilter, QueryResult, QuerySelect, QueryTrait,
    sea_query::{ExprTrait, Query, SimpleExpr},
};

use super::map_db_err;
use crate::error::{AuthError, AuthResult};

pub(super) async fn update_record_returning_one<E: EntityTrait, C: ConnectionTrait>(
    db: &C,
    record: super::record_write::RecordWrite<E>,
    filter: SimpleExpr,
    reselect: SimpleExpr,
) -> AuthResult<Option<E::Model>> {
    execute_update_returning_one(
        db,
        record.update(db.get_database_backend())?.filter(filter),
        reselect,
    )
    .await
}

pub(super) async fn execute_update_returning_one<E, C>(
    db: &C,
    query: sea_orm::UpdateMany<E>,
    reselect: SimpleExpr,
) -> AuthResult<Option<E::Model>>
where
    E: EntityTrait,
    C: ConnectionTrait,
{
    execute_update_returning_raw(db, query, reselect)
        .await?
        .map(|row| E::Model::from_query_result(&row, "").map_err(map_db_err))
        .transpose()
}

pub(super) async fn execute_update_returning_raw<E, C>(
    db: &C,
    query: sea_orm::UpdateMany<E>,
    reselect: SimpleExpr,
) -> AuthResult<Option<QueryResult>>
where
    E: EntityTrait,
    C: ConnectionTrait,
{
    let reselect = updated_primary_filter(&query, reselect);
    execute_returning_raw(db, query, reselect).await
}

fn updated_primary_filter<E: EntityTrait>(
    query: &sea_orm::UpdateMany<E>,
    fallback: SimpleExpr,
) -> SimpleExpr {
    for primary in E::PrimaryKey::iter() {
        let column = primary.into_column();
        if let Some((_, value)) = query
            .as_query()
            .get_values()
            .iter()
            .rev()
            .find(|(stored, _)| stored.to_string() == column.to_string())
        {
            if matches!(value.as_ref(), SimpleExpr::Value(value) | SimpleExpr::Constant(value) if *value == value.as_null())
            {
                return fallback;
            }
            return column.into_expr().eq(value.as_ref().clone());
        }
    }
    fallback
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
        let backend = db.get_database_backend();
        let mut query = query.into_query();
        let _ = query.returning(Query::returning().exprs(
            E::Column::iter().map(|column| column.select_as(column.into_returning_expr(backend))),
        ));
        return db
            .query_one_raw(backend.build(&query))
            .await
            .map_err(map_db_err);
    }
    if query.exec(db).await.map_err(map_db_err)?.rows_affected == 0 {
        return Ok(None);
    }
    // Ordinary updates use the assigned ID; guarded increments retain the locked ID.
    db.query_one_raw(E::find().filter(reselect).build(db.get_database_backend()))
        .await
        .map_err(map_db_err)
}

pub(super) async fn increment_returning_raw<E>(
    db: &sea_orm::DbConn,
    query: sea_orm::UpdateMany<E>,
    filter: SimpleExpr,
    reselect: SimpleExpr,
) -> AuthResult<Option<QueryResult>>
where
    E: EntityTrait,
{
    use sea_orm::TransactionTrait;
    if db.get_database_backend() != sea_orm::DbBackend::MySql {
        return increment_returning_raw_with_connection(db, query, filter, reselect).await;
    }
    let tx = db.begin().await.map_err(map_db_err)?;
    let result = increment_returning_raw_with_connection(&tx, query, filter, reselect).await;
    if result.is_ok() {
        tx.commit().await.map_err(map_db_err)?;
    } else {
        tx.rollback().await.map_err(map_db_err)?;
    }
    result
}

fn increment_target<E: EntityTrait>(primary: E::Column, filter: SimpleExpr) -> sea_orm::Select<E> {
    E::find()
        .select_only()
        .column(primary)
        .filter(filter)
        .limit(1)
}

/// The caller must hold a transaction when the connection uses MySQL.
pub(super) async fn increment_returning_raw_with_connection<E, C>(
    db: &C,
    query: sea_orm::UpdateMany<E>,
    filter: SimpleExpr,
    reselect: SimpleExpr,
) -> AuthResult<Option<QueryResult>>
where
    E: EntityTrait,
    C: ConnectionTrait,
{
    let primary = E::PrimaryKey::iter()
        .next()
        .ok_or_else(|| AuthError::config("An auth model requires a primary key"))?
        .into_column();
    let target = increment_target::<E>(primary, filter);
    if db.get_database_backend() != sea_orm::DbBackend::MySql {
        return execute_returning_raw(
            db,
            query.filter(primary.in_subquery(target.into_query())),
            reselect,
        )
        .await;
    }
    let backend = db.get_database_backend();
    let Some(target) = db
        .query_one_raw(target.lock_exclusive().build(backend))
        .await
        .map_err(map_db_err)?
    else {
        return Ok(None);
    };
    let value = super::plugin_rows::value(&target, primary.as_str())?;
    let value = super::record_bindings::Binding::for_column(primary, value).bind(backend)?;
    let selected_id = primary.into_expr().eq(primary.save_as(value));
    // Keep the original guards in UPDATE, then read by the locked ID even if SET changes the ID.
    execute_returning_raw(db, query.filter(selected_id.clone()), selected_id).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{entities::api_key, record_write::RecordWrite};
    use better_auth_core::FieldValue;
    use sea_orm::{DbBackend, sea_query::MysqlQueryBuilder};

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
            let filter = api_key::Column::Id.eq("before");
            let query = fields.update(DbBackend::MySql)?.filter(filter.clone());
            let statement = Query::select()
                .column(api_key::Column::Id)
                .from(api_key::Entity)
                .and_where(updated_primary_filter(&query, filter))
                .to_string(MysqlQueryBuilder);
            assert_eq!(
                statement,
                format!("SELECT `id` FROM `api_keys` WHERE `api_keys`.`id` = '{expected}'")
            );
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "increment_target_tests.rs"]
mod increment_target_tests;
