use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, FromQueryResult, Iterable, QueryFilter, QueryResult,
    QueryTrait,
    sea_query::{Query, SimpleExpr},
};

use super::map_db_err;
use crate::error::AuthResult;

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
    // MySQL has no UPDATE RETURNING. Select with the updated key, as the upstream adapter does.
    db.query_one_raw(E::find().filter(reselect).build(db.get_database_backend()))
        .await
        .map_err(map_db_err)
}

pub(super) async fn increment_returning_one<E>(
    db: &sea_orm::DbConn,
    query: sea_orm::UpdateMany<E>,
    filter: SimpleExpr,
    reselect: SimpleExpr,
) -> AuthResult<Option<E::Model>>
where
    E: EntityTrait,
{
    increment_returning_raw(db, query, filter, reselect)
        .await?
        .map(|row| E::Model::from_query_result(&row, "").map_err(map_db_err))
        .transpose()
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
    use sea_orm::{QuerySelect, TransactionTrait};
    if db.get_database_backend() != sea_orm::DbBackend::MySql {
        return execute_update_returning_raw(db, query, reselect).await;
    }
    let tx = db.begin().await.map_err(map_db_err)?;
    let result = async {
        if tx
            .query_one_raw(
                E::find()
                    .filter(filter.clone())
                    .lock_exclusive()
                    .build(db.get_database_backend()),
            )
            .await
            .map_err(map_db_err)?
            .is_none()
        {
            return Ok(None);
        }
        execute_update_returning_raw(&tx, query, reselect).await
    }
    .await;
    if result.is_ok() {
        tx.commit().await.map_err(map_db_err)?;
    } else {
        tx.rollback().await.map_err(map_db_err)?;
    }
    result
}
