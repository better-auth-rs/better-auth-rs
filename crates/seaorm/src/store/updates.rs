use sea_orm::{ConnectionTrait, EntityTrait, QueryFilter, sea_query::SimpleExpr};

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
    if db.support_returning() {
        return query
            .exec_with_returning(db)
            .await
            .map(|rows| rows.into_iter().next())
            .map_err(map_db_err);
    }
    if query.exec(db).await.map_err(map_db_err)?.rows_affected == 0 {
        return Ok(None);
    }
    // MySQL has no UPDATE RETURNING. Select with the updated key, as the upstream adapter does.
    E::find().filter(reselect).one(db).await.map_err(map_db_err)
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
    use sea_orm::{QuerySelect, TransactionTrait};
    if db.get_database_backend() != sea_orm::DbBackend::MySql {
        return execute_update_returning_one(db, query, reselect).await;
    }
    let tx = db.begin().await.map_err(map_db_err)?;
    let result = async {
        if E::find()
            .filter(filter.clone())
            .lock_exclusive()
            .one(&tx)
            .await
            .map_err(map_db_err)?
            .is_none()
        {
            return Ok(None);
        }
        execute_update_returning_one(&tx, query, reselect).await
    }
    .await;
    if result.is_ok() {
        tx.commit().await.map_err(map_db_err)?;
    } else {
        tx.rollback().await.map_err(map_db_err)?;
    }
    result
}
