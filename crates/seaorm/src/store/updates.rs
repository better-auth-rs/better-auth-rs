use sea_orm::{ActiveModelTrait, ConnectionTrait, EntityTrait, QueryFilter, sea_query::SimpleExpr};

use super::map_db_err;
use crate::error::AuthResult;

pub(super) async fn update_returning_one<E, C>(
    db: &C,
    active: impl ActiveModelTrait<Entity = E>,
    filter: SimpleExpr,
    reselect: SimpleExpr,
) -> AuthResult<Option<E::Model>>
where
    E: EntityTrait,
    C: ConnectionTrait,
{
    let query = E::update_many().set(active).filter(filter);
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
