use super::id_filter::IdColumn;
use super::{
    map_db_err,
    organization_models::{self as models, Entity},
};
use crate::SeaOrmOrganizationModel;
use better_auth_core::{AuthResult, SchemaField, user_fields::UserConfig};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
    sea_query::{Expr, ExprTrait, SimpleExpr},
};

async fn update<M: SeaOrmOrganizationModel, C: ConnectionTrait>(
    conn: &C,
    id: &str,
    condition: Option<SimpleExpr>,
    value: SimpleExpr,
    fields: &UserConfig,
    policy: &better_auth_core::id::IdGeneration,
) -> AuthResult<bool> {
    let mut update = Entity::<M>::update_many()
        .col_expr(M::column("member_count")?, value)
        .filter(M::column("id")?.eq_id(id, policy)?);
    if let Some(condition) = condition {
        update = update.filter(condition);
    }
    let changed = update.exec(conn).await.map_err(map_db_err)?.rows_affected > 0;
    if changed && let Some(row) = models::find::<M, _>(conn, id, policy).await? {
        let _ = row.record(fields, conn.get_database_backend()).await?;
    }
    Ok(changed)
}

pub(super) async fn reserve<M: SeaOrmOrganizationModel, C: ConnectionTrait>(
    conn: &C,
    id: &str,
    actual: u64,
    maximum: Option<usize>,
    fields: &UserConfig,
    policy: &better_auth_core::id::IdGeneration,
) -> AuthResult<bool> {
    let active = models::active::<M>(
        models::values([("member_count", (actual).into_field())]),
        Default::default(),
        fields,
        false,
        conn.get_database_backend(),
        policy,
    )
    .await?;
    let changed = active
        .update(conn.get_database_backend())?
        .filter(M::column("id")?.eq_id(id, policy)?)
        .filter(M::column("member_count")?.lt(actual))
        .exec(conn)
        .await
        .map_err(map_db_err)?
        .rows_affected
        > 0;
    if changed && let Some(row) = models::find::<M, _>(conn, id, policy).await? {
        let _ = row.record(fields, conn.get_database_backend()).await?;
    }
    update::<M, _>(
        conn,
        id,
        maximum
            .map(|max| M::column("member_count").map(|column| column.lt(max as u64)))
            .transpose()?,
        Expr::col(M::column("member_count")?).add(1),
        fields,
        policy,
    )
    .await
}

pub(super) async fn release<M: SeaOrmOrganizationModel, C: ConnectionTrait>(
    conn: &C,
    id: &str,
    deleted: u64,
    fields: &UserConfig,
    policy: &better_auth_core::id::IdGeneration,
) -> AuthResult<()> {
    if deleted > 0 {
        let _ = update::<M, _>(
            conn,
            id,
            Some(M::column("member_count")?.gte(deleted)),
            Expr::col(M::column("member_count")?).sub(deleted),
            fields,
            policy,
        )
        .await?;
    }
    Ok(())
}
