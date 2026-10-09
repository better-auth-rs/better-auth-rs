use super::{
    create_readback::ReadbackScope,
    organization_models::{self as models, Entity},
};
use crate::SeaOrmOrganizationModel;
use better_auth_core::{
    AuthResult, FieldValue, SchemaField, plugin_runtime::ModelFields, store::schema::EntityRole,
    user_fields::UserConfig,
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
    sea_query::{Expr, ExprTrait, SimpleExpr},
};

type Runtime<'a> = (&'a ModelFields, EntityRole);

enum Guard {
    Below(u64),
    AtLeast(u64),
}

struct Selectors {
    id: super::value_filter::BoundQueryField,
    guard: Option<(Guard, super::value_filter::BoundQueryField)>,
}

fn counter_column<M: SeaOrmOrganizationModel>(
    fields: &UserConfig,
    role: EntityRole,
) -> AuthResult<M::Column> {
    let fields = fields.adapter_fields(&[]);
    let (_, column) = super::value_filter::query_field_name(role, &fields, "memberCount")?;
    M::column(column)
}

fn bind_selectors(
    backend: sea_orm::DbBackend,
    id: &FieldValue,
    guard: Option<Guard>,
    fields: &UserConfig,
    policy: &better_auth_core::id::IdGeneration,
    runtime: Runtime<'_>,
) -> AuthResult<Selectors> {
    let id = super::value_filter::bind_factory_query_field(
        runtime.0, runtime.1, fields, "id", id, policy, backend,
    )?;
    let guard = guard
        .map(|guard| {
            let value = match guard {
                Guard::Below(value) | Guard::AtLeast(value) => value,
            };
            super::value_filter::bind_factory_query_field(
                runtime.0,
                runtime.1,
                fields,
                "memberCount",
                &value.into_field(),
                policy,
                backend,
            )
            .map(|bound| (guard, bound))
        })
        .transpose()?;
    Ok(Selectors { id, guard })
}

impl Selectors {
    fn resolve<M: SeaOrmOrganizationModel>(
        self,
        backend: sea_orm::DbBackend,
        fields: &UserConfig,
        role: EntityRole,
    ) -> AuthResult<(SimpleExpr, SimpleExpr)> {
        let (column, value) = self.id.resolve(role, fields)?;
        let id = super::value_filter::equals(M::column(&column)?, &value, backend)?;
        let condition = match self.guard {
            Some((guard, bound)) => {
                let (column, value) = bound.resolve(role, fields)?;
                let column = M::column(&column)?;
                let value = column.save_as(super::record_bindings::parameter(value, backend)?);
                let guard = match guard {
                    Guard::Below(_) => column.into_expr().lt(value),
                    Guard::AtLeast(_) => column.into_expr().gte(value),
                };
                id.clone().and(guard)
            }
            None => id.clone(),
        };
        Ok((id, condition))
    }
}

async fn write_and_output<M: SeaOrmOrganizationModel, C: ConnectionTrait>(
    conn: &C,
    scope: ReadbackScope<'_>,
    query: sea_orm::UpdateMany<Entity<M>>,
    id: SimpleExpr,
    filter: SimpleExpr,
    fields: &UserConfig,
    runtime: Runtime<'_>,
) -> AuthResult<bool> {
    let backend = conn.get_database_backend();
    let row = match scope {
        ReadbackScope::Direct(pool) => {
            super::updates::increment_returning_raw(pool, query, filter, id).await?
        }
        ReadbackScope::Transaction => {
            super::updates::increment_returning_raw_with_connection(conn, query, filter, id).await?
        }
    };
    let Some(row) = row else { return Ok(false) };
    let _ = fields
        .organization_output_records(
            vec![models::raw_record::<M>(
                &row.into(),
                fields,
                backend,
                runtime,
            )?],
            backend == sea_orm::DbBackend::Postgres,
        )
        .await?;
    Ok(true)
}

async fn update<M: SeaOrmOrganizationModel, C: ConnectionTrait>(
    conn: &C,
    scope: ReadbackScope<'_>,
    id: &FieldValue,
    (guard, delta): (Option<Guard>, f64),
    fields: &UserConfig,
    policy: &better_auth_core::id::IdGeneration,
    runtime: Runtime<'_>,
) -> AuthResult<bool> {
    let (id, condition) = bind_selectors(
        conn.get_database_backend(),
        id,
        guard,
        fields,
        policy,
        runtime,
    )?
    .resolve::<M>(conn.get_database_backend(), fields, runtime.1)?;
    let column = counter_column::<M>(fields, runtime.1)?;
    let update = Entity::<M>::update_many()
        .col_expr(column, Expr::col(column).add(delta))
        .filter(condition.clone());
    write_and_output::<M, _>(conn, scope, update, id, condition, fields, runtime).await
}

pub(super) async fn sync<M: SeaOrmOrganizationModel, C: ConnectionTrait>(
    conn: &C,
    id: &FieldValue,
    actual: u64,
    fields: &UserConfig,
    policy: &better_auth_core::id::IdGeneration,
    runtime: Runtime<'_>,
) -> AuthResult<()> {
    let selectors = bind_selectors(
        conn.get_database_backend(),
        id,
        Some(Guard::Below(actual)),
        fields,
        policy,
        runtime,
    )?;
    let active = models::active::<M>(
        models::values([("member_count", (actual).into_field())]),
        Default::default(),
        fields,
        None,
        conn.get_database_backend(),
        policy,
        runtime,
    )
    .await?;
    let (id, condition) = selectors.resolve::<M>(conn.get_database_backend(), fields, runtime.1)?;
    let query = active
        .update(conn.get_database_backend())?
        .filter(condition.clone());
    let _ = write_and_output::<M, _>(
        conn,
        ReadbackScope::Transaction,
        query,
        id,
        condition,
        fields,
        runtime,
    )
    .await?;
    Ok(())
}

pub(super) async fn reserve<M: SeaOrmOrganizationModel, C: ConnectionTrait>(
    conn: &C,
    id: &FieldValue,
    maximum: usize,
    fields: &UserConfig,
    policy: &better_auth_core::id::IdGeneration,
    runtime: Runtime<'_>,
) -> AuthResult<bool> {
    update::<M, _>(
        conn,
        ReadbackScope::Transaction,
        id,
        (Some(Guard::Below(maximum as u64)), 1.0),
        fields,
        policy,
        runtime,
    )
    .await
}

pub(super) async fn increment<M: SeaOrmOrganizationModel, C: ConnectionTrait>(
    conn: &C,
    id: &FieldValue,
    fields: &UserConfig,
    policy: &better_auth_core::id::IdGeneration,
    runtime: Runtime<'_>,
) -> AuthResult<()> {
    let _ = update::<M, _>(
        conn,
        ReadbackScope::Transaction,
        id,
        (None, 1.0),
        fields,
        policy,
        runtime,
    )
    .await?;
    Ok(())
}

pub(super) async fn release<M: SeaOrmOrganizationModel, C: ConnectionTrait>(
    conn: &C,
    scope: ReadbackScope<'_>,
    id: &FieldValue,
    deleted: u64,
    fields: &UserConfig,
    policy: &better_auth_core::id::IdGeneration,
    runtime: Runtime<'_>,
) -> AuthResult<()> {
    if deleted > 0 {
        let _ = update::<M, _>(
            conn,
            scope,
            id,
            (Some(Guard::AtLeast(deleted)), -(deleted as f64)),
            fields,
            policy,
            runtime,
        )
        .await?;
    }
    Ok(())
}
