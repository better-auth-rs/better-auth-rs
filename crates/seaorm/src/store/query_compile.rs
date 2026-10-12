//! Compile adapter statements without changing their connection or transaction owner.

use better_auth_core::AuthResult;
use sea_orm::{
    ConnectionTrait, DbBackend, DeleteMany, DeleteResult, EntityTrait, QueryTrait, Statement,
    StatementBuilder, UpdateMany, UpdateResult,
    sea_query::{Asterisk, ColumnRef, Expr, Query, QueryStatementBuilder, SelectStatement},
};

pub(super) fn build<Q>(backend: DbBackend, query: &Q) -> AuthResult<Statement>
where
    Q: QueryStatementBuilder + StatementBuilder,
{
    if backend == DbBackend::MySql {
        super::mysql_query::statement(query)
    } else {
        Ok(backend.build(query))
    }
}

/// Kysely selects the primary relation before joining and repeats its ordering outside.
pub(super) fn find_query(mut query: SelectStatement) -> SelectStatement {
    for selected in query.get_selects_mut() {
        unqualify_column(&mut selected.expr);
    }
    let orders = query.get_order_by_mut();
    for order in orders.iter_mut() {
        unqualify_column(order.expr_mut());
    }
    let orders = orders.to_vec();
    let mut outer = Query::select();
    let _ = outer
        .expr(Expr::col(("primary", Asterisk)))
        .from_subquery(query, "primary");
    for order in orders {
        let _ = outer.add_order_by(order);
    }
    outer
}

pub(super) fn unqualify_column(expr: &mut Expr) {
    if let Expr::Column(column) = expr {
        match column {
            ColumnRef::Column(column) => column.0 = None,
            ColumnRef::Asterisk(table) => *table = None,
            _ => {}
        }
    }
}

pub(super) fn find(backend: DbBackend, query: &SelectStatement) -> AuthResult<Statement> {
    if backend == DbBackend::MySql {
        build(backend, &find_query(query.clone()))
    } else {
        build(backend, query)
    }
}

pub(super) trait Compile: QueryTrait {
    fn compile(&self, backend: DbBackend) -> AuthResult<Statement>
    where
        Self::QueryStatement: QueryStatementBuilder,
    {
        build(backend, self.as_query())
    }

    fn compile_find(&self, backend: DbBackend) -> AuthResult<Statement>
    where
        Self: QueryTrait<QueryStatement = SelectStatement>,
    {
        find(backend, self.as_query())
    }
}

impl<Q: QueryTrait> Compile for Q {}

pub(super) trait Execute {
    type Output;

    fn exec_native(
        self,
        db: &impl ConnectionTrait,
    ) -> impl std::future::Future<Output = AuthResult<Self::Output>> + Send;
}

impl<E: EntityTrait> Execute for DeleteMany<E> {
    type Output = DeleteResult;

    async fn exec_native(self, db: &impl ConnectionTrait) -> AuthResult<Self::Output> {
        let result = db
            .execute_raw(self.compile(db.get_database_backend())?)
            .await
            .map_err(super::map_db_err)?;
        Ok(DeleteResult {
            rows_affected: result.rows_affected(),
        })
    }
}

impl<E: EntityTrait> Execute for UpdateMany<E> {
    type Output = UpdateResult;

    async fn exec_native(self, db: &impl ConnectionTrait) -> AuthResult<Self::Output> {
        if self.as_query().get_values().is_empty() {
            return Ok(UpdateResult::default());
        }
        let result = db
            .execute_raw(self.compile(db.get_database_backend())?)
            .await
            .map_err(super::map_db_err)?;
        Ok(UpdateResult {
            rows_affected: result.rows_affected(),
        })
    }
}
