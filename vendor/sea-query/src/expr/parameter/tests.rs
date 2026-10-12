use crate::*;

fn query() -> SelectStatement {
    Query::select()
        .expr(Expr::ExternalParameter(ExternalParameter::new(17_u32)))
        .to_owned()
}

#[cfg(feature = "backend-mysql")]
#[test]
#[should_panic(
    expected = "ExternalParameter requires a dedicated query builder and parameter collector"
)]
fn ordinary_mysql_rejects_native_parameters() {
    let _ = query().build(MysqlQueryBuilder);
}

#[cfg(feature = "backend-postgres")]
#[test]
#[should_panic(
    expected = "ExternalParameter requires a dedicated query builder and parameter collector"
)]
fn postgres_rejects_native_parameters() {
    let _ = query().build(PostgresQueryBuilder);
}

#[cfg(feature = "backend-sqlite")]
#[test]
#[should_panic(
    expected = "ExternalParameter requires a dedicated query builder and parameter collector"
)]
fn sqlite_rejects_native_parameters() {
    let _ = query().build(SqliteQueryBuilder);
}

#[cfg(feature = "backend-mysql")]
#[test]
#[should_panic(expected = "ExternalParameter requires a dedicated parameter collector")]
fn ordinary_value_writer_rejects_native_parameters() {
    let _ = query().build(KyselyMysqlQueryBuilder);
}
