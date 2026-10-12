use super::*;
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, TransactionTrait,
    sea_query::{Alias, Expr, ExprTrait, Query},
};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

async fn parameter_modes(database: &impl ConnectionTrait) -> TestResult {
    for binding in [
        Binding::Native(Value::Int(Some(17))),
        Binding::Raw("17".into()),
        Binding::Native(Value::String(Some("17".into()))),
        Binding::Raw("17".into()),
        Binding::Native(Value::Int(Some(17))),
    ] {
        let integer = matches!(&binding, Binding::Native(Value::Int(_)));
        let query = Query::select()
            .expr_as(binding.bind(DbBackend::Postgres)?, Alias::new("value"))
            .to_owned();
        let statement = DbBackend::Postgres.build(&query);
        assert_eq!(statement.sql, "SELECT $1 AS \"value\"");
        let row = database
            .query_one_raw(statement)
            .await?
            .ok_or("Missing parameter-mode result")?;
        if integer {
            assert_eq!(row.try_get::<i32>("", "value")?, 17);
        } else {
            assert_eq!(row.try_get::<String>("", "value")?, "17");
        }
    }
    Ok(())
}

async fn mixed_parameters(database: &impl ConnectionTrait) -> TestResult {
    let query = Query::select()
        .expr_as(
            Expr::cust_with_exprs(
                "CAST($1 AS INTEGER) + $2",
                bind(
                    DbBackend::Postgres,
                    vec![
                        Binding::Raw("17".into()),
                        Binding::Native(Value::Int(Some(4))),
                    ],
                )?,
            ),
            Alias::new("sum"),
        )
        .expr_as(
            Expr::cust_with_exprs(
                "CAST($1 AS TEXT)",
                [Binding::Raw(FieldValue::Null).bind(DbBackend::Postgres)?],
            ),
            Alias::new("missing"),
        )
        .expr_as(
            Binding::Native(Value::String(Some("17".into()))).bind(DbBackend::Postgres)?,
            Alias::new("native"),
        )
        .to_owned();
    let row = database
        .query_one_raw(DbBackend::Postgres.build(&query))
        .await?
        .ok_or("Missing mixed-parameter result")?;
    assert_eq!(row.try_get::<i32>("", "sum")?, 21);
    assert_eq!(row.try_get::<Option<String>>("", "missing")?, None);
    assert_eq!(row.try_get::<String>("", "native")?, "17");
    Ok(())
}

async fn atomic_rollback(database: &impl TransactionTrait) -> TestResult {
    let transaction = database.begin().await?;
    let query = Query::update()
        .table(Alias::new("ba_protocol_quota"))
        .value(Alias::new("quota"), Expr::col(Alias::new("quota")).sub(1))
        .value(
            Alias::new("label"),
            Binding::Raw("after'; SELECT 0; --".into()).bind(DbBackend::Postgres)?,
        )
        .and_where(Expr::col(Alias::new("quota")).gt(0))
        .to_owned();
    for expected in [1, 0] {
        let updated = transaction
            .execute_raw(DbBackend::Postgres.build(&query))
            .await?;
        assert_eq!(updated.rows_affected(), expected);
    }
    parameter_modes(&transaction).await?;
    mixed_parameters(&transaction).await?;
    let row = transaction
        .query_one_raw(sea_orm::Statement::from_string(
            DbBackend::Postgres,
            "SELECT quota, label FROM ba_protocol_quota",
        ))
        .await?
        .ok_or("Missing transactional quota")?;
    assert_eq!(row.try_get::<i32>("", "quota")?, 0);
    assert_eq!(row.try_get::<String>("", "label")?, "after'; SELECT 0; --");
    transaction.rollback().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL"]
async fn postgres_modes_preserve_cache_metadata_atomic_updates_and_transaction_ownership()
-> TestResult {
    let mut options = ConnectOptions::new(std::env::var("BETTER_AUTH_TEST_POSTGRES_URL")?);
    let _ = options.max_connections(1).sqlx_logging(false);
    let database = Database::connect(options).await?;
    let result = async {
        parameter_modes(&database).await?;
        mixed_parameters(&database).await?;
        let _ = database
            .execute_unprepared(
                "CREATE TEMPORARY TABLE ba_protocol_quota (quota INTEGER, label TEXT)",
            )
            .await?;
        let _ = database
            .execute_unprepared("INSERT INTO ba_protocol_quota VALUES (1, 'before')")
            .await?;
        atomic_rollback(&database).await?;
        let row = database
            .query_one_raw(sea_orm::Statement::from_string(
                DbBackend::Postgres,
                "SELECT quota, label FROM ba_protocol_quota",
            ))
            .await?
            .ok_or("Missing quota after rollback")?;
        assert_eq!(row.try_get::<i32>("", "quota")?, 1);
        assert_eq!(row.try_get::<String>("", "label")?, "before");
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;
    database.close().await?;
    result
}
