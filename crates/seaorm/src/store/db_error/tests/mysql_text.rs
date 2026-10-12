#![expect(
    clippy::panic_in_result_fn,
    reason = "Tests intentionally panic when fixture setup or adapter contract assertions fail."
)]

use super::*;
use sea_orm::Statement;

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL"]
async fn live_mysql_text_error_preserves_utf16_and_source_identity() -> TestResult {
    let mut options = ConnectOptions::new(std::env::var("BETTER_AUTH_TEST_MYSQL_URL")?);
    let _ = options.max_connections(1).sqlx_logging(false);
    let database = Database::connect(options).await?;
    let result = async {
        let mut logical: Vec<u16> = "SELECT missing_column FROM (SELECT 1) AS missing /* "
            .encode_utf16()
            .collect();
        logical.extend([0xd800, 0x0041, 0xdc00, 0xd83d, 0xde00]);
        logical.extend(" */".encode_utf16());
        let source = database
            .execute_raw(Statement::from_mysql_text(logical.clone()))
            .await
            .err()
            .ok_or("A missing column must fail")?;
        let error = map_db_err(source.clone());
        let _ = check_source(&error, &source)?;
        let value = error.into_thrown_value()?;
        assert_eq!(
            value.model_property("sql")?.display_utf16()?.as_utf16(),
            logical
        );
        assert_eq!(value.model_property("code")?, "ER_BAD_FIELD_ERROR".into());
        assert_eq!(value.model_property("errno")?, 1054.0.into());
        assert_eq!(value.model_property("sqlState")?, "42S22".into());
        assert_eq!(
            value
                .enumerable_fields()?
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["code", "errno", "sqlState", "sqlMessage", "sql"],
        );
        let (DbErr::Exec(RuntimeErr::SqlxError(source))
        | DbErr::Query(RuntimeErr::SqlxError(source))) = source
        else {
            return Err("Expected the original SQLx source".into());
        };
        let native = source
            .as_database_error()
            .and_then(|source| source.try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>())
            .ok_or("Expected the original MySQL error")?;
        assert_eq!(native.sql_utf16(), Some(logical.as_slice()));
        assert_eq!(
            native.sql(),
            Some(String::from_utf16_lossy(&logical).as_str())
        );

        let source = database
            .execute_raw(Statement::from_mysql_text(Vec::new()))
            .await
            .err()
            .ok_or("An empty text command must fail")?;
        let error = map_db_err(source.clone());
        let _ = check_source(&error, &source)?;
        let value = error.into_thrown_value()?;
        assert!(value.has_property("sql")?);
        assert!(value.model_property("sql")?.is_undefined());
        Ok(())
    }
    .await;
    database.close().await?;
    result
}
