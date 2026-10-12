use super::*;
use crate::connection::Connection;
use crate::row::Row;
use crate::statement::Statement;
use sqlx_core::error::BoxDynError;
use sqlx_core::query::{query, query_with};
use sqlx_core::raw_sql::raw_sql;

#[test]
#[ignore = "requires DATABASE_URL and the sqlx/runtime-tokio feature in PostgreSQL CI"]
fn mixed_formats_infer_types_and_preserve_nulls() -> Result<(), BoxDynError> {
    sqlx_core::rt::test_block_on(async {
        let mut connection = PgConnection::connect(&std::env::var("DATABASE_URL")?).await?;
        let mut arguments = PgArguments::default();
        arguments.add_text(Some("7"))?;
        arguments.add("7")?;
        arguments.add_text(None)?;
        let row = query_with::<Postgres, _>("SELECT $1::int4, $2, $3::int8", arguments)
            .fetch_one(&mut connection)
            .await?;
        assert_eq!(row.try_get::<i32, _>(0)?, 7);
        assert_eq!(row.try_get::<String, _>(1)?, "7");
        assert_eq!(row.try_get::<Option<i64>, _>(2)?, None);
        assert_eq!(
            row.metadata.parameters,
            [PgTypeInfo::INT4, PgTypeInfo::TEXT, PgTypeInfo::INT8]
        );
        assert_eq!(
            row.metadata.requested_parameters[0].oid(),
            Some(crate::types::Oid(0))
        );
        assert_eq!(
            row.metadata.requested_parameters[1].oid(),
            Some(crate::types::Oid(25))
        );
        assert_eq!(
            row.metadata.requested_parameters[2].oid(),
            Some(crate::types::Oid(0))
        );
        connection.close().await?;
        Ok(())
    })
}

#[test]
#[ignore = "requires DATABASE_URL and the sqlx/runtime-tokio feature in PostgreSQL CI"]
fn requested_signatures_reprepare_on_one_connection() -> Result<(), BoxDynError> {
    sqlx_core::rt::test_block_on(async {
        let mut connection = PgConnection::connect(&std::env::var("DATABASE_URL")?).await?;
        let sql = "SELECT $1 AS first, $2 AS second";
        let mut previous_id = None;
        for _ in 0..2 {
            let row = query::<Postgres>(sql)
                .bind(7_i32)
                .bind("8")
                .fetch_one(&mut connection)
                .await?;
            assert_eq!(row.try_get::<i32, _>(0)?, 7);
            assert_eq!(row.try_get::<String, _>(1)?, "8");
            let (typed_id, _) = connection
                .inner
                .cache_statement
                .get_mut(sql)
                .unwrap()
                .clone();
            assert_ne!(Some(typed_id), previous_id);

            let mut arguments = PgArguments::default();
            arguments.add_text(Some("7"))?;
            arguments.add(8_i32)?;
            let row = query_with::<Postgres, _>(sql, arguments.clone())
                .fetch_one(&mut connection)
                .await?;
            assert_eq!(row.try_get::<String, _>(0)?, "7");
            assert_eq!(row.try_get::<i32, _>(1)?, 8);
            let (text_id, _) = connection
                .inner
                .cache_statement
                .get_mut(sql)
                .unwrap()
                .clone();
            assert_ne!(text_id, typed_id);

            query_with::<Postgres, _>(sql, arguments)
                .fetch_one(&mut connection)
                .await?;
            assert_eq!(
                connection.inner.cache_statement.get_mut(sql).unwrap().0,
                text_id
            );
            previous_id = Some(text_id);
            assert_eq!(connection.cached_statements_size(), 1);
            let count = raw_sql("SELECT count(*) FROM pg_prepared_statements")
                .fetch_one(&mut connection)
                .await?;
            assert_eq!(count.try_get::<i64, _>(0)?, 1);
        }

        connection.clear_cached_statements().await?;
        let sql = "SELECT $1";
        query::<Postgres>(sql)
            .bind(7_i32)
            .fetch_one(&mut connection)
            .await?;
        let typed_id = connection.inner.cache_statement.get_mut(sql).unwrap().0;
        let mut arguments = PgArguments::default();
        arguments.add_text(Some("7"))?;
        let row = query_with::<Postgres, _>(sql, arguments)
            .persistent(false)
            .fetch_one(&mut connection)
            .await?;
        assert_eq!(row.try_get::<String, _>(0)?, "7");
        assert_eq!(
            connection.inner.cache_statement.get_mut(sql).unwrap().0,
            typed_id
        );
        let row = query::<Postgres>(sql)
            .bind(9_i32)
            .fetch_one(&mut connection)
            .await?;
        assert_eq!(row.try_get::<i32, _>(0)?, 9);
        assert_eq!(
            connection.inner.cache_statement.get_mut(sql).unwrap().0,
            typed_id
        );
        connection.close().await?;
        Ok(())
    })
}

#[test]
#[ignore = "requires DATABASE_URL and the sqlx/runtime-tokio feature in PostgreSQL CI"]
fn explicit_statement_metadata_follows_the_new_requested_signature() -> Result<(), BoxDynError> {
    sqlx_core::rt::test_block_on(async {
        let mut connection = PgConnection::connect(&std::env::var("DATABASE_URL")?).await?;
        let statement = connection
            .prepare_with("SELECT $1", &[PgTypeInfo::INT4])
            .await?;
        connection.clear_cached_statements().await?;
        let mut arguments = PgArguments::default();
        arguments.add_text(Some("7"))?;
        let row = statement
            .query_with(arguments)
            .fetch_one(&mut connection)
            .await?;
        assert_eq!(row.try_get::<String, _>(0)?, "7");
        assert_eq!(row.metadata.parameters, [PgTypeInfo::TEXT]);
        assert_eq!(
            row.metadata.requested_parameters[0].oid(),
            Some(crate::types::Oid(0))
        );
        assert_eq!(statement.metadata.parameters, [PgTypeInfo::INT4]);
        let row = statement
            .query()
            .bind(9_i32)
            .fetch_one(&mut connection)
            .await?;
        assert_eq!(row.try_get::<i32, _>(0)?, 9);
        assert_eq!(row.metadata.parameters, [PgTypeInfo::INT4]);
        connection.close().await?;
        Ok(())
    })
}

#[test]
#[ignore = "requires DATABASE_URL and the sqlx/runtime-tokio feature in PostgreSQL CI"]
fn prefix_type_names_reprepare_with_correct_metadata_and_i64_encoding() -> Result<(), BoxDynError> {
    sqlx_core::rt::test_block_on(async {
        let mut connection = PgConnection::connect(&std::env::var("DATABASE_URL")?).await?;
        let sql = "SELECT $1";
        let integer = connection
            .prepare_with(sql, &[PgTypeInfo::with_name("int")])
            .await?;
        assert_eq!(integer.metadata.parameters, [PgTypeInfo::INT4]);
        let integer_id = connection.inner.cache_statement.get_mut(sql).unwrap().0;
        let bigint = connection
            .prepare_with(sql, &[PgTypeInfo::with_name("int8")])
            .await?;
        assert_eq!(bigint.metadata.parameters, [PgTypeInfo::INT8]);
        let bigint_id = connection.inner.cache_statement.get_mut(sql).unwrap().0;
        assert_ne!(integer_id, bigint_id);
        let value = 1_i64 << 40;
        let row = bigint
            .query()
            .bind(value)
            .fetch_one(&mut connection)
            .await?;
        assert_eq!(row.try_get::<i64, _>(0)?, value);
        assert_eq!(row.metadata.parameters, [PgTypeInfo::INT8]);
        assert_eq!(integer.metadata.parameters, [PgTypeInfo::INT4]);
        connection.close().await?;
        Ok(())
    })
}
