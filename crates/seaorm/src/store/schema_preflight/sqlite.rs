use super::super::map_db_err;
use better_auth_core::{
    AuthResult,
    store::schema::{SchemaColumn, SchemaTable, StoredSchemaTable},
};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, QueryResult, Statement};

async fn rows(
    db: &DatabaseConnection,
    sql: &str,
    table: &str,
    schema: Option<&str>,
) -> AuthResult<Vec<QueryResult>> {
    let mut values = vec![table.into()];
    if let Some(schema) = schema {
        values.push(schema.into());
    }
    db.query_all_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        sql,
        values,
    ))
    .await
    .map_err(map_db_err)
}

async fn table(
    db: &DatabaseConnection,
    name: String,
    schema: Option<String>,
) -> AuthResult<Option<StoredSchemaTable>> {
    let sql = if schema.is_some() {
        "SELECT name, type, [notnull], dflt_value, pk FROM pragma_table_info(?, ?)"
    } else {
        "SELECT name, type, [notnull], dflt_value, pk FROM pragma_table_info(?)"
    };
    let values = rows(db, sql, &name, schema.as_deref()).await?;
    if values.is_empty() {
        return Ok(None);
    }
    let mut primary = Vec::new();
    let mut columns = Vec::new();
    for value in values {
        let column: String = value.try_get("", "name").map_err(map_db_err)?;
        let primary_key: i64 = value.try_get("", "pk").map_err(map_db_err)?;
        if primary_key > 0 {
            primary.push((
                column.clone(),
                value.try_get::<String>("", "type").map_err(map_db_err)?,
            ));
        }
        columns.push(SchemaColumn {
            name: column,
            nullable: value.try_get::<i64>("", "notnull").map_err(map_db_err)? == 0,
            has_default: value
                .try_get::<Option<String>>("", "dflt_value")
                .map_err(map_db_err)?
                .is_some(),
        });
    }
    if let [(primary, kind)] = primary.as_slice()
        && kind.eq_ignore_ascii_case("integer")
    {
        let sql = if schema.is_some() {
            "SELECT origin FROM pragma_index_list(?, ?)"
        } else {
            "SELECT origin FROM pragma_index_list(?)"
        };
        let indexes = rows(db, sql, &name, schema.as_deref()).await?;
        let has_primary_index = indexes
            .iter()
            .map(|index| index.try_get::<String>("", "origin").map_err(map_db_err))
            .collect::<AuthResult<Vec<_>>>()?
            .iter()
            .any(|origin| origin == "pk");
        if !has_primary_index
            && let Some(column) = columns.iter_mut().find(|column| &column.name == primary)
        {
            column.has_default = true;
        }
    }
    Ok(Some(StoredSchemaTable {
        name,
        schema,
        columns,
    }))
}

async fn catalog(db: &DatabaseConnection) -> AuthResult<Vec<StoredSchemaTable>> {
    let rows = db.query_all_raw(Statement::from_string(DbBackend::Sqlite, "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT IN ('kysely_migration', 'kysely_migration_lock')")).await.map_err(map_db_err)?;
    let mut tables = Vec::new();
    for row in rows {
        if let Some(table) = table(db, row.try_get("", "name").map_err(map_db_err)?, None).await? {
            tables.push(table);
        }
    }
    Ok(tables)
}

pub(super) async fn tables(
    db: &DatabaseConnection,
    expected: &[SchemaTable],
) -> AuthResult<Vec<StoredSchemaTable>> {
    // Pinned SQLite introspection retries named-table PRAGMAs only if the catalog path fails.
    match catalog(db).await {
        Ok(mut actual) => {
            for expected in expected
                .iter()
                .filter(|table| table.schema.is_some() && !table.disable_migrations)
            {
                if let Some(table) =
                    table(db, expected.name.clone(), expected.schema.clone()).await?
                {
                    actual.push(table);
                }
            }
            Ok(actual)
        }
        Err(_) => {
            let mut actual = Vec::new();
            for expected in expected.iter().filter(|table| !table.disable_migrations) {
                if let Some(table) =
                    table(db, expected.name.clone(), expected.schema.clone()).await?
                {
                    actual.push(table);
                }
            }
            Ok(actual)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn real_sqlite_metadata_preserves_omission_rules() -> AuthResult<()> {
        for (column, suffix, nullable, has_default) in [
            ("legacy TEXT", "", true, false),
            ("legacy TEXT NOT NULL", "", false, false),
            ("legacy TEXT NOT NULL DEFAULT 'provided'", "", false, true),
            ("legacy TEXT NOT NULL DEFAULT NULL", "", false, true),
            ("legacy INTEGER PRIMARY KEY NOT NULL", "", false, true),
            ("legacy INTEGER PRIMARY KEY DESC NOT NULL", "", false, false),
            (
                "legacy INTEGER PRIMARY KEY NOT NULL",
                " WITHOUT ROWID",
                false,
                false,
            ),
        ] {
            let database = sea_orm::Database::connect("sqlite::memory:")
                .await
                .map_err(map_db_err)?;
            let _ = database
                .execute_raw(Statement::from_string(
                    DbBackend::Sqlite,
                    format!("CREATE TABLE fixture ({column}){suffix}"),
                ))
                .await
                .map_err(map_db_err)?;
            let actual = table(&database, "fixture".into(), None)
                .await?
                .ok_or_else(|| better_auth_core::AuthError::internal("fixture table missing"))?;
            assert_eq!(
                actual
                    .columns
                    .iter()
                    .map(|column| (column.name.as_str(), column.nullable, column.has_default))
                    .collect::<Vec<_>>(),
                [("legacy", nullable, has_default)],
                "{column}{suffix}"
            );
        }
        Ok(())
    }
}
