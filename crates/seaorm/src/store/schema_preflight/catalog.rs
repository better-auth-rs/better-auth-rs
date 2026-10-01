use super::super::map_db_err;
use better_auth_core::{
    AuthResult,
    store::schema::{SchemaColumn, SchemaTable, StoredSchemaTable},
};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};

fn push_column(
    tables: &mut Vec<StoredSchemaTable>,
    name: String,
    schema: String,
    column: SchemaColumn,
) {
    if let Some(table) = tables
        .iter_mut()
        .find(|table| table.name == name && table.schema.as_deref() == Some(schema.as_str()))
    {
        table.columns.push(column);
    } else {
        tables.push(StoredSchemaTable {
            name,
            schema: Some(schema),
            columns: vec![column],
        });
    }
}

/// Resolve unqualified tables using the effective search path, without a guessed `public` fallback.
fn resolve_search_path(
    expected: &mut [SchemaTable],
    actual: &[StoredSchemaTable],
    search_path: &[String],
) {
    for table in expected.iter_mut().filter(|table| table.schema.is_none()) {
        table.schema = Some(
            search_path
                .iter()
                .find(|schema| {
                    actual.iter().any(|actual| {
                        actual.name == table.name
                            && actual.schema.as_deref() == Some(schema.as_str())
                    })
                })
                .cloned()
                .unwrap_or_default(),
        );
    }
}

pub(super) async fn postgres(
    db: &DatabaseConnection,
    expected: &mut [SchemaTable],
) -> AuthResult<Vec<StoredSchemaTable>> {
    // One statement binds metadata and current_schemas to the same pooled connection and search path.
    let rows = db
        .query_all_raw(Statement::from_string(
            DbBackend::Postgres,
            include_str!("postgres.sql"),
        ))
        .await
        .map_err(map_db_err)?;
    let search_path = rows
        .first()
        .map(|row| row.try_get::<Vec<String>>("", "search_path"))
        .transpose()
        .map_err(map_db_err)?
        .unwrap_or_default();
    let mut tables = Vec::new();
    for row in rows {
        push_column(
            &mut tables,
            row.try_get("", "table_name").map_err(map_db_err)?,
            row.try_get("", "schema_name").map_err(map_db_err)?,
            SchemaColumn {
                name: row.try_get("", "column_name").map_err(map_db_err)?,
                nullable: !row.try_get::<bool>("", "not_null").map_err(map_db_err)?,
                has_default: row.try_get::<bool>("", "has_default").map_err(map_db_err)?
                    || row
                        .try_get::<bool>("", "auto_incrementing")
                        .map_err(map_db_err)?,
            },
        );
    }
    resolve_search_path(expected, &tables, &search_path);
    Ok(tables)
}

pub(super) async fn mysql(db: &DatabaseConnection) -> AuthResult<Vec<StoredSchemaTable>> {
    let rows = db
        .query_all_raw(Statement::from_string(
            DbBackend::MySql,
            include_str!("mysql.sql"),
        ))
        .await
        .map_err(map_db_err)?;
    let mut tables = Vec::new();
    for row in rows {
        push_column(
            &mut tables,
            row.try_get("", "table_name").map_err(map_db_err)?,
            row.try_get("", "schema_name").map_err(map_db_err)?,
            SchemaColumn {
                name: row.try_get("", "column_name").map_err(map_db_err)?,
                nullable: row
                    .try_get::<String>("", "is_nullable")
                    .map_err(map_db_err)?
                    == "YES",
                has_default: row
                    .try_get::<Option<String>>("", "column_default")
                    .map_err(map_db_err)?
                    .is_some()
                    || row
                        .try_get::<String>("", "extra")
                        .map_err(map_db_err)?
                        .to_lowercase()
                        .contains("auto_increment"),
            },
        );
    }
    Ok(tables)
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::store::schema::{SchemaFinding, diff};

    #[test]
    fn postgres_search_path_selects_the_first_visible_table_and_preserves_explicit_schema() {
        let table = |schema: &str, column: &str| StoredSchemaTable {
            name: "user".into(),
            schema: Some(schema.into()),
            columns: vec![SchemaColumn {
                name: column.into(),
                nullable: true,
                has_default: false,
            }],
        };
        let actual = vec![table("public", "id"), table("tenant", "other")];
        let mut expected = vec![SchemaTable {
            name: "user".into(),
            schema: None,
            columns: vec!["id".into()],
            disable_migrations: false,
        }];
        resolve_search_path(&mut expected, &actual, &["tenant".into(), "public".into()]);
        assert_eq!(
            diff(&expected, &actual),
            vec![SchemaFinding::MissingColumn {
                table: "user".into(),
                column: "id".into()
            }]
        );
        expected.first_mut().unwrap().schema = Some("public".into());
        resolve_search_path(&mut expected, &actual, &["tenant".into()]);
        assert!(diff(&expected, &actual).is_empty());
        expected.first_mut().unwrap().schema = None;
        resolve_search_path(&mut expected, &actual, &[]);
        assert_eq!(
            diff(&expected, &actual),
            vec![SchemaFinding::MissingTable {
                table: "user".into()
            }]
        );
    }
}
