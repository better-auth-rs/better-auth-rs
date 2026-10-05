use super::TestResult;
use better_auth::seaorm::{
    DatabaseConnection,
    sea_orm::{ConnectionTrait, DbBackend, Statement},
};
use serde_json::{Value, json};

pub(super) async fn observe(
    database: &DatabaseConnection,
    backend: DbBackend,
    table_name: &str,
) -> TestResult<Value> {
    let (index_sql, foreign_key_sql) = match backend {
        DbBackend::Postgres => (
            r#"SELECT t.relname AS "table", i.relname AS "name",
            CASE WHEN x.indisunique THEN 'YES' ELSE 'NO' END AS "unique",
            CAST(k.position AS text) AS "position", a.attname AS "column"
            FROM pg_class t JOIN pg_namespace n ON n.oid = t.relnamespace
            JOIN pg_index x ON x.indrelid = t.oid JOIN pg_class i ON i.oid = x.indexrelid
            JOIN LATERAL unnest(x.indkey) WITH ORDINALITY k(attnum, position) ON TRUE
            LEFT JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
            WHERE n.nspname = current_schema() AND t.relname = $1 AND k.position <= x.indnkeyatts
            ORDER BY i.relname, k.position"#,
            r#"SELECT t.relname AS "table", c.conname AS "name",
            CAST(k.position AS text) AS "position", a.attname AS "column",
            r.relname AS "targetTable", ra.attname AS "targetColumn",
            CASE c.confupdtype WHEN 'a' THEN 'NO ACTION' WHEN 'r' THEN 'RESTRICT'
              WHEN 'c' THEN 'CASCADE' WHEN 'n' THEN 'SET NULL' WHEN 'd' THEN 'SET DEFAULT' END AS "onUpdate",
            CASE c.confdeltype WHEN 'a' THEN 'NO ACTION' WHEN 'r' THEN 'RESTRICT'
              WHEN 'c' THEN 'CASCADE' WHEN 'n' THEN 'SET NULL' WHEN 'd' THEN 'SET DEFAULT' END AS "onDelete"
            FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace JOIN pg_class r ON r.oid = c.confrelid
            JOIN LATERAL unnest(c.conkey, c.confkey) WITH ORDINALITY k(attnum, refnum, position) ON TRUE
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
            JOIN pg_attribute ra ON ra.attrelid = r.oid AND ra.attnum = k.refnum
            WHERE c.contype = 'f' AND n.nspname = current_schema() AND t.relname = $1
            ORDER BY c.conname, k.position"#,
        ),
        DbBackend::MySql => (
            r"SELECT TABLE_NAME AS `table`, INDEX_NAME AS `name`,
            CASE WHEN NON_UNIQUE = 0 THEN 'YES' ELSE 'NO' END AS `unique`,
            CAST(SEQ_IN_INDEX AS CHAR) AS `position`, COLUMN_NAME AS `column`
            FROM information_schema.STATISTICS
            WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? ORDER BY INDEX_NAME, SEQ_IN_INDEX",
            r"SELECT k.TABLE_NAME AS `table`, k.CONSTRAINT_NAME AS `name`,
            CAST(k.ORDINAL_POSITION AS CHAR) AS `position`, k.COLUMN_NAME AS `column`,
            k.REFERENCED_TABLE_NAME AS `targetTable`, k.REFERENCED_COLUMN_NAME AS `targetColumn`,
            r.UPDATE_RULE AS `onUpdate`, r.DELETE_RULE AS `onDelete`
            FROM information_schema.KEY_COLUMN_USAGE k JOIN information_schema.REFERENTIAL_CONSTRAINTS r
              ON r.CONSTRAINT_SCHEMA = k.CONSTRAINT_SCHEMA AND r.TABLE_NAME = k.TABLE_NAME
              AND r.CONSTRAINT_NAME = k.CONSTRAINT_NAME
            WHERE k.TABLE_SCHEMA = DATABASE() AND k.TABLE_NAME = ? AND k.REFERENCED_TABLE_NAME IS NOT NULL
            ORDER BY k.CONSTRAINT_NAME, k.ORDINAL_POSITION",
        ),
        _ => return Err("The DeviceCode index observer requires PostgreSQL or MySQL".into()),
    };
    let mut indexes = Vec::new();
    for row in database
        .query_all_raw(Statement::from_sql_and_values(
            backend,
            index_sql,
            [table_name.into()],
        ))
        .await?
    {
        indexes.push(json!({
            "table": row.try_get::<String>("", "table")?,
            "name": row.try_get::<String>("", "name")?,
            "unique": row.try_get::<String>("", "unique")?,
            "position": row.try_get::<String>("", "position")?,
            "column": row.try_get::<Option<String>>("", "column")?,
        }));
    }
    let mut foreign_keys = Vec::new();
    for row in database
        .query_all_raw(Statement::from_sql_and_values(
            backend,
            foreign_key_sql,
            [table_name.into()],
        ))
        .await?
    {
        foreign_keys.push(json!({
            "table": row.try_get::<String>("", "table")?,
            "name": row.try_get::<String>("", "name")?,
            "position": row.try_get::<String>("", "position")?,
            "column": row.try_get::<String>("", "column")?,
            "targetTable": row.try_get::<String>("", "targetTable")?,
            "targetColumn": row.try_get::<String>("", "targetColumn")?,
            "onUpdate": row.try_get::<String>("", "onUpdate")?,
            "onDelete": row.try_get::<String>("", "onDelete")?,
        }));
    }
    Ok(json!({"indexes": indexes, "foreignKeys": foreign_keys}))
}
