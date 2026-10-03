use better_auth::seaorm::{
    DatabaseConnection,
    sea_orm::{ConnectionTrait, DbBackend, DbErr, QueryResult, Statement},
};
use serde_json::{Value, json};

async fn rows(
    database: &DatabaseConnection,
    sql: &str,
    name: &str,
) -> Result<Vec<QueryResult>, DbErr> {
    database
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            sql,
            [name.into()],
        ))
        .await
}

pub(super) async fn observe(
    database: &DatabaseConnection,
    table_name: &str,
    missing_table: &str,
) -> Result<(Value, Value), DbErr> {
    let table = database
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT type, name, tbl_name FROM sqlite_schema WHERE type = 'table' AND name = ?",
            [table_name.into()],
        ))
        .await?
        .expect(missing_table);
    let table = json!({
        "type": table.try_get::<String>("", "type")?,
        "name": table.try_get::<String>("", "name")?,
        "tbl_name": table.try_get::<String>("", "tbl_name")?,
    });
    let columns = rows(
        database,
        "SELECT cid, name, type, \"notnull\", dflt_value, pk FROM pragma_table_info(?) ORDER BY cid",
        table_name,
    )
    .await?
    .into_iter()
    .map(|row| {
        Ok(json!({
            "cid": row.try_get::<i64>("", "cid")?,
            "name": row.try_get::<String>("", "name")?,
            "type": row.try_get::<String>("", "type")?,
            "notnull": row.try_get::<i64>("", "notnull")?,
            "dflt_value": row.try_get::<Option<String>>("", "dflt_value")?,
            "pk": row.try_get::<i64>("", "pk")?,
        }))
    })
    .collect::<Result<Vec<_>, DbErr>>()?;
    let mut indexes = Vec::new();
    for row in rows(
        database,
        "SELECT seq, name, \"unique\", origin, partial FROM pragma_index_list(?) ORDER BY seq",
        table_name,
    )
    .await?
    {
        let index_name: String = row.try_get("", "name")?;
        let definition = json!({
            "seq": row.try_get::<i64>("", "seq")?,
            "name": index_name,
            "unique": row.try_get::<i64>("", "unique")?,
            "origin": row.try_get::<String>("", "origin")?,
            "partial": row.try_get::<i64>("", "partial")?,
        });
        let columns = rows(
            database,
            "SELECT seqno, cid, name FROM pragma_index_info(?) ORDER BY seqno",
            &index_name,
        )
        .await?
        .into_iter()
        .map(|row| {
            Ok(json!({
                "seqno": row.try_get::<i64>("", "seqno")?,
                "cid": row.try_get::<i64>("", "cid")?,
                "name": row.try_get::<Option<String>>("", "name")?,
            }))
        })
        .collect::<Result<Vec<_>, DbErr>>()?;
        let extended_columns = rows(
            database,
            "SELECT seqno, cid, name, \"desc\", coll, \"key\" FROM pragma_index_xinfo(?) ORDER BY seqno",
            &index_name,
        )
        .await?
        .into_iter()
        .map(|row| {
            Ok(json!({
                "seqno": row.try_get::<i64>("", "seqno")?,
                "cid": row.try_get::<i64>("", "cid")?,
                "name": row.try_get::<Option<String>>("", "name")?,
                "desc": row.try_get::<i64>("", "desc")?,
                "coll": row.try_get::<String>("", "coll")?,
                "key": row.try_get::<i64>("", "key")?,
            }))
        })
        .collect::<Result<Vec<_>, DbErr>>()?;
        indexes.push(json!({
            "definition": definition,
            "columns": columns,
            "extendedColumns": extended_columns,
        }));
    }
    let foreign_keys = rows(
        database,
        "SELECT id, seq, \"table\", \"from\", \"to\", on_update, on_delete, \"match\" FROM pragma_foreign_key_list(?) ORDER BY id, seq",
        table_name,
    )
    .await?
    .into_iter()
    .map(|row| {
        Ok(json!({
            "id": row.try_get::<i64>("", "id")?,
            "seq": row.try_get::<i64>("", "seq")?,
            "table": row.try_get::<String>("", "table")?,
            "from": row.try_get::<String>("", "from")?,
            "to": row.try_get::<Option<String>>("", "to")?,
            "on_update": row.try_get::<String>("", "on_update")?,
            "on_delete": row.try_get::<String>("", "on_delete")?,
            "match": row.try_get::<String>("", "match")?,
        }))
    })
    .collect::<Result<Vec<_>, DbErr>>()?;
    let ddl = rows(
        database,
        "SELECT type, name, tbl_name, sql FROM sqlite_schema WHERE tbl_name = ? ORDER BY type, name",
        table_name,
    )
    .await?
    .into_iter()
    .map(|row| {
        Ok(json!({
            "type": row.try_get::<String>("", "type")?,
            "name": row.try_get::<String>("", "name")?,
            "tbl_name": row.try_get::<String>("", "tbl_name")?,
            "sql": row.try_get::<Option<String>>("", "sql")?,
        }))
    })
    .collect::<Result<Vec<_>, DbErr>>()?;
    Ok((
        json!({
            "table": table,
            "columns": columns,
            "indexes": indexes,
            "foreignKeys": foreign_keys,
        }),
        json!(ddl),
    ))
}
