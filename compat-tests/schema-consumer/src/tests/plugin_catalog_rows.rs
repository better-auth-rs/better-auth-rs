use super::server_catalog_support::TestResult;
use better_auth::{
    FieldValue,
    seaorm::{
        DatabaseConnection, SeaOrmPluginModel,
        sea_orm::{
            ActiveModelTrait, ConnectionTrait, DbBackend, EntityTrait, Iden, Iterable, QueryTrait,
            sqlx::{Row, TypeInfo, ValueRef},
        },
    },
};
use serde_json::{Map, Value, json};

pub(super) async fn stored<M: SeaOrmPluginModel>(
    database: &DatabaseConnection,
) -> TestResult<Vec<Map<String, Value>>> {
    let backend = database.get_database_backend();
    let mut rows = Vec::new();
    if backend == DbBackend::Sqlite {
        // Entity decoding parses JSON in TEXT columns and would hide the physical SQLite value.
        for result in database
            .query_all_raw(M::Entity::find().build(backend))
            .await?
        {
            let raw = result
                .try_as_sqlite_row()
                .ok_or("Missing SQLite driver row")?;
            let mut row = Map::new();
            for column in M::Column::iter() {
                let name = column.to_string();
                let value = raw.try_get_raw(name.as_str())?;
                let value = if value.is_null() {
                    Value::Null
                } else {
                    match value.type_info().name() {
                        "INTEGER" => json!(raw.try_get::<i64, _>(name.as_str())?),
                        "REAL" => json!(raw.try_get::<f64, _>(name.as_str())?),
                        "TEXT" => json!(raw.try_get::<String, _>(name.as_str())?),
                        kind => {
                            return Err(format!("Unsupported SQLite storage type {kind}").into());
                        }
                    }
                };
                let _ = row.insert(name, value);
            }
            rows.push(row);
        }
        return Ok(rows);
    }
    for model in M::Entity::find().all(database).await? {
        let model = model.into_active_model();
        let mut row = Map::new();
        for column in M::Column::iter() {
            let name = column.to_string();
            let value = model
                .get(column)
                .into_value()
                .ok_or("Missing physical column in the stored model")?;
            let mut value = better_auth::seaorm::__private_field_value(value)?;
            if backend != DbBackend::Postgres
                && let FieldValue::Bool(boolean) = value
            {
                value = f64::from(u8::from(boolean)).into();
            }
            row.insert(
                name,
                value
                    .json()?
                    .ok_or("SQL columns cannot contain Undefined")?,
            );
        }
        rows.push(row);
    }
    Ok(rows)
}
