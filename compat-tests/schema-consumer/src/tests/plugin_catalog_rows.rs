use super::server_catalog_support::TestResult;
use better_auth::{
    FieldValue,
    seaorm::{
        DatabaseConnection, SeaOrmPluginModel,
        sea_orm::{ActiveModelTrait, DbBackend, EntityTrait, Iden, Iterable},
    },
};
use serde_json::{Map, Value};

pub(super) async fn stored<M: SeaOrmPluginModel>(
    database: &DatabaseConnection,
) -> TestResult<Vec<Map<String, Value>>> {
    let backend = database.get_database_backend();
    let mut rows = Vec::new();
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
