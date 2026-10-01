use better_auth_core::{AuthResult, SchemaValue};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, Iden, Iterable, QueryFilter,
    sea_query::{Expr, Query, SimpleExpr},
};

use super::{
    map_db_err,
    record_bindings::{self, Binding},
};
use crate::SeaOrmUserModel;

fn fields<M: SeaOrmUserModel>(
    active: M::ActiveModel,
    name: SchemaValue<Option<String>>,
    image: SchemaValue<Option<String>>,
) -> AuthResult<Vec<(<M::Entity as EntityTrait>::Column, Binding)>> {
    let mut fields = Vec::new();
    // The upstream adapter walks the logical schema, independent of request key order or SQL column names.
    for key in [
        "name",
        "email",
        "emailVerified",
        "image",
        "createdAt",
        "updatedAt",
    ] {
        let column = M::field_column(key)?;
        let raw = match key {
            "name" => Some(&name),
            "image" => Some(&image),
            _ => None,
        };
        if let Some(raw) = raw {
            if let Some(value) = raw.json()? {
                fields.push((column, Binding::for_column(column, value)));
            }
        } else if let sea_orm::ActiveValue::Set(value) = active.get(column) {
            fields.push((column, Binding::Native(value)));
        }
    }
    for column in <M::Entity as EntityTrait>::Column::iter() {
        if column.to_string() == M::id_column().to_string()
            || fields
                .iter()
                .any(|(existing, _)| existing.to_string() == column.to_string())
            || column.to_string() == M::field_column("name")?.to_string()
            || column.to_string() == M::field_column("image")?.to_string()
        {
            continue;
        }
        if let sea_orm::ActiveValue::Set(value) = active.get(column) {
            fields.push((column, Binding::Native(value)));
        }
    }
    if let sea_orm::ActiveValue::Set(value) = active.get(M::id_column()) {
        fields.push((M::id_column(), Binding::Native(value)));
    }
    Ok(fields)
}

pub(super) async fn insert<M: SeaOrmUserModel>(
    db: &impl ConnectionTrait,
    active: M::ActiveModel,
    name: SchemaValue<Option<String>>,
    image: SchemaValue<Option<String>>,
) -> AuthResult<M> {
    let fields = fields::<M>(active, name, image)?;
    let backend = db.get_database_backend();
    let (columns, bindings): (Vec<_>, Vec<_>) = fields.into_iter().unzip();
    let values = record_bindings::bind(backend, bindings)?;
    let id = columns
        .iter()
        .position(|column| column.to_string() == M::id_column().to_string())
        .and_then(|index| values.get(index))
        .cloned();
    let mut query = Query::insert();
    let _ = query
        .into_table(M::Entity::default())
        .columns(columns)
        .values_panic(values.into_iter().map(SimpleExpr::Value));
    if db.support_returning() {
        let _ = query.returning(Query::returning().all());
        return M::find_by_statement(backend.build(&query))
            .one(db)
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| {
                better_auth_core::AuthError::internal("User insert returned no record")
            });
    }
    let result = db
        .execute_raw(backend.build(&query))
        .await
        .map_err(map_db_err)?;
    M::Entity::find()
        .filter(M::id_column().eq(id.unwrap_or_else(|| result.last_insert_id().into())))
        .one(db)
        .await
        .map_err(map_db_err)?
        .ok_or_else(|| better_auth_core::AuthError::internal("User insert returned no record"))
}

pub(super) async fn update<M: SeaOrmUserModel>(
    db: &impl ConnectionTrait,
    active: M::ActiveModel,
    name: SchemaValue<Option<String>>,
    image: SchemaValue<Option<String>>,
    id: sea_orm::Value,
) -> AuthResult<Option<M>> {
    let fields = fields::<M>(active, name, image)?;
    let backend = db.get_database_backend();
    let (columns, bindings): (Vec<_>, Vec<_>) = fields.into_iter().unzip();
    let values = record_bindings::bind(backend, bindings)?;
    let mut query = M::Entity::update_many();
    for (column, value) in columns.into_iter().zip(values) {
        query = query.col_expr(column, Expr::val(value));
    }
    super::updates::execute_update_returning_one(
        db,
        query.filter(M::id_column().eq(id.clone())),
        M::id_column().eq(id),
    )
    .await
}
