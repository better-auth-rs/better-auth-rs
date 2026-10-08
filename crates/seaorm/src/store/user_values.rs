use better_auth_core::{AuthResult, SchemaValue};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, Iden, Iterable,
    QueryFilter,
    sea_query::{ExprTrait, Value},
};

use super::{
    create_readback::CreateReadback,
    record_bindings::{self, Binding},
    record_write::RecordWrite,
};
use crate::SeaOrmUserModel;

fn fields<M: SeaOrmUserModel>(
    backend: DbBackend,
    active: M::ActiveModel,
    name: SchemaValue<Option<String>>,
    image: SchemaValue<Option<String>>,
    extra: better_auth_core::FieldMap,
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
            if let Some(value) = Some(raw.field_value()).filter(|value| !value.is_undefined()) {
                fields.push((column, Binding::for_column(column, value)));
            }
        } else if let sea_orm::ActiveValue::Set(value) = active.get(column) {
            let binding = match (backend, key, value) {
                (DbBackend::Sqlite, "createdAt" | "updatedAt", Value::ChronoDateTimeUtc(value)) => {
                    Binding::Raw(value.map_or(better_auth_core::FieldValue::Null, |value| {
                        better_auth_core::FieldValue::String(
                            value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                        )
                    }))
                }
                (_, _, value) => Binding::Native(value),
            };
            fields.push((column, binding));
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
    for (name, value) in extra {
        if value.is_undefined() {
            continue;
        }
        let column = M::field_column(&name)?;
        let value = Binding::for_column(column, value);
        if let Some((_, stored)) = fields
            .iter_mut()
            .find(|(stored, _)| stored.to_string() == column.to_string())
        {
            *stored = value;
        } else {
            fields.push((column, value));
        }
    }
    Ok(fields)
}

pub(super) async fn insert<M: SeaOrmUserModel>(
    db: &impl ConnectionTrait,
    active: M::ActiveModel,
    name: SchemaValue<Option<String>>,
    image: SchemaValue<Option<String>>,
    extra: better_auth_core::FieldMap,
    readback: CreateReadback<'_, M::Entity>,
) -> AuthResult<Option<M>> {
    let backend = db.get_database_backend();
    let fields = fields::<M>(backend, active, name, image, extra)?;
    RecordWrite::<M::Entity>::from_bindings(fields)
        .insert(db, readback)
        .await
}

pub(super) async fn update<M: SeaOrmUserModel>(
    db: &impl ConnectionTrait,
    active: M::ActiveModel,
    name: SchemaValue<Option<String>>,
    image: SchemaValue<Option<String>>,
    extra: better_auth_core::FieldMap,
    id: better_auth_core::FieldValue,
    policy: &better_auth_core::id::IdGeneration,
) -> AuthResult<Option<M>> {
    let backend = db.get_database_backend();
    let fields = fields::<M>(backend, active, name, image, extra)?;
    let (columns, bindings): (Vec<_>, Vec<_>) = fields.into_iter().unzip();
    let values = record_bindings::bind(backend, bindings)?;
    let column = M::id_column();
    let filter = if id.is_undefined() {
        column
            .into_expr()
            .eq(column.save_as(record_bindings::parameter(id, backend)?))
    } else {
        super::value_filter::equals_id(column, &id, policy, backend)?
    };
    let mut query = M::Entity::update_many();
    for (column, value) in columns.into_iter().zip(values) {
        query = query.col_expr(column, value);
    }
    super::updates::execute_update_returning_one(db, query.filter(filter.clone()), filter).await
}
