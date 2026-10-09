use better_auth_core::{
    AuthResult, FieldValue,
    user_fields::{UserFieldConfig, UserFieldType},
};
use sea_orm::{
    ColumnTrait, DbBackend,
    sea_query::{ExprTrait, SimpleExpr},
};

use super::id_filter::IdColumn;

pub(super) fn adapter_query_value(
    mut value: FieldValue,
    original: &FieldValue,
    field: &UserFieldConfig,
    backend: DbBackend,
) -> AuthResult<FieldValue> {
    if backend == DbBackend::Sqlite
        && matches!(field.field_type, UserFieldType::Date)
        && let FieldValue::Date(date) = original
    {
        value = super::record_bindings::sqlite_date(date.clone())?;
    }
    if backend != DbBackend::Postgres
        && matches!(field.field_type, UserFieldType::Json)
        && matches!(
            original,
            FieldValue::Null | FieldValue::Date(_) | FieldValue::Array(_) | FieldValue::Object(_)
        )
    {
        value = original
            .stringify()?
            .map(FieldValue::String)
            .unwrap_or_default();
    }
    if backend != DbBackend::Postgres
        && matches!(field.field_type, UserFieldType::Boolean)
        && let FieldValue::Bool(boolean) = value
    {
        value = FieldValue::Number(f64::from(u8::from(boolean)));
    }
    Ok(value)
}

pub(super) fn like_pattern(
    value: &FieldValue,
    prefix: &str,
    suffix: &str,
    backend: DbBackend,
) -> AuthResult<SimpleExpr> {
    let text = value.display_utf16()?;
    let units = prefix
        .encode_utf16()
        .chain(text.as_utf16().iter().copied())
        .chain(suffix.encode_utf16())
        .collect();
    super::record_bindings::parameter(
        better_auth_core::Utf16String::from_units(units).into(),
        backend,
    )
}

pub(super) fn equals_id(
    column: impl ColumnTrait,
    value: &FieldValue,
    policy: &better_auth_core::id::IdGeneration,
    backend: DbBackend,
) -> AuthResult<SimpleExpr> {
    let value = policy.adapter_id_query(value.clone())?;
    match &value {
        FieldValue::String(value) => column.eq_id(value, policy, backend),
        value => equals(column, value, backend),
    }
}

pub(super) fn equals(
    column: impl ColumnTrait,
    value: &FieldValue,
    backend: DbBackend,
) -> AuthResult<SimpleExpr> {
    if value.is_null() {
        return Ok(column.is_null());
    }
    let value = if let FieldValue::Array(values) = value {
        SimpleExpr::Tuple(
            values
                .iter()
                .cloned()
                .map(|value| super::record_bindings::parameter(value, backend))
                .collect::<AuthResult<Vec<_>>>()?,
        )
    } else {
        super::record_bindings::parameter(value.clone(), backend)?
    };
    Ok(column.into_expr().eq(column.save_as(value)))
}

pub(super) fn equals_native(
    column: impl ColumnTrait,
    value: impl Into<sea_orm::Value>,
    backend: DbBackend,
) -> AuthResult<SimpleExpr> {
    let value = super::record_bindings::Binding::Native(value.into()).bind(backend)?;
    Ok(column.into_expr().eq(column.save_as(value)))
}

pub(super) fn is_in(
    column: impl ColumnTrait,
    value: &FieldValue,
    backend: DbBackend,
) -> AuthResult<SimpleExpr> {
    let values = value
        .as_array()
        .unwrap_or_else(|| std::slice::from_ref(value));
    in_bindings(
        column,
        values
            .iter()
            .cloned()
            .map(super::record_bindings::Binding::Raw)
            .collect(),
        backend,
    )
}

pub(super) fn is_in_native(
    column: impl ColumnTrait,
    values: impl IntoIterator<Item = impl Into<sea_orm::Value>>,
    backend: DbBackend,
) -> AuthResult<SimpleExpr> {
    in_bindings(
        column,
        values
            .into_iter()
            .map(|value| super::record_bindings::Binding::Native(value.into()))
            .collect(),
        backend,
    )
}

fn in_bindings(
    column: impl ColumnTrait,
    values: Vec<super::record_bindings::Binding>,
    backend: DbBackend,
) -> AuthResult<SimpleExpr> {
    let values = super::record_bindings::bind(backend, values)?;
    Ok(column
        .into_expr()
        .is_in(values.into_iter().map(|value| column.save_as(value))))
}

#[cfg(test)]
#[path = "core_query_binding_tests.rs"]
mod core_query_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::entities::api_key;
    use sea_orm::{QueryFilter, QueryTrait};

    #[test]
    fn undefined_equality_keeps_the_driver_binding_instead_of_testing_for_null() -> AuthResult<()> {
        use sea_orm::EntityTrait;

        for backend in [DbBackend::Sqlite, DbBackend::Postgres, DbBackend::MySql] {
            let undefined = api_key::Entity::find()
                .filter(equals(
                    api_key::Column::LastRefillAt,
                    &FieldValue::Undefined,
                    backend,
                )?)
                .build(backend)
                .to_string();
            let null = api_key::Entity::find()
                .filter(equals(
                    api_key::Column::LastRefillAt,
                    &FieldValue::Null,
                    backend,
                )?)
                .build(backend)
                .to_string();
            assert!(undefined.ends_with(" = NULL"), "{backend:?}: {undefined}");
            assert!(null.ends_with(" IS NULL"), "{backend:?}: {null}");
        }
        Ok(())
    }
}
