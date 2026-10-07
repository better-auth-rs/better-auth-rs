use better_auth_core::{AuthResult, FieldValue};
use sea_orm::{
    ColumnTrait, DbBackend,
    sea_query::{ExprTrait, SimpleExpr},
};

use super::id_filter::IdColumn;

pub(super) fn equals_id(
    column: impl ColumnTrait,
    value: &FieldValue,
    policy: &better_auth_core::id::IdGeneration,
    backend: DbBackend,
) -> AuthResult<SimpleExpr> {
    match value {
        FieldValue::String(value) => column.eq_id(value, policy),
        value => equals(column, value, backend),
    }
}

pub(super) fn equals(
    column: impl ColumnTrait,
    value: &FieldValue,
    backend: DbBackend,
) -> AuthResult<SimpleExpr> {
    if value.is_null() || value.is_undefined() {
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
