use better_auth_core::{
    AuthResult, FieldValue,
    user_fields::{FieldOutputCapabilities, UserFieldConfig, UserFieldType},
};
use sea_orm::{DbBackend, EntityTrait, ModelTrait};

pub(super) fn column_value<E: EntityTrait>(model: &E::Model, column: E::Column) -> sea_orm::Value {
    model.get(column)
}

pub(super) fn capabilities(backend: DbBackend) -> FieldOutputCapabilities {
    FieldOutputCapabilities {
        supports_native_json: backend == DbBackend::Postgres,
        supports_arrays: false,
        supports_booleans: backend == DbBackend::Postgres,
    }
}

pub(super) fn sqlite_extra_output(
    value: sea_orm::Value,
    field: &UserFieldConfig,
) -> AuthResult<Option<FieldValue>> {
    use sea_orm::Value;
    if matches!(field.field_type, UserFieldType::Boolean)
        && let Value::Bool(Some(value)) = value
    {
        return Ok(Some(FieldValue::Number(f64::from(u8::from(value)))));
    }
    if matches!(
        field.field_type,
        UserFieldType::Json | UserFieldType::StringArray | UserFieldType::NumberArray
    ) {
        match &value {
            Value::Json(None) => return Ok(Some(FieldValue::Null)),
            // SQL NULL and a stored JSON literal null must reach the callback differently.
            Value::Json(Some(value)) => {
                return better_auth_core::utils::json::stringify(value)
                    .map(|text| Some(FieldValue::String(text)))
                    .map_err(Into::into);
            }
            value @ Value::Array(_, Some(_)) => {
                return crate::__private_field_value(value.clone())?
                    .stringify()
                    .map(|value| value.map(FieldValue::String));
            }
            _ => {}
        }
    }
    let value = crate::__private_field_value(value)?;
    if matches!(field.field_type, UserFieldType::Date)
        && let FieldValue::Date(date) = &value
    {
        return Ok(Some(date.to_datetime()?.map_or(FieldValue::Null, |date| {
            FieldValue::String(date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        })));
    }
    Ok(Some(value))
}

pub(super) fn plugin_field_output(
    value: sea_orm::Value,
    field: &UserFieldConfig,
    backend: DbBackend,
) -> AuthResult<Option<FieldValue>> {
    if field.references_id() {
        return Ok(None);
    }
    if backend == DbBackend::Sqlite {
        return sqlite_extra_output(value, field);
    }
    if backend == DbBackend::MySql
        && matches!(field.field_type, UserFieldType::Boolean)
        && let sea_orm::Value::Bool(Some(value)) = value
    {
        return Ok(Some(FieldValue::Number(f64::from(u8::from(value)))));
    }
    crate::__private_field_value(value).map(Some)
}
