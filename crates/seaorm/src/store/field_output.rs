use better_auth_core::{
    AuthResult,
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
) -> AuthResult<Option<serde_json::Value>> {
    use sea_orm::Value;
    if matches!(field.field_type, UserFieldType::Boolean)
        && let Value::Bool(Some(value)) = value
    {
        return Ok(Some(serde_json::Value::from(i64::from(value))));
    }
    if matches!(
        field.field_type,
        UserFieldType::Json | UserFieldType::StringArray | UserFieldType::NumberArray
    ) {
        match &value {
            Value::Json(None) => return Ok(Some(serde_json::Value::Null)),
            // SQL NULL and a stored JSON literal null must reach the callback differently.
            Value::Json(Some(value)) => {
                return better_auth_core::utils::json::stringify(value)
                    .map(|text| Some(serde_json::Value::String(text)))
                    .map_err(Into::into);
            }
            Value::Array(_, Some(_)) => {
                return better_auth_core::utils::json::stringify(
                    &sea_orm::sea_query::sea_value_to_json_value(&value),
                )
                .map(|text| Some(serde_json::Value::String(text)))
                .map_err(Into::into);
            }
            _ => {}
        }
    }
    if matches!(field.field_type, UserFieldType::Date) {
        return match value {
            Value::ChronoDateTimeUtc(value) => better_auth_core::utils::date::serialize_option(
                &value,
                serde_json::value::Serializer,
            )
            .map(Some)
            .map_err(Into::into),
            Value::ChronoDate(value) => Ok(Some(serde_json::to_value(value)?)),
            Value::ChronoTime(value) => Ok(Some(serde_json::to_value(value)?)),
            Value::ChronoDateTime(value) => Ok(Some(serde_json::to_value(value)?)),
            Value::ChronoDateTimeWithTimeZone(value) => Ok(Some(serde_json::to_value(value)?)),
            Value::ChronoDateTimeLocal(value) => Ok(Some(serde_json::to_value(value)?)),
            // The SQL formatter changes these representations; retain their serialized source.
            Value::TimeDate(_)
            | Value::TimeTime(_)
            | Value::TimeDateTime(_)
            | Value::TimeDateTimeWithTimeZone(_) => Ok(None),
            value => Ok(Some(sea_orm::sea_query::sea_value_to_json_value(&value))),
        };
    }
    Ok(Some(sea_orm::sea_query::sea_value_to_json_value(&value)))
}

pub(super) fn plugin_field_output(
    value: sea_orm::Value,
    field: &UserFieldConfig,
    backend: DbBackend,
) -> AuthResult<Option<serde_json::Value>> {
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
        return Ok(Some(serde_json::Value::from(i64::from(value))));
    }
    Ok(None)
}
