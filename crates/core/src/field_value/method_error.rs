use super::FieldValue;
use crate::{AuthError, Utf16String};

impl FieldValue {
    pub(super) fn not_callable(&self, member: &str, call_source: &str) -> AuthError {
        // Error diagnostics inspect the resolved value without invoking user conversion methods.
        let description: Utf16String = match self {
            Self::Undefined => "undefined".into(),
            Self::Null => "null".into(),
            Self::Bool(value) => value.to_string().into(),
            Self::Number(value) => crate::schema_value::number_string(*value).into(),
            Self::String(value) => format!("\"{value}\"").into(),
            Self::Utf16String(value) => {
                let mut units = vec![u16::from(b'"')];
                units.extend_from_slice(value.as_utf16());
                units.push(u16::from(b'"'));
                Utf16String::from_units(units)
            }
            Self::Object(_) => "an instance of Object".into(),
            Self::Array(_) => "an instance of Array".into(),
            Self::Date(_) => "an instance of Date".into(),
            Self::Function(_) => "a function".into(),
        };
        let mut units = format!("{member} is not a function. (In '{call_source}', '{member}' is ")
            .encode_utf16()
            .collect::<Vec<_>>();
        units.extend_from_slice(description.as_utf16());
        units.push(u16::from(b')'));
        let message = Utf16String::from_units(units);
        match message.to_utf8() {
            Ok(message) => AuthError::type_error(message),
            Err(_) => AuthError::type_error_native(message),
        }
    }
}
