use super::{ApiErrorClass, ApiErrorInit, AuthError, AuthResult, native};
use crate::FieldValue;

impl AuthError {
    /// Preserve UTF-16 message code units in a native TypeError without narrowing to UTF-8.
    pub fn type_error_native(message: impl Into<crate::Utf16String>) -> Self {
        Self::from_thrown(native::runtime_error("TypeError", message.into().into()))
    }

    pub(crate) fn syntax_error(message: FieldValue) -> Self {
        Self::from_thrown(native::runtime_error("SyntaxError", message))
    }

    /// Move an error into a native callback value without applying HTTP error sanitization.
    /// Existing thrown values retain their identity and do not evaluate properties.
    /// Database errors retain one object and available driver properties; typed errors have no JavaScript stack metadata.
    pub fn into_thrown_value(self) -> AuthResult<FieldValue> {
        if let Self::Response(error) = self {
            return Ok(error.value);
        }
        self.callback_value()
    }

    pub(crate) fn callback_value(&self) -> AuthResult<FieldValue> {
        if let Some(value) = self.raw_value() {
            return Ok(value.clone());
        }
        if self.is_api_error_instance(ApiErrorClass::BetterCall) {
            return native::construct(ApiErrorInit {
                class: if self.is_api_error_instance(ApiErrorClass::BetterAuth) {
                    ApiErrorClass::BetterAuth
                } else {
                    ApiErrorClass::BetterCall
                },
                status: self.status_value()?,
                body: self.body_value()?,
                ..Default::default()
            });
        }
        let name = match self.original() {
            Self::TypeError(_) => "TypeError",
            Self::RangeError(_) => "RangeError",
            Self::DataClone => "DataCloneError",
            _ => "Error",
        };
        Ok(native::runtime_error(name, self.message_value()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_type_error_retains_surrogates_brand_and_hidden_message() -> AuthResult<()> {
        let message = crate::Utf16String::from_units(vec![0x61, 0xd800, 0x62]);
        let error = AuthError::type_error_native(message.clone());
        let original = error
            .raw_value()
            .cloned()
            .ok_or_else(|| AuthError::internal("Missing native error"))?;
        assert_eq!(error.message_value()?.display_utf16()?, message);
        assert_eq!(original.model_property("name")?, "TypeError".into());
        assert!(super::super::native::is_error_value(&original));
        assert!(!original.enumerable_fields()?.contains_key("message"));
        assert!(error.into_thrown_value()?.strict_equals(&original));
        Ok(())
    }
}
