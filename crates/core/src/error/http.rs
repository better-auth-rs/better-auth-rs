use super::{AuthError, AuthResult};
use crate::{
    FieldValue,
    observability::{LogArgument, LogLevel, Logger, LoggerSource},
};

impl AuthError {
    pub(crate) fn log_http_error(&self, logger: &Logger, options: &LoggerSource) -> AuthResult<()> {
        let level = options.raw_level()?;
        let disabled = options.raw_disabled()?;
        if disabled.strict_equals(&true.into()) {
            return Ok(());
        }
        if self.http_has_property("message")? && self.message_value()?.is_string() {
            for keyword in ["no column", "column", "relation", "table", "does not exist"] {
                if message_includes(&self.message_value()?, keyword)? {
                    logger.log(
                        LogLevel::Error,
                        LogArgument::Native(&self.message_value()?),
                        &[],
                    )?;
                    return Ok(());
                }
            }
        }
        if self.is_api_error()? {
            if self
                .status_value()?
                .strict_equals(&"INTERNAL_SERVER_ERROR".into())
            {
                logger.log(
                    LogLevel::Error,
                    LogArgument::Native(&self.status_value()?),
                    &[self.http_log_argument()],
                )?;
            }
            if ["error", "warn", "debug"]
                .iter()
                .any(|name| level.strict_equals(&(*name).into()))
            {
                crate::observability::logger::current().log(
                    LogLevel::Error,
                    LogArgument::Native(&self.message_value()?),
                    &[],
                )?;
            }
        } else {
            let name = if self.http_has_property("name")? {
                match self.raw_value() {
                    Some(value) => value.model_property("name")?,
                    None => match self.original() {
                        Self::TypeError(_) => "TypeError",
                        Self::RangeError(_) => "RangeError",
                        Self::DataClone => "DataCloneError",
                        _ => "Error",
                    }
                    .into(),
                }
            } else {
                "".into()
            };
            logger.log(
                LogLevel::Error,
                LogArgument::Native(&name),
                &[self.http_log_argument()],
            )?;
        }
        Ok(())
    }

    fn http_has_property(&self, name: &str) -> AuthResult<bool> {
        match self.raw_value() {
            Some(value @ (FieldValue::Object(_) | FieldValue::Array(_) | FieldValue::Date(_))) => {
                value.has_property(name)
            }
            Some(_) => Ok(false),
            None => Ok(matches!(name, "message" | "name")),
        }
    }

    fn http_log_argument(&self) -> LogArgument<'_> {
        match self.raw_value() {
            Some(value) => LogArgument::Native(value),
            None => LogArgument::Error(self),
        }
    }
}

fn message_includes(message: &FieldValue, keyword: &str) -> AuthResult<bool> {
    match message {
        FieldValue::String(value) => Ok(value.contains(keyword)),
        FieldValue::Utf16String(value) => {
            let keyword: Vec<_> = keyword.encode_utf16().collect();
            Ok(value
                .as_utf16()
                .windows(keyword.len())
                .any(|window| window == keyword.as_slice()))
        }
        FieldValue::Array(array) => array.includes(&keyword.into()),
        _ => match message.model_property("includes")? {
            FieldValue::Function(method) => {
                Ok(method.call_with(message, &[keyword.into()])?.is_truthy())
            }
            _ => Err(AuthError::type_error(
                "Error message includes property is not callable",
            )),
        },
    }
}
