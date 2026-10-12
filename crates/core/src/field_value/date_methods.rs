use super::{FieldDate, FieldValue};
use crate::{AuthError, AuthResult};

impl FieldValue {
    /// Invoke a Date getter without narrowing a custom method's return value.
    /// Built-in local getters retain the Date's full TimeClip range on Unix.
    pub fn date_getter_method(&self, method: &str, expression: &str) -> AuthResult<Self> {
        self.read_date_getter(method, |value| {
            let invocation = format!("{expression}.{method}");
            let mut message = format!("{invocation} is not a function");
            if let Some(Self::Bool(value)) = value {
                message.push_str(&format!(
                    ". (In '{invocation}()', '{invocation}' is {value})"
                ));
            }
            AuthError::type_error(message)
        })
    }

    pub(super) fn read_date_getter(
        &self,
        method: &str,
        non_callable: impl FnOnce(Option<&Self>) -> AuthError,
    ) -> AuthResult<Self> {
        let property = self.method_property(method)?;
        match (self, property.as_ref()) {
            (_, Some(Self::Function(callback))) => callback.call_with(self, &[]),
            (Self::Date(date), None) => match method {
                "getTime" => Ok(date.milliseconds().into()),
                "getFullYear" | "getMonth" | "getDate" | "getHours" | "getMinutes"
                | "getSeconds" | "getMilliseconds" => date.local_component(method),
                _ => Err(non_callable(None)),
            },
            _ => Err(non_callable(property.as_ref())),
        }
    }
}

impl FieldDate {
    fn local_component(&self, method: &str) -> AuthResult<FieldValue> {
        let Some(milliseconds) = self.0.milliseconds else {
            return Ok(f64::NAN.into());
        };
        if method == "getMilliseconds" {
            return Ok(milliseconds.rem_euclid(1_000).into());
        }
        local_component(milliseconds, method)
    }
}

#[cfg(unix)]
fn local_component(milliseconds: i64, method: &str) -> AuthResult<FieldValue> {
    let seconds = libc::time_t::try_from(milliseconds.div_euclid(1_000)).map_err(|cause| {
        AuthError::internal(format!(
            "Date seconds exceed the host time_t range: {cause}"
        ))
    })?;
    let mut local = std::mem::MaybeUninit::<libc::tm>::uninit();
    // SAFETY: Both pointers reference live storage. localtime_r writes one tm before returning its address.
    let result = unsafe { libc::localtime_r(&seconds, local.as_mut_ptr()) };
    if result.is_null() {
        return Err(AuthError::internal(format!(
            "Cannot read local Date components: {}",
            std::io::Error::last_os_error(),
        )));
    }
    // SAFETY: A non-null localtime_r result confirms that local was initialized.
    let local = unsafe { local.assume_init() };
    Ok(match method {
        "getFullYear" => (local.tm_year + 1900).into(),
        "getMonth" => local.tm_mon.into(),
        "getDate" => local.tm_mday.into(),
        "getHours" => local.tm_hour.into(),
        "getMinutes" => local.tm_min.into(),
        "getSeconds" => local.tm_sec.into(),
        _ => return Err(AuthError::internal("Unknown local Date component")),
    })
}

#[cfg(not(unix))]
fn local_component(milliseconds: i64, method: &str) -> AuthResult<FieldValue> {
    use chrono::{Datelike, Timelike};

    let date = chrono::DateTime::from_timestamp_millis(milliseconds)
        .ok_or_else(|| {
            AuthError::internal("Valid Date milliseconds exceed the host calendar range")
        })?
        .with_timezone(&chrono::Local);
    Ok(match method {
        "getFullYear" => date.year().into(),
        "getMonth" => date.month0().into(),
        "getDate" => date.day().into(),
        "getHours" => date.hour().into(),
        "getMinutes" => date.minute().into(),
        "getSeconds" => date.second().into(),
        _ => return Err(AuthError::internal("Unknown local Date component")),
    })
}
