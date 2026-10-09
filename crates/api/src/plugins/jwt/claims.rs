use super::*;
use crate::plugins::json_body::is_truthy;
use better_auth_core::SchemaValue;
use std::sync::LazyLock;

pub(super) fn default_expiration(
    expiration: &JwtExpiration,
    issued: Option<&Value>,
) -> AuthResult<Value> {
    if matches!(expiration, JwtExpiration::At(_)) {
        return Ok(expiration.claim(0.0));
    }
    match issued.filter(|issued| !issued.is_null()) {
        None => Ok(expiration.claim(Utc::now().timestamp() as f64)),
        Some(Value::Bool(issued)) => Ok(expiration.claim(u8::from(*issued).into())),
        Some(Value::Number(issued)) => Ok(expiration.claim(
            issued
                .as_f64()
                .ok_or_else(|| AuthError::internal("Invalid NumericDate"))?,
        )),
        Some(issued) => {
            // Upstream adds the relative lifetime before JOSE parses the resulting NumericDate.
            let issued =
                SchemaValue::<better_auth_core::FieldValue>::from_json(Some(issued.clone()))?
                    .display_string()?;
            let seconds = SchemaValue::<better_auth_core::FieldValue>::from_json(Some(
                expiration.claim(0.0),
            ))?
            .display_string()?;
            Ok(format!("{issued}{seconds}").into())
        }
    }
}

pub(super) fn prepare_local_claims(
    payload: &mut Map<String, Value>,
    subject: &FieldValue,
) -> AuthResult<()> {
    let expiry = numeric_date(&payload["exp"])?;
    let _ = payload.insert("exp".into(), expiry);
    require_string("iss", &payload["iss"])?;
    let audience = &payload["aud"];
    if !audience.is_string()
        && !audience
            .as_array()
            .is_some_and(|values| values.iter().all(Value::is_string))
    {
        return Err(AuthError::internal(
            "\"aud\" claim must be a string or an array of strings",
        ));
    }
    for name in ["iat", "sub", "nbf", "jti"] {
        if name == "sub" {
            if subject.is_truthy()
                && !matches!(subject, FieldValue::String(_) | FieldValue::Utf16String(_))
            {
                return Err(AuthError::internal("\"sub\" claim must be a string"));
            }
            continue;
        }
        if let Some(value) = payload.get(name).filter(|value| is_truthy(value)) {
            if matches!(name, "iat" | "nbf") {
                let date = numeric_date(value)?;
                let _ = payload.insert(name.into(), date);
            } else {
                require_string(name, value)?;
            }
        }
    }
    Ok(())
}

fn require_string(name: &str, value: &Value) -> AuthResult<()> {
    if value.is_string() {
        Ok(())
    } else {
        Err(AuthError::internal(format!(
            "\"{name}\" claim must be a string"
        )))
    }
}

fn numeric_date(value: &Value) -> AuthResult<Value> {
    if value.is_number() {
        return Ok(value.clone());
    }
    static PERIOD: LazyLock<Result<regex::Regex, regex::Error>> = LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)^(\+|\-)? ?([0-9]+|[0-9]+\.[0-9]+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?(?:\r\n|[\n\r\u{2028}\u{2029}])?$",
        )
    });
    let invalid = || AuthError::internal("Invalid time period format");
    let period = PERIOD
        .as_ref()
        .map_err(|error| AuthError::internal(error.to_string()))?;
    let captures = value
        .as_str()
        .and_then(|value| period.captures(value))
        .ok_or_else(invalid)?;
    if captures.get(1).is_some() && captures.get(4).is_some() {
        return Err(invalid());
    }
    let amount: f64 = captures[2].parse().map_err(|_| invalid())?;
    let unit = captures
        .get(3)
        .and_then(|value| value.as_str().as_bytes().first())
        .ok_or_else(invalid)?;
    let scale = match unit.to_ascii_lowercase() {
        b's' => 1.0,
        b'm' => 60.0,
        b'h' => 3600.0,
        b'd' => 86400.0,
        b'w' => 604800.0,
        b'y' => 31557600.0,
        _ => return Err(invalid()),
    };
    let seconds = (amount * scale + 0.5).floor();
    if !seconds.is_finite() {
        return Err(invalid());
    }
    let negative = captures.get(1).is_some_and(|value| value.as_str() == "-")
        || captures.get(4).is_some_and(|value| value.as_str() == "ago");
    Ok(Value::from(
        Utc::now().timestamp() as f64 + if negative { -seconds } else { seconds },
    ))
}
