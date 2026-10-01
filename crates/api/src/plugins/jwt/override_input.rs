use super::*;
use serde::{Deserialize, Deserializer, de::Error};
use std::sync::LazyLock;

pub(super) fn expiration<'de, D: Deserializer<'de>>(
    input: D,
) -> Result<Option<JwtExpiration>, D::Error> {
    Option::<Value>::deserialize(input)?
        .map(|value| match value {
            Value::Number(value) => Ok(JwtExpiration::At(value)),
            Value::String(value) => relative_seconds(&value)
                .and_then(|seconds| {
                    Duration::try_seconds(seconds)
                        .ok_or_else(|| "JWT lifetime is out of range".into())
                })
                .map(JwtExpiration::After)
                .map_err(D::Error::custom),
            _ => Err(D::Error::custom(
                "JWT expirationTime must be a number or time string",
            )),
        })
        .transpose()
}

pub(super) fn duration<'de, D: Deserializer<'de>>(input: D) -> Result<Option<Duration>, D::Error> {
    Option::<f64>::deserialize(input)?
        .map(|seconds| {
            if !seconds.is_finite() || !(i64::MIN as f64..i64::MAX as f64).contains(&seconds) {
                return Err(D::Error::custom("JWT rotationInterval is out of range"));
            }
            Duration::try_seconds(seconds.trunc() as i64)
                .and_then(|whole| {
                    whole.checked_add(&Duration::nanoseconds((seconds.fract() * 1e9) as i64))
                })
                .ok_or_else(|| D::Error::custom("JWT rotationInterval is out of range"))
        })
        .transpose()
}

fn relative_seconds(value: &str) -> Result<i64, String> {
    static PERIOD: LazyLock<Result<regex::Regex, regex::Error>> = LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)^(\+|\-)? ?([0-9]+|[0-9]+\.[0-9]+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|months?|mo|years?|yrs?|y)(?: (ago|from now))?(?:\r\n|[\n\r\u{2028}\u{2029}])?$",
        )
    });
    let invalid = || {
        format!(
            "Invalid time string format: \"{value}\". Use formats like \"7d\", \"30m\", \"1 hour\", etc."
        )
    };
    let captures = PERIOD
        .as_ref()
        .map_err(ToString::to_string)?
        .captures(value)
        .ok_or_else(invalid)?;
    if captures.get(1).is_some() && captures.get(4).is_some() {
        return Err(invalid());
    }
    let amount: f64 = captures
        .get(2)
        .ok_or_else(invalid)?
        .as_str()
        .parse()
        .map_err(|_| invalid())?;
    let unit = captures
        .get(3)
        .ok_or_else(invalid)?
        .as_str()
        .to_ascii_lowercase();
    let scale = match unit.as_str() {
        "year" | "years" | "yr" | "yrs" | "y" => 31557600.0,
        "month" | "months" | "mo" => 2592000.0,
        "week" | "weeks" | "w" => 604800.0,
        "day" | "days" | "d" => 86400.0,
        "hour" | "hours" | "hr" | "hrs" | "h" => 3600.0,
        "minute" | "minutes" | "min" | "mins" | "m" => 60.0,
        "second" | "seconds" | "sec" | "secs" | "s" => 1.0,
        _ => return Err(invalid()),
    };
    let negative = captures.get(1).is_some_and(|value| value.as_str() == "-")
        || captures.get(4).is_some_and(|value| value.as_str() == "ago");
    let seconds = (if negative {
        -amount * scale
    } else {
        amount * scale
    } + 0.5)
        .floor();
    if !seconds.is_finite() || !(i64::MIN as f64..i64::MAX as f64).contains(&seconds) {
        return Err(invalid());
    }
    Ok(seconds as i64)
}
