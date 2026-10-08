//! Preserve the default pg and mysql2 query decoders before field transforms.

use better_auth_core::{AuthResult, FieldDate, FieldValue};
use sea_orm::{
    entity::prelude::BigDecimal,
    sqlx::{
        Decode, MySql, Postgres,
        error::UnexpectedNullError,
        mysql::MySqlValueRef,
        postgres::{PgValueFormat, PgValueRef},
    },
};

use super::{error, local_date};

pub(super) fn postgres_numeric(raw: PgValueRef<'_>, column: &str) -> AuthResult<FieldValue> {
    if matches!(raw.format(), PgValueFormat::Text) {
        return raw
            .as_str()
            .map(FieldValue::from)
            .map_err(|cause| error(column, cause));
    }
    let bytes = raw.as_bytes().map_err(|cause| error(column, cause))?;
    let [_, _, _, _, sign_high, sign_low, scale_high, scale_low, ..] = bytes else {
        return Err(error(column, "incomplete PostgreSQL NUMERIC header"));
    };
    let special = match u16::from_be_bytes([*sign_high, *sign_low]) {
        0xc000 => Some("NaN"),
        0xd000 => Some("Infinity"),
        0xf000 => Some("-Infinity"),
        _ => None,
    };
    if let Some(special) = special {
        return Ok(special.into());
    }
    // SQLx retains numeric precision but discards PostgreSQL's display scale, including zero scale.
    let scale = i64::from(u16::from_be_bytes([*scale_high, *scale_low]));
    let number =
        <BigDecimal as Decode<Postgres>>::decode(raw).map_err(|cause| error(column, cause))?;
    Ok(number.with_scale(scale).to_plain_string().into())
}

pub(super) fn mysql_decimal(raw: MySqlValueRef<'_>, column: &str) -> AuthResult<FieldValue> {
    // DECIMAL payloads are strings in both protocols; SQLx's String type check excludes DECIMAL.
    <String as Decode<MySql>>::decode(raw)
        .map(FieldValue::from)
        .map_err(|cause| error(column, cause))
}

pub(super) fn postgres_date(raw: PgValueRef<'_>, column: &str) -> AuthResult<FieldValue> {
    let milliseconds = match raw.format() {
        PgValueFormat::Binary => {
            let bytes = raw.as_bytes().map_err(|cause| error(column, cause))?;
            let days = i32::from_be_bytes(bytes.try_into().map_err(|cause| error(column, cause))?);
            match days {
                i32::MAX => return Ok(f64::INFINITY.into()),
                i32::MIN => return Ok(f64::NEG_INFINITY.into()),
                _ => 946_684_800_000 + i64::from(days) * 86_400_000,
            }
        }
        PgValueFormat::Text => {
            let text = raw.as_str().map_err(|cause| error(column, cause))?;
            match text {
                "infinity" => return Ok(f64::INFINITY.into()),
                "-infinity" => return Ok(f64::NEG_INFINITY.into()),
                _ => {}
            }
            let (text, bc) = text
                .strip_suffix(" BC")
                .map_or((text, false), |text| (text, true));
            let mut parts = text.split('-');
            let mut component = || {
                parts
                    .next()
                    .ok_or_else(|| error(column, "incomplete PostgreSQL DATE"))?
                    .parse::<i64>()
                    .map_err(|cause| error(column, cause))
            };
            let year = component()?;
            let year = if bc { 1 - year } else { year };
            let month = component()?;
            let day = component()?;
            // Gregorian cycles retain PostgreSQL dates beyond Chrono's finite year range.
            let cycle = (year - 2000).div_euclid(400);
            let year = 2000 + (year - 2000).rem_euclid(400);
            better_auth_core::utils::date::normalize_components(year, month - 1, day, 0)
                .ok_or_else(|| error(column, "invalid PostgreSQL DATE"))?
                .timestamp_millis()
                + cycle * (146_097 * 86_400_000)
        }
    };
    if milliseconds.unsigned_abs() > 8_640_000_000_000_000 {
        return Ok(FieldDate::invalid().into());
    }
    let midnight = chrono::DateTime::from_timestamp_millis(milliseconds)
        .ok_or_else(|| error(column, "local DATE exceeds Chrono's supported range"))?;
    local_date(midnight.naive_utc(), column)
}

pub(super) fn mysql_date(raw: MySqlValueRef<'_>, column: &str) -> AuthResult<FieldValue> {
    let bytes = match <&[u8] as Decode<MySql>>::decode(raw) {
        Ok(bytes) => bytes,
        Err(cause) if cause.is::<UnexpectedNullError>() => return Ok(FieldValue::Null),
        Err(cause) => return Err(error(column, cause)),
    };
    let (year, month, day) = match bytes {
        [0] => (0, 0, 0),
        [4, low, high, month, day] => (
            i64::from(u16::from_le_bytes([*low, *high])),
            i64::from(*month),
            i64::from(*day),
        ),
        [_, _, _, _, b'-', _, _, b'-', _, _] => {
            let text = std::str::from_utf8(bytes).map_err(|cause| error(column, cause))?;
            let mut components = text.split('-');
            let mut next = || {
                components
                    .next()
                    .ok_or_else(|| error(column, "incomplete MySQL DATE"))?
                    .parse::<i64>()
                    .map_err(|cause| error(column, cause))
            };
            (next()?, next()?, next()?)
        }
        _ => return Err(error(column, "invalid MySQL DATE payload")),
    };
    // mysql2's query path uses Date(year, month - 1, day), including years 0–99 and zero components.
    let year = if year < 100 { year + 1900 } else { year };
    let midnight = better_auth_core::utils::date::normalize_components(year, month - 1, day, 0)
        .ok_or_else(|| error(column, "invalid MySQL DATE components"))?;
    local_date(midnight.naive_utc(), column)
}
