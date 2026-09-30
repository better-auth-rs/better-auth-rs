//! Serialize auth timestamps with JavaScript's millisecond precision.

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Serialize, Serializer};

/// Serialize an auth timestamp as an ISO 8601 string with three fractional digits.
pub fn serialize<S: Serializer>(value: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&value.to_rfc3339_opts(SecondsFormat::Millis, true))
}

/// Serialize an optional auth timestamp, preserving absent values as null.
pub fn serialize_option<S: Serializer>(
    value: &Option<DateTime<Utc>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    value
        .map(|date| date.to_rfc3339_opts(SecondsFormat::Millis, true))
        .serialize(serializer)
}

/// Normalize overflowing calendar components without JavaScript's special handling of years 0–99.
/// `month` is zero-based; `milliseconds` is the offset from midnight on the selected day.
pub fn normalize_components(
    year: i64,
    month: i64,
    day: i64,
    milliseconds: i64,
) -> Option<DateTime<Utc>> {
    let year = year.checked_add(month.div_euclid(12))?;
    let month = month.rem_euclid(12) + 1;
    let start =
        chrono::NaiveDate::from_ymd_opt(i32::try_from(year).ok()?, u32::try_from(month).ok()?, 1)?
            .and_hms_opt(0, 0, 0)?;
    let milliseconds = day
        .checked_sub(1)?
        .checked_mul(86_400_000)?
        .checked_add(milliseconds)?;
    start
        .checked_add_signed(chrono::Duration::try_milliseconds(milliseconds)?)
        .map(|date| date.and_utc())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct Dates {
        #[serde(serialize_with = "serialize")]
        required: DateTime<Utc>,
        #[serde(serialize_with = "serialize_option")]
        optional: Option<DateTime<Utc>>,
    }

    #[test]
    fn truncates_submillisecond_precision_without_changing_the_second()
    -> Result<(), Box<dyn std::error::Error>> {
        let date =
            DateTime::parse_from_rfc3339("2026-09-30T10:32:24.133279123Z")?.with_timezone(&Utc);
        let mut dates = Dates {
            required: date,
            optional: Some(date),
        };
        let json = serde_json::to_value(&dates)?;
        assert_eq!(json["required"], "2026-09-30T10:32:24.133Z");
        assert_eq!(json["optional"], json["required"]);
        dates.optional = None;
        assert_eq!(
            serde_json::to_value(dates)?["optional"],
            serde_json::Value::Null
        );
        Ok(())
    }
}
