//! Convert and serialize auth timestamps with JavaScript's millisecond precision.

use chrono::{DateTime, Local, SecondsFormat, TimeZone, Utc};
use serde::{Serialize, Serializer};
use std::sync::OnceLock;

use crate::FieldDate;

/// Convert JavaScript milliseconds using TimeClip within Chrono's supported date range.
pub fn from_milliseconds(millis: f64) -> Option<DateTime<Utc>> {
    if !millis.is_finite() || millis.abs() > 8_640_000_000_000_000.0 {
        return None;
    }
    DateTime::from_timestamp_millis(millis.trunc() as i64)
}

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

/// Parse adapter date strings within Chrono's supported range.
pub fn parse_adapter_date(text: &str) -> Option<DateTime<Utc>> {
    from_milliseconds(parse_date_constructor(text)?.milliseconds())
}

/// Parse standard ECMAScript Date strings and previously supported legacy forms.
/// UTC and explicit offsets retain the complete TimeClip range.
/// Local timezone gaps and local years outside Chrono's range remain unsupported.
pub fn parse_date_constructor(text: &str) -> Option<FieldDate> {
    parse_in_timezone(text, &Local)
}

fn parse_in_timezone(text: &str, timezone: &impl TimeZone) -> Option<FieldDate> {
    if let Some(parts) = constructor_pattern().captures(text) {
        return parse_standard_date(&parts, timezone);
    }
    // Keep previously accepted legacy forms separate from the standard constructor grammar.
    crate::utils::json::parse_json_date(text)
        .or_else(|| {
            DateTime::parse_from_rfc3339(text)
                .ok()
                .map(|date| date.with_timezone(&Utc))
        })
        .or_else(|| {
            chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d")
                .ok()?
                .and_hms_opt(0, 0, 0)
                .map(|date| date.and_utc())
        })
        .map(FieldDate::from)
}

#[expect(
    clippy::expect_used,
    reason = "The expression is a constant ECMAScript Date Time String Format grammar"
)]
fn constructor_pattern() -> &'static regex::Regex {
    static PATTERN: OnceLock<regex::Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        regex::Regex::new(
            r"^([0-9]{4}|[+-][0-9]{6})(?:-([0-9]{2})(?:-([0-9]{2}))?)?(?:T([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:\.([0-9]+))?)?(Z|[+-][0-9]{2}:[0-9]{2})?)?$",
        )
        .expect("Date constructor grammar")
    })
}

fn parse_standard_date(parts: &regex::Captures<'_>, timezone: &impl TimeZone) -> Option<FieldDate> {
    let number = |index, default| {
        parts
            .get(index)
            .map_or(Some(default), |part| part.as_str().parse::<i64>().ok())
    };
    if parts.get(1)?.as_str() == "-000000" {
        return None;
    }
    let year = number(1, 0)?;
    let month = number(2, 1)?;
    let day = number(3, 1)?;
    let hour = number(4, 0)?;
    let minute = number(5, 0)?;
    let second = number(6, 0)?;
    let fraction = parts.get(7).map_or("", |part| part.as_str());
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 24
        || minute > 59
        || second > 59
        || (hour == 24
            && (minute != 0 || second != 0 || fraction.bytes().any(|digit| digit != b'0')))
    {
        return None;
    }
    let millis = fraction
        .bytes()
        .chain(std::iter::repeat(b'0'))
        .take(3)
        .fold(0_i64, |value, digit| value * 10 + i64::from(digit - b'0'));
    let daytime = (hour * 60 + minute) * 60_000 + second * 1_000 + millis;
    let zone = parts.get(8).map(|part| part.as_str());
    let milliseconds = if parts.get(4).is_some() && zone.is_none() {
        let local = normalize_components(year, month - 1, day, daytime)?.naive_utc();
        timezone
            .from_local_datetime(&local)
            .earliest()?
            .timestamp_millis()
    } else {
        let offset = match zone {
            Some("Z") | None => 0,
            Some(zone) => {
                let hours = zone.get(1..3)?.parse::<i64>().ok()?;
                let minutes = zone.get(4..6)?.parse::<i64>().ok()?;
                if hours > 23 || minutes > 59 {
                    return None;
                }
                (hours * 60 + minutes) * 60_000 * if zone.starts_with('+') { 1 } else { -1 }
            }
        };
        // Gregorian cycles keep expanded years within Chrono's range until the final TimeClip.
        let cycle = (year - 2000).div_euclid(400);
        let representative_year = 2000 + (year - 2000).rem_euclid(400);
        normalize_components(representative_year, month - 1, day, daytime)?.timestamp_millis()
            + cycle * (146_097 * 86_400_000)
            - offset
    };
    let date = FieldDate::from_milliseconds(milliseconds as f64);
    date.milliseconds().is_finite().then_some(date)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_defaults_offsets_and_calendar_overflow() -> Result<(), Box<dyn std::error::Error>>
    {
        for (input, complete) in [
            ("2100", "2100-01-01T00:00:00Z"),
            ("2100-01", "2100-01-01T00:00:00Z"),
            ("2100-01-01", "2100-01-01T00:00:00Z"),
            ("2100T00:00Z", "2100-01-01T00:00:00Z"),
            ("2100-01T00:00Z", "2100-01-01T00:00:00Z"),
            ("2100-01-01T00:00Z", "2100-01-01T00:00:00Z"),
            ("2100-01-01T00:00+08:00", "2099-12-31T16:00:00Z"),
            ("2100-01-01T00:00-03:30", "2100-01-01T03:30:00Z"),
            ("2100-01-01T23:59:00.1+23:59", "2100-01-01T00:00:00.100Z"),
            ("2100-12-31T24:00:00.0000Z", "2101-01-01T00:00:00Z"),
            ("2100-02-31T00:00Z", "2100-03-03T00:00:00Z"),
            ("2000-02-29T24:00Z", "2000-03-01T00:00:00Z"),
            ("2100-01-01T00:00:00.123456Z", "2100-01-01T00:00:00.123Z"),
            ("0000", "0000-01-01T00:00:00Z"),
            ("+000000", "0000-01-01T00:00:00Z"),
        ] {
            let expected = DateTime::parse_from_rfc3339(complete)?.timestamp_millis() as f64;
            assert_eq!(
                parse_date_constructor(input).map(|date| date.milliseconds()),
                Some(expected),
                "{input}"
            );
        }
        Ok(())
    }

    #[test]
    fn constructor_rejects_invalid_standard_components() {
        for text in [
            "2100-00",
            "2100-13",
            "2100-01-00",
            "2100-01-32",
            "-000000",
            "2100-01-01T24:01Z",
            "2100-01-01T24:00:01Z",
            "2100-01-01T24:00:00.0001Z",
            "2100-01-01T25:00Z",
            "2100-01-01T00:60Z",
            "2100-01-01T00:00:60Z",
            "2100-01-01T00:00+24:00",
            "2100-01-01T00:00-00:60",
            "2100-01-01T00:00:00.Z",
        ] {
            assert!(parse_date_constructor(text).is_none(), "{text}");
        }
    }

    #[test]
    fn expanded_years_clip_after_the_timezone_offset() {
        for (text, expected) in [
            ("-000001-01-01T00:00:00Z", -62_198_755_200_000.0),
            ("+275760-09-13T00:00:00.000Z", 8_640_000_000_000_000.0),
            ("-271821-04-20T00:00:00.000Z", -8_640_000_000_000_000.0),
            ("+275760-09-13T00:01:00.000+00:01", 8_640_000_000_000_000.0),
            ("-271821-04-19T23:59:00.000-00:01", -8_640_000_000_000_000.0),
        ] {
            assert_eq!(
                parse_date_constructor(text).map(|date| date.milliseconds()),
                Some(expected),
                "{text}"
            );
        }
        for text in [
            "+275760-09-13T00:00:00.001Z",
            "-271821-04-19T23:59:59.999Z",
            "+275760-09-13T00:00:00.000-00:01",
            "-271821-04-20T00:00:00.000+00:01",
        ] {
            assert!(parse_date_constructor(text).is_none(), "{text}");
        }
    }

    #[test]
    fn absent_zone_uses_local_time_only_for_datetime_forms()
    -> Result<(), Box<dyn std::error::Error>> {
        let zone = chrono::FixedOffset::east_opt(8 * 3600).ok_or("invalid offset")?;
        for (text, expected) in [
            ("1970", 0.0),
            ("1970-01", 0.0),
            ("1970-01-01", 0.0),
            ("1970T00:00", -28_800_000.0),
            ("1970-01T00:00", -28_800_000.0),
            ("1970-01-01T00:00:00", -28_800_000.0),
            ("1970-01-01T24:00", 57_600_000.0),
        ] {
            assert_eq!(
                parse_in_timezone(text, &zone).map(|date| date.milliseconds()),
                Some(expected),
                "{text}"
            );
        }
        Ok(())
    }

    #[test]
    fn constructor_does_not_broaden_json_revivers() -> Result<(), Box<dyn std::error::Error>> {
        let input = r#"{"date":"2100-01-01T00:00Z"}"#;
        let expected = crate::FieldValue::parse_json(input)?;
        assert!(parse_date_constructor("2100-01-01T00:00Z").is_some());
        assert_eq!(
            crate::utils::json::safe_parse_field(&input.into()),
            expected
        );
        assert_eq!(
            crate::utils::json::parse_client_json(input.into())?,
            expected
        );
        assert!(crate::utils::json::parse_json_date("2100-01-01T00:00Z").is_none());
        Ok(())
    }

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
