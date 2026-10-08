use std::cell::OnceCell;
use std::cmp::Ordering;
use std::sync::OnceLock;

use rust_icu_sys::{UColAttribute, UColAttributeValue};
use rust_icu_ucol::UCollator;
use rust_icu_ustring::UChar;

use crate::{AuthError, AuthResult, FieldValue};

#[derive(Default)]
pub(crate) struct Comparator {
    collator: OnceCell<Result<UCollator, String>>,
}

impl Comparator {
    pub(crate) fn compare(&self, left: &FieldValue, right: &FieldValue) -> AuthResult<Ordering> {
        Ok(match (left, right) {
            (
                FieldValue::Null | FieldValue::Undefined,
                FieldValue::Null | FieldValue::Undefined,
            ) => Ordering::Equal,
            (FieldValue::Null | FieldValue::Undefined, _) => Ordering::Less,
            (_, FieldValue::Null | FieldValue::Undefined) => Ordering::Greater,
            (FieldValue::Date(left), FieldValue::Date(right)) => (left.milliseconds()
                - right.milliseconds())
            .partial_cmp(&0.0)
            .unwrap_or(Ordering::Equal),
            (FieldValue::Number(left), FieldValue::Number(right)) => {
                (left - right).partial_cmp(&0.0).unwrap_or(Ordering::Equal)
            }
            (FieldValue::Bool(left), FieldValue::Bool(right)) => left.cmp(right),
            _ => {
                let left = left.display_utf16()?;
                let right = right.display_utf16()?;
                let collator = self
                    .collator
                    .get_or_init(open_collator)
                    .as_ref()
                    .map_err(|error| AuthError::internal(error.clone()))?;
                // ICU takes signed 32-bit lengths. The wrapper asserts this precondition.
                for value in [&left, &right] {
                    let _ = i32::try_from(value.as_utf16().len()).map_err(|_| {
                        AuthError::internal("Memory sort string exceeds the ICU length limit")
                    })?;
                }
                collator.strcoll(
                    &UChar::from(left.as_utf16().to_vec()),
                    &UChar::from(right.as_utf16().to_vec()),
                )
            }
        })
    }
}

fn open_collator() -> Result<UCollator, String> {
    let locale = default_locale()?;
    let collator = UCollator::try_from(locale).map_err(|error| {
        format!("Cannot initialize Memory sort collation for {locale}: {error}")
    })?;
    for (attribute, value) in [
        (
            UColAttribute::UCOL_STRENGTH,
            UColAttributeValue::UCOL_TERTIARY,
        ),
        (UColAttribute::UCOL_CASE_LEVEL, UColAttributeValue::UCOL_OFF),
        (UColAttribute::UCOL_CASE_FIRST, UColAttributeValue::UCOL_OFF),
        (
            UColAttribute::UCOL_NUMERIC_COLLATION,
            UColAttributeValue::UCOL_OFF,
        ),
        (
            UColAttribute::UCOL_NORMALIZATION_MODE,
            UColAttributeValue::UCOL_ON,
        ),
    ] {
        collator.set_attribute(attribute, value).map_err(|error| {
            format!("Cannot configure Memory sort collation for {locale}: {error}")
        })?;
    }
    // Intl.Collator without options retains the locale's punctuation handling.
    Ok(collator)
}

fn default_locale() -> Result<&'static str, String> {
    static LOCALE: OnceLock<Result<String, String>> = OnceLock::new();
    LOCALE
        .get_or_init(platform_locale)
        .as_deref()
        .map_err(Clone::clone)
}

#[cfg(unix)]
fn platform_locale() -> Result<String, String> {
    // JSCOnly reads the current LC_CTYPE locale. Environment variables do not select that locale.
    // SAFETY: A null second argument queries libc without changing the process locale.
    let locale = unsafe { libc::setlocale(libc::LC_CTYPE, std::ptr::null()) };
    let bytes = if locale.is_null() {
        &[][..]
    } else {
        // SAFETY: setlocale returns a libc-owned, NUL-terminated locale name for this query.
        unsafe { std::ffi::CStr::from_ptr(locale) }.to_bytes()
    };
    let name = bytes
        .split(|byte| matches!(byte, b'.' | b'@'))
        .next()
        .unwrap_or_default();
    if name.is_empty() || name.eq_ignore_ascii_case(b"C") || name.eq_ignore_ascii_case(b"POSIX") {
        // JSC maps the C/POSIX locale and an absent locale name to en-US.
        return Ok("en-US".into());
    }
    Ok(name
        .iter()
        .map(|byte| {
            if *byte == b'_' {
                '-'
            } else {
                char::from(*byte)
            }
        })
        .collect())
}

#[cfg(windows)]
fn platform_locale() -> Result<String, String> {
    use windows_sys::Win32::Globalization::{
        GetLocaleInfoW, GetUserDefaultUILanguage, LOCALE_SISO639LANGNAME, LOCALE_SISO3166CTRYNAME,
    };

    fn locale_info(kind: u32, fallback: &str) -> Result<String, String> {
        // SAFETY: GetUserDefaultUILanguage takes no arguments and returns the user's UI language ID.
        let language = unsafe { GetUserDefaultUILanguage() };
        // SAFETY: A null buffer and zero length query the required UTF-16 buffer length.
        let length = unsafe { GetLocaleInfoW(u32::from(language), kind, std::ptr::null_mut(), 0) };
        if length == 0 {
            // JSC uses the supplied language/country default when Windows cannot resolve the value.
            return Ok(fallback.into());
        }
        let mut buffer = vec![0; length as usize];
        // SAFETY: The buffer contains the number of UTF-16 units requested by GetLocaleInfoW.
        let written =
            unsafe { GetLocaleInfoW(u32::from(language), kind, buffer.as_mut_ptr(), length) };
        if written == 0 {
            return Ok(fallback.into());
        }
        buffer.truncate(written.saturating_sub(1) as usize);
        String::from_utf16(&buffer).map_err(|error| format!("Invalid Windows UI locale: {error}"))
    }

    let language = locale_info(LOCALE_SISO639LANGNAME, "en")?;
    let country = locale_info(LOCALE_SISO3166CTRYNAME, "")?;
    Ok(if country.is_empty() {
        language
    } else {
        format!("{language}-{country}")
    })
}

#[cfg(not(any(unix, windows)))]
fn platform_locale() -> Result<String, String> {
    Err("Memory sort collation requires a Unix or Windows locale provider".into())
}

pub(crate) fn sort<T>(
    values: &mut [T],
    descending: bool,
    value: impl Fn(&T) -> AuthResult<FieldValue>,
) -> AuthResult<()> {
    let comparator = Comparator::default();
    // JSC uses binary insertion; mixed values need not form a total order, so comparison order matters.
    // ponytail: O(n²) moves; JSC's Powersort merging for longer mixed-value runs still needs pairing.
    #[expect(
        clippy::indexing_slicing,
        reason = "The outer range bounds index, and the binary search keeps left and middle within 0..=index"
    )]
    for index in 1..values.len() {
        let mut left = 0;
        let mut right = index;
        while left < right {
            let middle = left + (right - left) / 2;
            let order = comparator.compare(&value(&values[index])?, &value(&values[middle])?)?;
            let order = if descending { order.reverse() } else { order };
            if order.is_lt() {
                right = middle;
            } else {
                left = middle + 1;
            }
        }
        values[left..=index].rotate_right(1);
    }
    Ok(())
}
