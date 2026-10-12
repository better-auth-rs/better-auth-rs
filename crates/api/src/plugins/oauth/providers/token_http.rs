//! Convert native token values only at URL, form, and HTTP header boundaries.

use better_auth_core::{AuthError, AuthResult, FieldValue};
use reqwest::header::HeaderValue;

pub(in crate::plugins::oauth) fn form_string(value: &FieldValue) -> AuthResult<String> {
    Ok(String::from_utf16_lossy(value.display_utf16()?.as_utf16()))
}

pub(in crate::plugins::oauth) fn authorization(
    scheme: &str,
    token: &FieldValue,
) -> AuthResult<HeaderValue> {
    let token = token.display_utf16()?;
    let mut bytes = scheme
        .encode_utf16()
        .chain([u16::from(b' ')])
        .chain(token.as_utf16().iter().copied())
        .map(|unit| {
            u8::try_from(unit).map_err(|_| {
                AuthError::type_error("Cannot convert authorization header to a ByteString")
            })
        })
        .collect::<AuthResult<Vec<_>>>()?;
    while matches!(bytes.last(), Some(b' ' | b'\t')) {
        let _ = bytes.pop();
    }
    HeaderValue::from_bytes(&bytes)
        .map_err(|error| AuthError::type_error(format!("Invalid authorization header: {error}")))
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]
mod tests {
    use super::*;
    use better_auth_core::{FieldMap, Utf16String};

    #[test]
    fn native_tokens_convert_at_the_selected_web_boundary() -> AuthResult<()> {
        for (value, expected) in [
            (FieldValue::Undefined, "Bearer undefined"),
            (FieldValue::Null, "Bearer null"),
            (FieldValue::Number(7.0), "Bearer 7"),
            (FieldValue::Number(f64::NAN), "Bearer NaN"),
            (FieldMap::new().into(), "Bearer [object Object]"),
            (
                vec!["first".into(), FieldValue::Null, 7.0.into()].into(),
                "Bearer first,,7",
            ),
        ] {
            assert_eq!(
                authorization("Bearer", &value)?.as_bytes(),
                expected.as_bytes()
            );
        }
        let latin = Utf16String::from_units(vec![0xff]);
        assert_eq!(
            authorization("Bearer", &latin.clone().into())?.as_bytes(),
            b"Bearer \xff"
        );
        assert_eq!(form_string(&latin.into())?, "\u{ff}");
        let surrogate = FieldValue::from(Utf16String::from_units(vec![0xd800]));
        assert!(authorization("Bearer", &surrogate).is_err());
        assert_eq!(form_string(&surrogate)?, "\u{fffd}");
        assert!(authorization("Bearer", &"line\nbreak".into()).is_err());
        Ok(())
    }
}
