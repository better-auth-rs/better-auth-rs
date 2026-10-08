use super::*;
use better_auth_core::{FieldMap, FieldValue};

pub(super) fn algorithm(key: &better_auth_core::Jwk, fallback: FieldValue) -> FieldValue {
    let value = key.alg.field_value();
    if value.is_null() || value.is_undefined() {
        fallback
    } else {
        value
    }
}

pub(super) fn expires_before(key: &better_auth_core::Jwk, now: i64) -> AuthResult<bool> {
    let expiry = key.expires_at.field_value();
    Ok(expiry.is_truthy()
        && better_auth_core::query::field_compare(&expiry, &(now as f64).into())?
            == Some(std::cmp::Ordering::Less))
}

pub(super) fn latest(
    keys: Vec<better_auth_core::Jwk>,
    algorithm: Option<&str>,
    default_algorithm: &str,
) -> AuthResult<Option<better_auth_core::Jwk>> {
    let now = FieldValue::from(Utc::now().timestamp_millis() as f64);
    let mut candidates = Vec::new();
    for key in keys {
        if let Some(expected) = algorithm {
            let alg = key.alg.field_value();
            if !alg.strict_equals(&expected.into())
                && !((alg.is_null() || alg.is_undefined()) && default_algorithm == expected)
            {
                continue;
            }
        }
        let expiry = key.expires_at.field_value();
        if !expiry.is_truthy()
            || better_auth_core::query::field_compare(&expiry, &now)?
                == Some(std::cmp::Ordering::Greater)
        {
            candidates.push(key);
        }
    }
    let mut failure = None;
    candidates.sort_by(|left, right| {
        if failure.is_some() {
            return std::cmp::Ordering::Equal;
        }
        let compare = || -> AuthResult<_> {
            let right = date_millis(&right.created_at.field_value(), "b.createdAt")?;
            let left = date_millis(&left.created_at.field_value(), "a.createdAt")?;
            Ok((right - left)
                .partial_cmp(&0.0)
                .unwrap_or(std::cmp::Ordering::Equal))
        };
        match compare() {
            Ok(order) => order,
            Err(error) => {
                failure = Some(error);
                std::cmp::Ordering::Equal
            }
        }
    });
    if let Some(error) = failure {
        return Err(error);
    }
    Ok(candidates.into_iter().next())
}

pub(super) fn date_millis(value: &FieldValue, expression: &str) -> AuthResult<f64> {
    value
        .as_date()
        .map(|value| value.milliseconds())
        .ok_or_else(|| {
            AuthError::internal(if value.is_null() {
                "Cannot read properties of null (reading 'getTime')".into()
            } else if value.is_undefined() {
                "Cannot read properties of undefined (reading 'getTime')".into()
            } else {
                format!("{expression}.getTime is not a function")
            })
        })
}

pub(super) fn parse_json(value: &FieldValue) -> AuthResult<FieldValue> {
    let text = value.display_utf16()?;
    let mut source = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for unit in char::decode_utf16(text.as_utf16().iter().copied()) {
        match unit {
            Ok(character) => {
                source.push(character);
                if escaped {
                    escaped = false;
                } else if quoted && character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    quoted = !quoted;
                }
            }
            Err(error) => {
                // JSON source can contain an unpaired surrogate inside a quoted string.
                if !quoted || escaped {
                    return Err(AuthError::internal("Invalid JSON source"));
                }
                use std::fmt::Write as _;
                write!(source, "\\u{:04x}", error.unpaired_surrogate())
                    .map_err(|error| AuthError::internal(error.to_string()))?;
            }
        }
    }
    FieldValue::parse_json(&source)
}

pub(super) fn spread(fields: &mut FieldMap, value: FieldValue) {
    match value {
        FieldValue::Object(values) => fields.extend(
            values
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        ),
        FieldValue::Array(values) => fields.extend(
            values
                .iter()
                .enumerate()
                .map(|(index, value)| (index.to_string(), value.clone())),
        ),
        value => {
            if let Some(units) = better_auth_core::query::field_string_units(&value) {
                fields.extend(units.iter().enumerate().map(|(index, unit)| {
                    (
                        index.to_string(),
                        better_auth_core::Utf16String::from_units(vec![*unit]).into(),
                    )
                }));
            }
        }
    }
}

pub(super) fn import(value: FieldValue, alg: &FieldValue) -> AuthResult<(String, Jwk)> {
    let fields = value
        .as_object()
        .ok_or_else(|| AuthError::internal("JWK must be an object"))?;
    if fields
        .get("ext")
        .is_some_and(|value| !value.is_undefined() && !matches!(value, FieldValue::Bool(_)))
    {
        return Err(AuthError::internal(
            "\"ext\" (Extractable) Parameter must be a boolean",
        ));
    }
    if let Some(operations) = fields.get("key_ops").filter(|value| !value.is_undefined()) {
        let mut seen = std::collections::HashSet::new();
        if !operations.as_array().is_some_and(|values| {
            values
                .iter()
                .all(|value| value.as_str().is_some_and(|value| seen.insert(value)))
        }) {
            return Err(AuthError::internal(
                "\"key_ops\" (Key Operations) Parameter must be an array of unique strings",
            ));
        }
    }
    let kind = fields.get("kty").and_then(FieldValue::as_str);
    if kind != Some("oct") && !alg.is_truthy() {
        return Err(AuthError::internal(
            "\"alg\" argument is required when \"jwk.alg\" is not present",
        ));
    }
    if !matches!(kind, Some("RSA" | "EC" | "OKP" | "oct")) {
        return Err(AuthError::internal(
            "Unsupported \"kty\" (Key Type) Parameter value",
        ));
    }
    let algorithm = alg
        .as_str()
        .filter(|value| matches!(*value, "EdDSA" | "RS256" | "ES256" | "ES512" | "PS256"))
        .ok_or_else(|| {
            AuthError::internal("Invalid or unsupported JWK \"alg\" (Algorithm) Parameter value")
        })?;
    if algorithm == "EdDSA" && fields.get("crv").and_then(FieldValue::as_str) != Some("Ed25519") {
        return Err(AuthError::internal(
            "JWK \"crv\" (Curve) does not match the Ed25519 algorithm",
        ));
    }
    let mut fields = fields.clone();
    // WebCrypto consumes key material and key_ops; metadata does not constrain the imported key.
    for name in ["alg", "use", "kid"] {
        let _ = fields.remove(name);
    }
    let encoded = FieldValue::from(fields)
        .stringify()?
        .ok_or_else(|| AuthError::internal("JWK must be an object"))?;
    Ok((
        algorithm.to_owned(),
        Jwk::from_bytes(encoded).map_err(jose_error)?,
    ))
}
