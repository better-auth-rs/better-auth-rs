use super::*;
use base64::{
    Engine as _, alphabet,
    engine::{
        DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig, general_purpose::URL_SAFE_NO_PAD,
    },
};
use hmac::{Hmac, Mac};
use jsonwebtoken::errors::{Error as JwtError, ErrorKind};
use sha2::Sha256;

pub(super) fn sign(
    payload: &Map<String, Value>,
    header: FieldMap,
    signer: &dyn JwsSigner,
) -> AuthResult<String> {
    let serialized = FieldValue::from(header)
        .stringify()?
        .ok_or_else(|| AuthError::internal("JOSE Header is not valid JSON"))?;
    let header = serde_json::from_str(&serialized)?;
    validate_header(&header, true)?;
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serialized),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload)?)
    );
    let signature = signer.sign(input.as_bytes()).map_err(jose_error)?;
    Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
}

pub(super) fn header(token: &str) -> Option<verification::Header> {
    if token.split('.').count() != 3 {
        return None;
    }
    let bytes = decode(token.split('.').next()?)?;
    let text = std::str::from_utf8(&bytes).ok()?;
    serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(text)).ok()
}

pub(super) fn verify(
    token: &str,
    header: &verification::Header,
    algorithm: &str,
    verify_signature: impl FnOnce(&[u8], &[u8]) -> bool,
) -> AuthResult<Vec<u8>> {
    validate_header(header, false).map_err(|_| JwtError::from(ErrorKind::InvalidToken))?;
    if header.field("alg")?.as_str() != Some(algorithm) {
        return Err(JwtError::from(ErrorKind::InvalidAlgorithm).into());
    }
    let (input, signature) = token
        .rsplit_once('.')
        .ok_or_else(|| JwtError::from(ErrorKind::InvalidToken))?;
    let (_, payload) = input
        .split_once('.')
        .ok_or_else(|| JwtError::from(ErrorKind::InvalidToken))?;
    if !input.is_ascii() {
        return Err(JwtError::from(ErrorKind::InvalidToken).into());
    }
    let signature = decode(signature).ok_or_else(|| JwtError::from(ErrorKind::InvalidToken))?;
    if !verify_signature(input.as_bytes(), &signature) {
        return Err(JwtError::from(ErrorKind::InvalidSignature).into());
    }
    decode(payload).ok_or_else(|| JwtError::from(ErrorKind::InvalidToken).into())
}

/// Verify HS256 integrity and JOSE headers without parsing or validating payload claims.
pub(crate) fn verify_hs256_raw(token: &str, secret: &str) -> AuthResult<Vec<u8>> {
    let protected = header(token).ok_or_else(|| JwtError::from(ErrorKind::InvalidToken))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| JwtError::from(ErrorKind::InvalidKeyFormat))?;
    verify(token, &protected, "HS256", |input, signature| {
        mac.update(input);
        mac.verify_slice(signature).is_ok()
    })
}

fn decode(value: &str) -> Option<Vec<u8>> {
    let value: String = value
        .chars()
        .filter(|value| !matches!(value, '\t' | '\n' | '\u{c}' | '\r' | ' '))
        .collect();
    let engine = GeneralPurpose::new(
        &alphabet::URL_SAFE,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    engine.decode(value).ok()
}

fn validate_header(header: &verification::Header, signing: bool) -> AuthResult<()> {
    let critical = header.field("crit")?;
    if !critical.is_undefined() {
        let critical = critical.as_array().filter(|values| !values.is_empty()).ok_or_else(|| AuthError::internal("\"crit\" (Critical) Header Parameter MUST be an array of non-empty strings when present"))?;
        if signing
            && critical.iter().enumerate().any(|(index, value)| {
                critical
                    .iter()
                    .take(index)
                    .any(|previous| previous.same_value_zero(value))
            })
        {
            return Err(AuthError::internal(
                "\"crit\" (Critical) Header Parameter MUST NOT contain duplicate values",
            ));
        }
        for value in critical.iter() {
            let name = value.as_str().filter(|value| !value.is_empty()).ok_or_else(|| AuthError::internal("\"crit\" (Critical) Header Parameter MUST be an array of non-empty strings when present"))?;
            if name != "b64" {
                return Err(AuthError::internal(format!(
                    "Extension Header Parameter \"{name}\" is not recognized"
                )));
            }
            let encoded = header.field(name)?;
            if encoded.is_undefined() {
                return Err(AuthError::internal(format!(
                    "Extension Header Parameter \"{name}\" is missing"
                )));
            }
            match encoded.as_bool() {
                Some(true) => {}
                Some(false) => {
                    return Err(AuthError::internal("JWTs MUST NOT use unencoded payload"));
                }
                None => {
                    return Err(AuthError::internal(
                        "The \"b64\" (base64url-encode payload) Header Parameter must be a boolean",
                    ));
                }
            }
        }
    }
    if header.field("alg")?.as_str().is_none_or(str::is_empty) {
        return Err(AuthError::internal(
            "JWS \"alg\" (Algorithm) Header Parameter missing or invalid",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed(header: &str, payload: &[u8], secret: &str) -> AuthResult<String> {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload)
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
            .map_err(|_| JwtError::from(ErrorKind::InvalidKeyFormat))?;
        mac.update(input.as_bytes());
        Ok(format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        ))
    }

    #[test]
    fn hs256_raw_preserves_payload_and_verification_error_classes() -> AuthResult<()> {
        let secret = "short";
        let payload = br#"{"exp":0,"exp":1e400,"ignored":"\ud800"}"#;
        let token = signed(r#"{"alg":"HS256","ignored":"\ud800"}"#, payload, secret)?;
        assert_eq!(verify_hs256_raw(&token, secret)?.as_slice(), payload);
        assert!(matches!(
            verify_hs256_raw(&token, "wrong"),
            Err(AuthError::Jwt(error)) if error.kind() == &ErrorKind::InvalidSignature
        ));
        let opaque = signed(r#"{"alg":"HS256"}"#, b"not JSON", secret)?;
        assert_eq!(verify_hs256_raw(&opaque, secret)?.as_slice(), b"not JSON");
        for (header, expected) in [
            (r#"{"alg":"HS384"}"#, ErrorKind::InvalidAlgorithm),
            (
                r#"{"alg":"HS256","crit":["unknown"],"unknown":true}"#,
                ErrorKind::InvalidToken,
            ),
            (
                r#"{"alg":"HS256","crit":["b64"],"b64":false}"#,
                ErrorKind::InvalidToken,
            ),
        ] {
            let token = signed(header, payload, secret)?;
            assert!(matches!(
                verify_hs256_raw(&token, secret),
                Err(AuthError::Jwt(error)) if error.kind() == &expected
            ));
        }
        assert!(matches!(
            verify_hs256_raw("invalid compact JWT", secret),
            Err(AuthError::Jwt(error)) if error.kind() == &ErrorKind::InvalidToken
        ));
        Ok(())
    }
}
