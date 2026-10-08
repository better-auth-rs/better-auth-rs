use super::*;
use base64::{
    Engine as _, alphabet,
    engine::{
        DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig, general_purpose::URL_SAFE_NO_PAD,
    },
};
use josekit::jws::JwsVerifier;

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
    verifier: &dyn JwsVerifier,
) -> Option<Vec<u8>> {
    validate_header(header, false).ok()?;
    if header.field("alg").ok()?.as_str() != Some(verifier.algorithm().name()) {
        return None;
    }
    let (input, signature) = token.rsplit_once('.')?;
    let (_, payload) = input.split_once('.')?;
    if !input.is_ascii() {
        return None;
    }
    verifier
        .verify(input.as_bytes(), &decode(signature)?)
        .ok()?;
    decode(payload)
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
