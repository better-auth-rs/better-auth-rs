use super::*;
use serde_json::value::RawValue;

pub(crate) fn fixture() -> AuthResult<Json> {
    observation(serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/native-email-consumers-1.7.6.json"
    )))?)
}

fn observation(raw: &RawValue) -> AuthResult<Json> {
    match raw.get().as_bytes().first() {
        // The graph observer uses UTF-16 code units when Rust String cannot represent the source string.
        Some(b'"') => native_test_observation::NativeObservation::default()
            .observe(&FieldValue::parse_json(raw.get())?),
        Some(b'[') => serde_json::from_str::<Vec<&RawValue>>(raw.get())?
            .into_iter()
            .map(observation)
            .collect::<AuthResult<Vec<_>>>()
            .map(Into::into),
        Some(b'{') => serde_json::from_str::<indexmap::IndexMap<String, &RawValue>>(raw.get())?
            .into_iter()
            .map(|(key, value)| Ok((key, observation(value)?)))
            .collect::<AuthResult<serde_json::Map<_, _>>>()
            .map(Into::into),
        _ => Ok(serde_json::from_str(raw.get())?),
    }
}
