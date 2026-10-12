#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]

use super::*;

pub(super) use crate::plugins::test_helpers::native_observation::assert_replay;

// Bun locations and stack text remain in the fixture, outside this semantic error boundary.
const HOST_ERROR_KEYS: [&str; 6] = [
    "originalLine",
    "originalColumn",
    "line",
    "column",
    "sourceURL",
    "stack",
];

pub(super) fn revive(value: &Json) -> AuthResult<FieldValue> {
    Ok(match value {
        Json::Object(fields) if fields.get("type").and_then(Json::as_str) == Some("undefined") => {
            assert_eq!(fields.len(), 1);
            FieldValue::Undefined
        }
        Json::Object(fields) if fields.get("type").and_then(Json::as_str) == Some("date") => {
            assert_eq!(fields.len(), 2);
            let date = fields["value"]
                .as_str()
                .unwrap()
                .parse::<chrono::DateTime<chrono::Utc>>()
                .map_err(|error| AuthError::internal(format!("Invalid frozen date: {error}")))?;
            FieldDate::from(date).into()
        }
        Json::Object(fields) => fields
            .iter()
            .map(|(name, value)| Ok((name.clone(), revive(value)?)))
            .collect::<AuthResult<FieldMap>>()?
            .into(),
        Json::Array(values) => values
            .iter()
            .map(revive)
            .collect::<AuthResult<Vec<_>>>()?
            .into(),
        value => FieldValue::from_json(value.clone())?,
    })
}

fn bytes(value: &[u8]) -> Json {
    value
        .iter()
        .enumerate()
        .map(|(index, byte)| (index.to_string(), (*byte).into()))
        .collect::<serde_json::Map<_, _>>()
        .into()
}

// Read every typed callback field. Vec bytes, Option absence, and struct declaration order
// are Rust API representations; this comparison does not claim JavaScript reflection parity.
pub(super) fn registration(
    verification: &PasskeyRegistrationVerification,
    client_data: &Json,
) -> Json {
    let info = &verification.registration_info;
    json!({
        "verification": {
            "verified": verification.verified,
            "registrationInfo": {
                "fmt":info.fmt,
                "aaguid":info.aaguid,
                "credentialType":info.credential_type,
                "credential": {
                    "id":info.credential.id,
                    "publicKey":bytes(&info.credential.public_key),
                    "counter":info.credential.counter,
                    "transports":info.credential.transports,
                },
                "attestationObject":bytes(&info.attestation_object),
                "userVerified":info.user_verified,
                "credentialDeviceType":info.credential_device_type,
                "credentialBackedUp":info.credential_backed_up,
                "origin":info.origin,
                "rpID":info.rp_id,
                "authenticatorExtensionResults":info.authenticator_extension_results.clone().unwrap_or_else(|| json!({"type":"undefined"})),
            },
        },
        "clientData":client_data,
    })
}

pub(super) fn authentication(
    verification: &PasskeyAuthenticationVerification,
    client_data: &Json,
) -> AuthResult<Json> {
    let info = &verification.authentication_info;
    Ok(json!({
        "verification": {
            "verified":verification.verified,
            "authenticationInfo": {
                "newCounter":info.new_counter,
                "credentialID":NativeObservation::default().observe(&info.credential_id.field_value())?,
                "userVerified":info.user_verified,
                "credentialDeviceType":info.credential_device_type,
                "credentialBackedUp":info.credential_backed_up,
                "authenticatorExtensionResults":info.authenticator_extension_results.clone().unwrap_or_else(|| json!({"type":"undefined"})),
                "origin":info.origin,
                "rpID":info.rp_id,
            },
        },
        "clientData":client_data,
    }))
}

pub(super) fn logged_error(error: &AuthError) -> AuthResult<FieldValue> {
    if let Some(value) = error.raw_value() {
        return Ok(value.clone());
    }
    match error {
        AuthError::Internal(message) => AuthError::Internal(message.clone()),
        AuthError::TypeError(message) => AuthError::TypeError(message.clone()),
        AuthError::RangeError(message) => AuthError::RangeError(message.clone()),
        _ => {
            return Err(AuthError::internal(
                "Unexpected typed error at the Passkey logger boundary",
            ));
        }
    }
    .into_thrown_value()
}

pub(super) fn error(value: &FieldValue) -> AuthResult<Json> {
    let mut observer = NativeObservation::default();
    let name = value.model_property("name")?;
    if name.is_undefined() {
        return Ok(json!({"thrown":observer.observe(value)?}));
    }
    let object = value.as_object().unwrap();
    let mut properties = FieldMap::new();
    for key in object.own_keys()? {
        if !["stack", "name", "message"].contains(&key.as_str()) {
            let _ = properties.insert(key.clone(), object.get(&key)?.unwrap_or_default());
        }
    }
    Ok(json!({
        "name":observer.observe(&name)?,
        "message":observer.observe(&value.model_property("message")?)?,
        "properties":observer.observe(&properties.into())?,
    }))
}

pub(super) fn outcome(caught: &AuthError, state: &State) -> AuthResult<Json> {
    let value = caught
        .raw_value()
        .ok_or_else(|| AuthError::internal("Native dispatch must retain the thrown value"))?;
    let object = value.as_object().unwrap();
    let body = value.model_property("body")?;
    let headers = caught
        .captured_headers_value()
        .as_ref()
        .map(better_auth_core::Headers::from_field_value)
        .transpose()?;
    Ok(json!({
        "returned":false,
        "error":error(value)?,
        "coreAPIError":caught.is_api_error_instance(ApiErrorClass::BetterAuth),
        "endpointAPIError":caught.is_api_error_instance(ApiErrorClass::BetterCall),
        "syntaxError":value.model_property("name")?.strict_equals(&"SyntaxError".into()),
        "ownKeys":object.own_keys()?,
        "enumerableKeys":object.enumerable_keys()?,
        "bodyKeys":if body.is_undefined() { None } else { Some(body.as_object().unwrap().enumerable_keys()?) },
        "sameOriginal":value.strict_equals(&state.original),
        "sameOriginalBody":body.strict_equals(&state.original_body),
        "headers":headers.as_ref().map(|headers| headers.iter().collect::<Vec<_>>()),
        "cookies":headers.as_ref().map(|headers| headers.get_all("set-cookie").collect::<Vec<_>>()).unwrap_or_default(),
    }))
}

fn source_error(value: &mut Json) {
    if let Some(properties) = value.get_mut("properties") {
        properties
            .as_object_mut()
            .unwrap()
            .retain(|key, _| !HOST_ERROR_KEYS.contains(&key.as_str()));
    }
}

pub(super) fn source_outcome(value: &Json) -> Json {
    let mut output = value.clone();
    source_error(&mut output["error"]);
    let keys = output["ownKeys"].as_array_mut().unwrap();
    let symbol = json!({"type":"symbol","value":"Symbol(better-call:api-error-headers)"});
    let symbols = keys
        .iter()
        .filter(|key| !key.is_string())
        .collect::<Vec<_>>();
    if value["endpointAPIError"] == true {
        assert_eq!(symbols, vec![&symbol]);
    } else {
        assert!(symbols.is_empty());
    }
    // Captured headers are compared above; Rust does not expose the JavaScript symbol as an own key.
    keys.retain(|key| {
        key.as_str()
            .is_some_and(|key| !HOST_ERROR_KEYS.contains(&key))
    });
    output
}

pub(super) fn source_logs(value: &Json) -> Json {
    let mut output = value.clone();
    for entry in output.as_array_mut().unwrap() {
        for argument in entry["arguments"].as_array_mut().unwrap() {
            source_error(argument);
        }
    }
    output
}
