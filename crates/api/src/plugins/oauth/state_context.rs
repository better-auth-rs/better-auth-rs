use better_auth_core::{AuthError, AuthRequest, AuthResult, FieldMap, FieldValue};

use super::state::OAuthStatePayload;

const OAUTH_STATE_CONTEXT: &str = "oauth.state";

/// Read the state generated or accepted during the current OAuth request.
/// Additional top-level fields are client input. Only `serverContext` contains trusted server data.
/// Unpaired UTF-16 object keys return an error because `FieldMap` requires UTF-8 keys.
/// State persistence and callback parsing retain those keys without calling this accessor.
pub fn get_oauth_state(req: &AuthRequest) -> AuthResult<Option<FieldValue>> {
    let Some(snapshot) = req.server_context(OAUTH_STATE_CONTEXT)? else {
        return Ok(None);
    };
    let snapshot = snapshot
        .as_object()
        .ok_or_else(|| AuthError::internal("Invalid request OAuth state snapshot"))?;
    let fields = snapshot
        .get("fields")
        .and_then(FieldValue::as_object)
        .ok_or_else(|| AuthError::internal("Invalid request OAuth state fields"))?;
    let extras = snapshot
        .get("extras")
        .and_then(FieldValue::as_str)
        .ok_or_else(|| AuthError::internal("Invalid request OAuth state extras"))?;
    let extras = FieldValue::parse_json(extras)?;
    let extras = extras
        .as_object()
        .ok_or_else(|| AuthError::internal("OAuth state extras must be an object"))?;
    let mut state = if snapshot.get("extrasFirst") == Some(&FieldValue::Bool(true)) {
        let mut state = extras.clone();
        state.extend(fields.clone());
        state
    } else {
        let mut state = fields.clone();
        state.extend(extras.clone());
        state
    };
    if let Some(error_url) = snapshot
        .get("errorURL")
        .filter(|value| !value.is_undefined())
        && !state.get("errorURL").is_some_and(FieldValue::is_truthy)
    {
        let _ = state.insert("errorURL".into(), error_url.clone());
    }
    state.sort_by_key(|name, _| {
        better_auth_core::utils::json::array_index(name).map_or((true, 0), |index| (false, index))
    });
    Ok(Some(state.into()))
}

fn publish(
    req: &AuthRequest,
    payload: &OAuthStatePayload,
    fields: FieldMap,
    extras_first: bool,
    error_url: Option<&str>,
) -> AuthResult<()> {
    // Defer native key conversion until an explicit read. Persistence accepts raw UTF-16 keys.
    req.set_server_context(
        OAUTH_STATE_CONTEXT,
        FieldMap::from([
            ("fields".into(), fields.into()),
            (
                "extras".into(),
                serde_json::to_string(&payload.additional_data)?.into(),
            ),
            ("extrasFirst".into(), extras_first.into()),
            (
                "errorURL".into(),
                error_url.map_or(FieldValue::Undefined, Into::into),
            ),
        ])
        .into(),
    )
}

pub(super) fn publish_generated(req: &AuthRequest, payload: &OAuthStatePayload) -> AuthResult<()> {
    let server_context = if payload.server_context.is_empty() {
        FieldValue::Undefined
    } else {
        FieldMap::from_json(payload.server_context.clone())?.into()
    };
    let fields = FieldMap::from([
        ("callbackURL".into(), payload.callback_url.clone().into()),
        ("codeVerifier".into(), payload.code_verifier.clone().into()),
        ("errorURL".into(), optional_string(&payload.error_url)),
        ("newUserURL".into(), optional_string(&payload.new_user_url)),
        (
            "link".into(),
            payload
                .link
                .as_ref()
                .map_or(FieldValue::Undefined, |link| link.native_value()),
        ),
        ("serverContext".into(), server_context),
        ("expiresAt".into(), payload.expires_at.into()),
        (
            "requestSignUp".into(),
            payload
                .request_sign_up
                .map_or(FieldValue::Undefined, Into::into),
        ),
        (
            "idTokenNonce".into(),
            optional_string(&payload.id_token_nonce),
        ),
    ]);
    publish(req, payload, fields, true, None)
}

pub(super) fn publish_parsed(
    req: &AuthRequest,
    payload: &OAuthStatePayload,
    error_url: Option<&str>,
) -> AuthResult<()> {
    let mut fields = FieldMap::from([
        ("callbackURL".into(), payload.callback_url.clone().into()),
        ("codeVerifier".into(), payload.code_verifier.clone().into()),
    ]);
    for (key, value) in [
        ("errorURL", &payload.error_url),
        ("newUserURL", &payload.new_user_url),
    ] {
        if let Some(value) = value {
            let _ = fields.insert(key.into(), value.clone().into());
        }
    }
    let _ = fields.insert("expiresAt".into(), payload.expires_at.into());
    if let Some(state) = &payload.oauth_state {
        let _ = fields.insert("oauthState".into(), state.clone().into());
    }
    if let Some(link) = &payload.link {
        let _ = fields.insert("link".into(), link.native_value());
    }
    if let Some(sign_up) = payload.request_sign_up {
        let _ = fields.insert("requestSignUp".into(), sign_up.into());
    }
    if let Some(nonce) = &payload.id_token_nonce {
        let _ = fields.insert("idTokenNonce".into(), nonce.clone().into());
    }
    if payload.server_context_present || !payload.server_context.is_empty() {
        let _ = fields.insert(
            "serverContext".into(),
            FieldMap::from_json(payload.server_context.clone())?.into(),
        );
    }
    publish(req, payload, fields, false, error_url)
}

fn optional_string(value: &Option<String>) -> FieldValue {
    value
        .as_ref()
        .map_or(FieldValue::Undefined, |value| value.clone().into())
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Regression assertions retain native state shape and raw JSON boundaries"
)]
mod tests {
    use super::*;
    use better_auth_core::HttpMethod;

    #[test]
    fn generated_and_parsed_state_keep_distinct_native_fields() -> AuthResult<()> {
        let request = AuthRequest::new(HttpMethod::Post, "/link-social");
        assert!(get_oauth_state(&request)?.is_none());
        let mut payload = OAuthStatePayload::new(
            "/done".into(),
            "verifier".into(),
            None,
            None,
            Some(super::super::state::OAuthStateLink::new(
                FieldValue::Undefined,
                "owner@example.test".into(),
            )),
            None,
            Default::default(),
        );
        payload.oauth_state = Some("bound".into());
        payload.additional_data.insert("2", &true)?;
        publish_generated(&request, &payload)?;
        let generated = get_oauth_state(&request)?
            .ok_or_else(|| AuthError::internal("missing generated state"))?;
        let fields = generated
            .as_object()
            .ok_or_else(|| AuthError::internal("expected generated object"))?;
        assert_eq!(fields.get("errorURL"), Some(&FieldValue::Undefined));
        assert_eq!(fields.keys().next().map(String::as_str), Some("2"));
        assert!(!fields.contains_key("oauthState"));
        assert_eq!(
            fields
                .get("link")
                .and_then(FieldValue::as_object)
                .and_then(|link| link.get("userId")),
            Some(&FieldValue::Undefined)
        );

        assert!(matches!(
            OAuthStatePayload::parse(&serde_json::to_string(&payload)?),
            Err(AuthError::BadRequest(message)) if message == "Invalid OAuth state link user ID"
        ));
        payload.link = Some(super::super::state::OAuthStateLink::new(
            7.into(),
            "owner@example.test".into(),
        ));
        let parsed = OAuthStatePayload::parse(&serde_json::to_string(&payload)?)?;
        publish_parsed(&request, &parsed, Some("/error"))?;
        let parsed = get_oauth_state(&request)?
            .ok_or_else(|| AuthError::internal("missing parsed state"))?;
        let fields = parsed
            .as_object()
            .ok_or_else(|| AuthError::internal("expected parsed object"))?;
        assert_eq!(fields.get("errorURL"), Some(&"/error".into()));
        assert_eq!(fields.keys().next().map(String::as_str), Some("2"));
        assert_eq!(fields.keys().last().map(String::as_str), Some("errorURL"));
        assert_eq!(fields.get("oauthState"), Some(&"bound".into()));
        assert!(!fields.contains_key("newUserURL"));
        assert_eq!(
            fields
                .get("link")
                .and_then(FieldValue::as_object)
                .and_then(|link| link.get("userId")),
            Some(&"7".into())
        );
        Ok(())
    }

    #[test]
    fn state_publication_preserves_raw_keys_until_the_explicit_accessor() -> AuthResult<()> {
        let raw = r#"{"callbackURL":"/done","codeVerifier":"verifier","expiresAt":1,"serverContext":{},"\ud800":{"value":"\udc00"}}"#;
        let payload = OAuthStatePayload::parse(raw)?;
        let request = AuthRequest::new(HttpMethod::Get, "/callback/google");
        publish_parsed(&request, &payload, None)?;
        assert!(get_oauth_state(&request).is_err());
        let persisted = serde_json::to_string(&payload)?;
        assert!(persisted.contains(r#""\ud800":{"value":"\udc00"}"#));
        assert!(persisted.contains(r#""serverContext":{}"#));
        Ok(())
    }
}
