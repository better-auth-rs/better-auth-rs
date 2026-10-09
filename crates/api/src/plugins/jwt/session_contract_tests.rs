use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{
    FromFieldMap,
    session::{NativeSessionData, SessionCookieContext, SessionCookieSigner},
    wire::SessionView,
};
use better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
use std::sync::{Arc, Mutex};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
type Events = Arc<Mutex<Vec<Value>>>;

fn record(events: &Events, event: Value) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("JWT capture event lock poisoned"))?
        .push(event);
    Ok(())
}

fn native(value: &FieldValue) -> AuthResult<Value> {
    Ok(match value {
        FieldValue::Undefined => json!({"undefined": true}),
        FieldValue::Number(value) if !value.is_finite() => {
            json!({"number": if value.is_nan() { "NaN" } else { "Infinity" }})
        }
        FieldValue::Date(value) => json!({"date": value.milliseconds()}),
        FieldValue::Array(values) => values
            .iter()
            .map(native)
            .collect::<AuthResult<Vec<_>>>()?
            .into(),
        FieldValue::Object(fields) => fields
            .iter()
            .map(|(name, value)| Ok((name.clone(), native(value)?)))
            .collect::<AuthResult<Map<_, _>>>()?
            .into(),
        value => value.json()?.unwrap_or(Value::Null),
    })
}

fn data(user: FieldValue) -> AuthResult<NativeSessionData> {
    Ok(NativeSessionData {
        session: SessionView::from_field_values(FieldMap::from([
            ("id".into(), "sid".into()),
            ("token".into(), "session-token".into()),
            ("userId".into(), "owner".into()),
        ]))?,
        user,
    })
}

fn users() -> Vec<(&'static str, FieldValue)> {
    let user = |id| {
        let mut fields = FieldMap::from([("marker".into(), "kept".into())]);
        if let Some(id) = id {
            let _ = fields.insert("id".into(), id);
        }
        FieldValue::from(fields)
    };
    vec![
        ("string", user(Some("owner".into()))),
        ("missing", user(None)),
        ("undefined", user(Some(FieldValue::Undefined))),
        ("null", user(Some(FieldValue::Null))),
        ("false", user(Some(false.into()))),
        ("zero", user(Some(0.0.into()))),
        ("empty", user(Some("".into()))),
        ("number", user(Some(7.0.into()))),
        ("nan", user(Some(f64::NAN.into()))),
        ("infinity", user(Some(f64::INFINITY.into()))),
        ("many-array", vec![user(Some("child".into()))].into()),
        (
            "many-public",
            FieldMap::from([("0".into(), user(Some("child".into())))]).into(),
        ),
        ("null-user", FieldValue::Null),
        ("false-user", false.into()),
        ("zero-user", 0.0.into()),
    ]
}

fn config(policy: &'static str, events: &Events) -> JwtPluginConfig {
    let mut config = JwtPluginConfig {
        disable_private_key_encryption: true,
        ..Default::default()
    };
    if matches!(policy, "both" | "payload-failure" | "subject-failure") {
        let events = events.clone();
        config.define_payload = Some(Arc::new(move |data| {
            let events = events.clone();
            Box::pin(async move {
                let observed = native(&FieldValue::from_json(data.clone())?)?;
                record(
                    &events,
                    json!(["payload", {"native": observed, "json": data}]),
                )?;
                if policy == "payload-failure" {
                    return Err(AuthError::internal("payload failure"));
                }
                Ok(Map::from_iter([("callback".into(), true.into())]))
            })
        }));
    }
    if policy != "none" {
        let events = events.clone();
        config.get_subject = Some(Arc::new(move |data| {
            let events = events.clone();
            Box::pin(async move {
                let observed = native(&FieldValue::from_json(data.clone())?)?;
                record(
                    &events,
                    json!(["subject", {"native": observed, "json": data}]),
                )?;
                if policy == "subject-failure" {
                    return Err(AuthError::internal("subject failure"));
                }
                Ok("callback-subject".into())
            })
        }));
    }
    config
}

fn token_claims(token: &str) -> TestResult<Map<String, Value>> {
    let encoded = token.split('.').nth(1).ok_or("JWT has no payload")?;
    Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded)?)?)
}

fn observe(result: AuthResult<String>, cookie: bool) -> TestResult<Value> {
    match result {
        Ok(token) => {
            let mut claims = token_claims(&token)?;
            let issued = claims
                .get("iat")
                .and_then(Value::as_i64)
                .ok_or("JWT iat must be an integer")?;
            let expiry = claims
                .get("exp")
                .and_then(Value::as_i64)
                .ok_or("JWT exp must be an integer")?;
            if cookie {
                // Cookie signing reads the clock separately for iat and exp.
                assert!((60..=61).contains(&(expiry - issued)));
            } else {
                assert_eq!(expiry - issued, 900);
            }
            let _ = claims.insert("iat".into(), "now".into());
            let _ = claims.insert(
                "exp".into(),
                if cookie { "now+60" } else { "now+900" }.into(),
            );
            Ok(json!({"claims": claims}))
        }
        Err(AuthError::Internal(message) | AuthError::TypeError(message)) => {
            Ok(json!({"error": message}))
        }
        Err(error) => Err(error.into()),
    }
}

async fn capture(
    context: &AuthContext<BundledSchema>,
    key: &better_auth_core::Jwk,
    name: &str,
    session: Option<NativeSessionData>,
    policy: &'static str,
    cookie: bool,
) -> TestResult<Value> {
    let events = Events::default();
    let mut context = context.clone();
    let key = key.clone();
    let recorded = events.clone();
    context
        .extensions
        .insert(Arc::new(JwtCallbacks::<BundledSchema>::default().get_jwks(
            move |endpoint| {
                let key = key.clone();
                let events = recorded.clone();
                Box::pin(async move {
                    let snapshot = match &endpoint.session {
                        Some(data) => native(&FieldMap::from(data.clone()).into())?,
                        None => Value::Null,
                    };
                    record(&events, json!(["keys", snapshot]))?;
                    Ok(Some(vec![key]))
                })
            },
        )));
    let plugin = JwtPlugin::with_config(config(policy, &events));
    let request = AuthRequest::new(HttpMethod::Get, "/token");
    let result = if cookie {
        let init = AuthInitContext::new(context.config.clone(), context.database.clone());
        let runtime = init.runtime();
        let context = Arc::new(context);
        runtime.bind(&context)?;
        let signer = cache::CookieSigner { plugin, runtime };
        signer
            .sign(
                FieldMap::from(session.ok_or("Cookie capture requires Session data")?).json()?,
                60.0,
                SessionCookieContext {
                    request: &request,
                    config: &context.config,
                    transaction: None,
                },
            )
            .await
    } else {
        let mut endpoint = EndpointContext::new(Some(&request), FieldValue::Null, &context);
        endpoint.session = session.clone();
        plugin.sign_session(session, &endpoint).await
    };
    let events = events
        .lock()
        .map_err(|_| AuthError::internal("JWT capture event lock poisoned"))?
        .clone();
    Ok(json!({"name": name, "result": observe(result, cookie)?, "events": events}))
}

#[tokio::test]
async fn native_session_jwt_matches_pinned_capture() -> TestResult {
    let mut context = crate::plugins::test_helpers::create_test_context().await;
    let mut config = (*context.config).clone();
    config.base_url = "http://jwt-native-session.test".into();
    context.config = Arc::new(config);
    let key = JwtPlugin::new()
        .disable_private_key_encryption(true)
        .create_key_pair(JwtKeyPairConfig::new(JwtAlgorithm::EdDsa), &context)
        .await?
        .ok_or("JWT capture key creation returned no row")?;
    let mut captured = Vec::new();
    for (name, user) in users() {
        captured.push(capture(&context, &key, name, Some(data(user)?), "none", false).await?);
    }
    for (name, session, policy) in [
        (
            "missing-callbacks",
            Some(data(
                FieldMap::from([("marker".into(), "kept".into())]).into(),
            )?),
            "both",
        ),
        (
            "many-callbacks",
            Some(data(
                vec![FieldMap::from([("id".into(), "child".into())]).into()].into(),
            )?),
            "both",
        ),
        (
            "null-user-subject",
            Some(data(FieldValue::Null)?),
            "subject",
        ),
        ("absent-session", None, "none"),
        ("absent-session-callbacks", None, "both"),
        (
            "payload-failure",
            Some(data(FieldMap::new().into())?),
            "payload-failure",
        ),
        (
            "subject-failure",
            Some(data(FieldMap::new().into())?),
            "subject-failure",
        ),
    ] {
        captured.push(capture(&context, &key, name, session, policy, false).await?);
    }
    for (name, user) in users()
        .into_iter()
        .filter(|(name, _)| !matches!(*name, "null-user" | "false-user" | "zero-user"))
    {
        captured.push(
            capture(
                &context,
                &key,
                &format!("cache-{name}"),
                Some(data(user)?),
                "none",
                true,
            )
            .await?,
        );
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/jwt-native-session-1.7.6.json");
    let expected: Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    let cases = expected
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("JWT capture has no cases")?;
    assert_eq!(cases.len(), 34);
    assert_eq!(json!({"version": "1.7.6", "cases": captured}), expected);
    Ok(())
}

#[tokio::test]
async fn token_header_and_cookie_keys_observe_native_relationship_snapshots() -> TestResult {
    use better_auth_core::{
        AuthConfig, CreateSession, CreateUser,
        store::{AuthStore, EphemeralStore, StatelessSchema},
        user_fields::{UserFieldConfig, UserFieldReference},
        utils::cookie_utils::sign_cookie_value,
    };

    let mut config =
        AuthConfig::new("jwt-native-relationship-secret-at-least-thirty-two-characters")
            .base_url("http://jwt-native-session.test");
    config.telemetry.enabled = false;
    config.session.disable_session_refresh = Some(true);
    let _ = config.user.fields_mut().insert(
        "image".into(),
        UserFieldConfig {
            references: Some(UserFieldReference {
                model: "session".into(),
                field: "id".into(),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let config = Arc::new(config);
    let database: Arc<dyn AuthStore<StatelessSchema>> =
        Arc::new(EphemeralStore::new(config.clone()));
    let plugin = JwtPlugin::new().disable_private_key_encryption(true);
    let mut context =
        crate::plugins::test_helpers::initialize_test_context(config, database, &[&plugin]).await?;
    let _ = plugin
        .create_key_pair(JwtKeyPairConfig::new(JwtAlgorithm::EdDsa), &context)
        .await?
        .ok_or("JWT relationship key creation returned no row")?;
    let session = context
        .database
        .create_session(CreateSession {
            inherited_fields: Default::default(),
            additional_fields: Default::default(),
            user_id: "canonical-owner".into(),
            expires_at: (Utc::now() + Duration::hours(1)).into(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?;
    let mut selected = CreateUser::new()
        .with_name("Selected User")
        .with_email("selected@jwt.test");
    selected.image = Some(session.id.typed()?.clone()).into();
    let selected = context.database.create_user(selected).await?;
    let events = Events::default();
    let recorded = events.clone();
    context.extensions.insert(Arc::new(
        JwtCallbacks::<StatelessSchema>::default().get_jwks(move |endpoint| {
            let events = recorded.clone();
            Box::pin(async move {
                let snapshot = endpoint.session.as_ref().ok_or_else(|| {
                    AuthError::internal("JWT key callback lost its native Session")
                })?;
                record(&events, native(&FieldMap::from(snapshot.clone()).into())?)?;
                endpoint.auth.database.list_jwks().await.map(Some)
            })
        }),
    ));
    let cookies = format!(
        "better-auth.session_token={}",
        sign_cookie_value(session.token.typed()?, context.config.signing_secret())
    );
    let mut token_request = AuthRequest::new(HttpMethod::Get, "/token");
    let _ = token_request
        .headers
        .insert("cookie".into(), cookies.clone());
    let token_response = plugin
        .on_request(&token_request, &context)
        .await?
        .ok_or("JWT route returned no response")?;
    assert_eq!(token_response.status, 200);
    assert!(token_request.session_snapshot().is_err());
    let token_body: Value = serde_json::from_slice(&token_response.body.bytes()?)?;
    let token = token_body
        .get("token")
        .and_then(Value::as_str)
        .ok_or("JWT response has no token")?;
    let claims = token_claims(token)?;
    assert!(claims.get("sub").is_none());
    assert_eq!(
        claims.get("0").and_then(|user| user.get("id")),
        Some(
            &selected
                .id
                .field_value()
                .json()?
                .ok_or("Selected User has no JSON ID")?
        )
    );

    let mut header_request = AuthRequest::new(HttpMethod::Get, "/get-session");
    let _ = header_request.headers.insert("cookie".into(), cookies);
    let snapshot = context.require_native_session(&header_request).await?;
    context.session_manager().publish_session(
        &header_request,
        data(FieldMap::from([("id".into(), "issued-owner".into())]).into())?,
    )?;
    let mut response = AuthResponse::native(200, FieldValue::Null);
    plugin
        .after_request(&header_request, &mut response, &context)
        .await?;
    let header_claims = token_claims(
        response
            .headers
            .get("set-auth-jwt")
            .ok_or("Session response has no JWT header")?,
    )?;
    assert!(header_claims.get("sub").is_none());
    assert_eq!(header_claims.get("0"), claims.get("0"));
    assert_eq!(
        response
            .headers
            .get("access-control-expose-headers")
            .map(String::as_str),
        Some("set-auth-jwt")
    );

    let new_only = AuthRequest::new(HttpMethod::Get, "/get-session");
    context.session_manager().publish_session(
        &new_only,
        data(FieldMap::from([("id".into(), "issued-owner".into())]).into())?,
    )?;
    let mut response = AuthResponse::native(200, FieldValue::Null);
    assert!(
        matches!(plugin.after_request(&new_only, &mut response, &context).await, Err(AuthError::TypeError(message)) if message == "null is not an object (evaluating 'ctx.context.session.user')")
    );
    assert!(!response.headers.contains_key("set-auth-jwt"));

    let init = AuthInitContext::new(context.config.clone(), context.database.clone());
    let runtime = init.runtime();
    let context = Arc::new(context);
    runtime.bind(&context)?;
    let signer = cache::CookieSigner { plugin, runtime };
    let cookie_context = || SessionCookieContext {
        request: &header_request,
        config: &context.config,
        transaction: None,
    };
    let token = signer
        .sign(
            FieldMap::from(data(
                FieldMap::from([("id".into(), "owner".into())]).into(),
            )?)
            .json()?,
            60.0,
            cookie_context(),
        )
        .await?;
    assert!(signer.verify(&token, cookie_context()).await?.is_some());
    let recorded = events
        .lock()
        .map_err(|_| AuthError::internal("JWT capture event lock poisoned"))?
        .clone();
    assert_eq!(recorded, vec![native(&FieldMap::from(snapshot).into())?; 4]);
    Ok(())
}
