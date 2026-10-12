#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]

//! OAuth public projections run only at the response or cookie-cache boundary.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    CookieCacheConfig, FieldFunction, FieldMap, FieldValue, HttpMethod,
    config::CookieCacheVersion,
    store::{EphemeralStore, StatelessSchema, schema::EntityRole},
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType},
};
use serde_json::{Value, json};

use super::{OAuthPlugin, OAuthProxyPlugin, google_test_support::GoogleFixture};
use crate::plugins::{
    one_tap::{OneTapConfig, OneTapPlugin},
    test_helpers,
};

const ORIGIN: &str = "http://oauth-projection.test";
const CALLBACK: &str = "http://oauth-projection.test/complete";
const SECRET: &str = "oauth-projection-contract-secret-at-least-thirty-two-characters";
const EMAIL: &str = "owner@oauth-projection.test";
const IMAGE: &str = "https://images.example.test/owner.png";

#[derive(Clone, Copy, Debug)]
enum Flow {
    Direct,
    OneTap,
    Callback,
    Proxy,
}

impl Flow {
    fn returns_user(self) -> bool {
        matches!(self, Self::Direct | Self::OneTap)
    }
}

const FLOWS: [Flow; 4] = [Flow::Direct, Flow::OneTap, Flow::Callback, Flow::Proxy];

fn missing(message: &str) -> AuthError {
    AuthError::internal(message)
}

fn function(calls: Arc<AtomicUsize>) -> FieldValue {
    FieldFunction::contextual(move |_, _| {
        let _ = calls.fetch_add(1, Ordering::SeqCst);
        Ok(FieldValue::Undefined)
    })
    .into()
}

fn request(method: HttpMethod, path: &str, body: Value) -> AuthResult<AuthRequest> {
    let mut request = AuthRequest::new(method, path);
    request.body = Some(serde_json::to_vec(&body)?);
    let _ = request
        .headers
        .insert("user-agent".into(), "oauth-projection-contract".into());
    Ok(request)
}

fn claims() -> Value {
    json!({"sub":"projection-owner","email":EMAIL,"email_verified":true,
        "name":"Projection Owner","picture":IMAGE,"nonce":"projection-nonce"})
}

async fn context(
    config: AuthConfig,
    oauth: &OAuthPlugin,
) -> AuthResult<(AuthContext<StatelessSchema>, Arc<EphemeralStore>)> {
    let config = Arc::new(config);
    let store = Arc::new(EphemeralStore::new(config.clone()));
    let context = test_helpers::initialize_test_context(config, store.clone(), &[oauth]).await?;
    Ok((context, store))
}

async fn prepare(
    flow: Flow,
    server: &GoogleFixture,
    oauth: &OAuthPlugin,
    ctx: &AuthContext<StatelessSchema>,
) -> AuthResult<AuthRequest> {
    match flow {
        Flow::Direct => request(
            HttpMethod::Post,
            "/sign-in/social",
            json!({"provider":"google","idToken":{"token":server.token,"nonce":"projection-nonce"}}),
        ),
        Flow::OneTap => request(
            HttpMethod::Post,
            "/one-tap/callback",
            json!({"idToken":server.token}),
        ),
        Flow::Callback | Flow::Proxy => {
            let start = oauth
                .on_request(
                    &request(
                        HttpMethod::Post,
                        "/sign-in/social",
                        json!({"provider":"google","callbackURL":CALLBACK,"disableRedirect":true}),
                    )?,
                    ctx,
                )
                .await?
                .ok_or_else(|| missing("OAuth start response missing"))?;
            let url = start.body.field_value()?.model_property("url")?;
            let url = url::Url::parse(
                url.as_str()
                    .ok_or_else(|| missing("OAuth authorization URL missing"))?,
            )
            .map_err(|error| missing(&format!("Invalid OAuth authorization URL: {error}")))?;
            let state = url
                .query_pairs()
                .find(|(key, _)| key == "state")
                .ok_or_else(|| missing("OAuth state missing"))?
                .1
                .into_owned();
            let mut request = request(
                HttpMethod::Get,
                if matches!(flow, Flow::Proxy) {
                    "/oauth-proxy-callback"
                } else {
                    "/callback/google"
                },
                Value::Null,
            )?;
            let _ = request.headers.insert(
                "cookie".into(),
                start
                    .headers
                    .get_all("set-cookie")
                    .filter_map(|value| value.split(';').next())
                    .collect::<Vec<_>>()
                    .join("; "),
            );
            request.query = Some(if matches!(flow, Flow::Proxy) {
                let profile = json!({
                    "userInfo":{"id":"projection-owner","email":EMAIL,"emailVerified":true,
                        "name":"Projection Owner","image":IMAGE},
                    "account":{"accountId":"projection-owner","providerId":"google"},
                    "state":state,"callbackURL":CALLBACK,"timestamp":chrono::Utc::now().timestamp_millis(),
                });
                json!({"callbackURL":CALLBACK,"profile":crate::plugins::symmetric::encrypt(SECRET, &profile.to_string())?})
            } else {
                json!({"code":"projection-code","state":state})
            });
            Ok(request)
        }
    }
}

async fn invoke(
    flow: Flow,
    server: &GoogleFixture,
    oauth: &OAuthPlugin,
    req: &AuthRequest,
    ctx: &AuthContext<StatelessSchema>,
) -> AuthResult<AuthResponse> {
    let response = match flow {
        Flow::Direct | Flow::Callback => oauth.on_request(req, ctx).await?,
        Flow::OneTap => {
            OneTapPlugin::with_config(OneTapConfig {
                client_id: Some(vec!["client".into()]),
                google_jwks_url: format!("{}/jwks", server.url),
                ..Default::default()
            })
            .on_request(req, ctx)
            .await?
        }
        Flow::Proxy => OAuthProxyPlugin::new().on_request(req, ctx).await?,
    };
    response.ok_or_else(|| missing("OAuth result missing"))
}

fn one_row(store: &EphemeralStore, role: EntityRole) -> AuthResult<FieldMap> {
    let mut rows = store.storage_rows(role)?;
    assert_eq!(rows.len(), 1, "{role:?} persistence after OAuth output");
    rows.pop()
        .ok_or_else(|| missing("Persisted OAuth row missing"))
}

fn assert_storage(store: &EphemeralStore) -> AuthResult<(FieldMap, FieldMap)> {
    let user = one_row(store, EntityRole::User)?;
    let session = one_row(store, EntityRole::Session)?;
    let account = one_row(store, EntityRole::Account)?;
    assert_eq!(user.get("name"), Some(&"Projection Owner".into()));
    assert_eq!(user.get("image"), Some(&IMAGE.into()));
    assert_eq!(user.get("email"), Some(&EMAIL.into()));
    assert_eq!(account.get("accountId"), Some(&"projection-owner".into()));
    assert_eq!(account.get("providerId"), Some(&"google".into()));
    assert_eq!(account.get("userId"), user.get("id"));
    assert_eq!(session.get("userId"), user.get("id"));
    assert_eq!(
        session.get("userAgent"),
        Some(&"oauth-projection-contract".into())
    );
    assert!(store.storage_rows(EntityRole::Verification)?.is_empty());
    Ok((user, session))
}

fn cookies(req: &AuthRequest, session: &FieldMap) -> AuthResult<Vec<(String, String)>> {
    let values = req
        .take_response_headers()?
        .get_all("set-cookie")
        .map(|header| {
            let cookie = cookie::Cookie::parse(header.to_owned())
                .map_err(|error| missing(&format!("Invalid OAuth cookie: {error}")))?;
            Ok((cookie.name().to_owned(), cookie.value().to_owned()))
        })
        .collect::<AuthResult<Vec<_>>>()?;
    let token = values
        .iter()
        .find(|(name, _)| name == "better-auth.session_token")
        .ok_or_else(|| missing("Session token cookie must precede public projection"))?;
    assert_eq!(
        better_auth_core::utils::cookie_utils::verify_cookie_value(&token.1, SECRET),
        session
            .get("token")
            .and_then(FieldValue::as_str)
            .map(str::to_owned)
    );
    Ok(values)
}

fn assert_response(
    flow: Flow,
    response: AuthResponse,
    mut user: FieldMap,
    session: &FieldMap,
    hide_image: bool,
) -> AuthResult<()> {
    if flow.returns_user() {
        assert_eq!(response.status, 200);
        if hide_image {
            let _ = user.shift_remove("image");
        }
        let mut expected = FieldMap::new();
        if matches!(flow, Flow::Direct) {
            let _ = expected.insert("redirect".into(), false.into());
        }
        let _ = expected.insert(
            "token".into(),
            session.get("token").cloned().unwrap_or_default(),
        );
        if matches!(flow, Flow::Direct) {
            let _ = expected.insert("url".into(), FieldValue::Undefined);
        }
        let _ = expected.insert("user".into(), user.into());
        let actual = response.body.field_value()?.enumerable_fields()?;
        assert_eq!(
            actual.keys().collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            FieldValue::from(actual).json()?,
            FieldValue::from(expected).json()?
        );
    } else {
        assert_eq!(response.status, 302);
        assert_eq!(response.headers.get("location"), Some(&CALLBACK.to_owned()));
    }
    Ok(())
}

#[tokio::test]
async fn native_clone_failures_preserve_oauth_cookie_snapshot_and_persistence_order()
-> AuthResult<()> {
    let server = GoogleFixture::start(claims()).await;
    for flow in FLOWS {
        for user_field in [false, true] {
            for cache in [false, true] {
                let calls = Arc::new(AtomicUsize::new(0));
                let output = function(calls.clone());
                let field = UserFieldConfig {
                    field_type: UserFieldType::String,
                    required: Some(false),
                    returned: Some(false),
                    transform: Some(FieldTransforms {
                        output: Some(UserFieldTransform::new(move |_| Ok(output.clone()))),
                        ..Default::default()
                    }),
                    ..Default::default()
                };
                let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
                config.session.cookie_cache = Some(CookieCacheConfig {
                    enabled: Some(cache),
                    ..Default::default()
                });
                if user_field {
                    let _ = config.user.fields_mut().insert("image".into(), field);
                } else {
                    let _ = config
                        .session
                        .fields_mut()
                        .insert("userAgent".into(), field);
                }
                let oauth = OAuthPlugin::new().add_provider("google", server.provider());
                let (ctx, store) = context(config, &oauth).await?;
                let req = prepare(flow, &server, &oauth, &ctx).await?;
                let response = invoke(flow, &server, &oauth, &req, &ctx).await;
                let (user, session) = assert_storage(&store)?;
                let cookie_values = cookies(&req, &session)?;
                assert!(
                    cookie_values
                        .iter()
                        .all(|(name, _)| name != "better-auth.session_data")
                );
                assert_eq!(
                    req.new_session()?.is_some(),
                    !cache,
                    "{flow:?}/{user_field}/{cache}"
                );
                if cache || user_field && flow.returns_user() {
                    assert!(
                        matches!(response, Err(AuthError::DataClone)),
                        "{flow:?}/{user_field}/{cache}: {response:?}"
                    );
                } else {
                    assert_response(flow, response?, user, &session, user_field)?;
                }
                assert_eq!(calls.load(Ordering::SeqCst), 0);
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn cookie_version_mutation_is_visible_only_to_later_oauth_user_projection() -> AuthResult<()>
{
    let server = GoogleFixture::start(claims()).await;
    for flow in FLOWS {
        for invalid in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let replacement = if invalid {
                function(calls.clone())
            } else {
                "After cookie payload".into()
            };
            let versions = Arc::new(AtomicUsize::new(0));
            let observed = versions.clone();
            let value = replacement.clone();
            let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
            config.session.cookie_cache = Some(CookieCacheConfig {
                enabled: Some(true),
                version: CookieCacheVersion::dynamic(move |data| {
                    let value = value.clone();
                    let observed = observed.clone();
                    async move {
                        let _ = observed.fetch_add(1, Ordering::SeqCst);
                        let _ = data
                            .user_value()?
                            .as_object()
                            .ok_or_else(|| missing("Cookie version User must remain native"))?
                            .set("name", value)?;
                        Ok("projection".into())
                    }
                }),
                ..Default::default()
            });
            let oauth = OAuthPlugin::new().add_provider("google", server.provider());
            let (ctx, store) = context(config, &oauth).await?;
            let req = prepare(flow, &server, &oauth, &ctx).await?;
            let response = invoke(flow, &server, &oauth, &req, &ctx).await;
            let (mut user, session) = assert_storage(&store)?;
            let cookie_values = cookies(&req, &session)?;
            let encoded = cookie_values
                .iter()
                .find(|(name, _)| name == "better-auth.session_data")
                .ok_or_else(|| missing("Cookie cache must precede OAuth public User projection"))?;
            let bytes = URL_SAFE_NO_PAD
                .decode(&encoded.1)
                .map_err(|error| missing(&format!("Invalid cookie cache encoding: {error}")))?;
            let cache: Value = serde_json::from_slice(&bytes)?;
            assert_eq!(
                cache.pointer("/session/user/name"),
                Some(&json!("Projection Owner"))
            );
            let issued = req
                .new_session()?
                .ok_or_else(|| missing("Cookie mutation issuance snapshot missing"))?;
            assert!(issued.user_property("name")?.strict_equals(&replacement));
            assert_eq!(versions.load(Ordering::SeqCst), 1);
            if invalid && flow.returns_user() {
                assert!(
                    matches!(response, Err(AuthError::DataClone)),
                    "{flow:?}: {response:?}"
                );
            } else {
                let _ = user.insert("name".into(), replacement);
                assert_response(flow, response?, user, &session, false)?;
            }
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }
    Ok(())
}
