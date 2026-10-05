#![cfg(feature = "seaorm2")]

use better_auth::config::{FieldTransforms, UserFieldTransform};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthStore, CreateAccount, CreateSession,
    CreateUser, store::EphemeralStore, user_fields::UserFieldConfig,
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::Database,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use serde_json::{Value, json};

type Events = Arc<Mutex<Vec<String>>>;

fn take(events: &Events) -> AuthResult<Vec<String>> {
    Ok(std::mem::take(
        &mut *events
            .lock()
            .map_err(|error| AuthError::internal(error.to_string()))?,
    ))
}

fn config(limit: Option<f64>, events: &Events, reject_user: &Arc<AtomicBool>) -> AuthConfig {
    let mut config = AuthConfig::default();
    config.advanced.database.default_find_many_limit = limit;
    for (name, kind) in [
        ("username", "user"),
        ("accessToken", "account"),
        ("userAgent", "session"),
    ] {
        let events = events.clone();
        let reject = reject_user.clone();
        let field = UserFieldConfig {
            required: Some(false),
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    let value_text = value
                        .as_ref()
                        .and_then(Value::as_str)
                        .unwrap_or("undefined");
                    events
                        .lock()
                        .map_err(|error| AuthError::internal(error.to_string()))?
                        .push(format!("{kind}:{value_text}"));
                    if kind == "user" && reject.load(Ordering::SeqCst) {
                        return Err(AuthError::internal("user projection rejected"));
                    }
                    Ok(value)
                })),
                ..Default::default()
            }),
            ..Default::default()
        };
        let fields = match kind {
            "user" => config.user.fields_mut(),
            "account" => &mut config.account.additional_fields,
            _ => config.session.fields_mut(),
        };
        let _ = fields.insert(name.into(), field);
    }
    config
}

async fn run<S: AuthSchema>(
    store: &impl AuthStore<S>,
    case: &Value,
    events: &Events,
    reject: &AtomicBool,
) -> AuthResult<()> {
    let mut tokens = Vec::new();
    for name in ["alice", "bob"] {
        let _ = store
            .create_user(CreateUser {
                id: Some(name.into()),
                email: Some(format!("{name}@example.test")),
                name: Some(name.into()).into(),
                email_verified: Some(true),
                username: Some(Some(name.into())),
                ..Default::default()
            })
            .await?;
        for index in 0..3 {
            let _ = store
                .create_account(CreateAccount {
                    user_id: name.into(),
                    provider_id: format!("provider-{index}").into(),
                    account_id: format!("{name}-{index}").into(),
                    access_token: Some(format!("{name}-{index}")).into(),
                    ..Default::default()
                })
                .await?;
        }
        let session = store
            .create_session(CreateSession {
                user_id: name.into(),
                user_agent: Some(name.into()),
                expires_at: "2099-01-01T00:00:00Z"
                    .parse()
                    .map_err(|error: chrono::ParseError| AuthError::internal(error.to_string()))?,
                additional_fields: Default::default(),
                ip_address: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await?;
        let token = format!("{name}-session");
        let _ = store
            .update_session_with_writer(
                &session.token,
                better_auth_core::store::database_hooks::SessionUpdate {
                    token: Some(token.clone()),
                    ..Default::default()
                },
                None,
            )
            .await?;
        tokens.push(token);
    }
    let _ = take(events)?;
    let owner = store
        .get_account_owner("provider-1", "alice-1")
        .await?
        .ok_or_else(|| AuthError::internal("owner missing"))?;
    assert_eq!(owner.account.user_id, "alice");
    assert_eq!(
        owner
            .user
            .ok_or_else(|| AuthError::internal("user missing"))?
            .id,
        "alice"
    );
    assert_eq!(json!(take(events)?), case["ownerEvents"]);
    let record = store
        .get_user_with_accounts("ALICE@example.test")
        .await?
        .ok_or_else(|| AuthError::internal("user missing"))?;
    assert_eq!(record.user.id, "alice");
    assert!(
        record
            .accounts
            .iter()
            .all(|account| account.user_id == "alice")
    );
    assert_eq!(
        json!(
            record
                .accounts
                .iter()
                .map(|account| &account.account_id)
                .collect::<Vec<_>>()
        ),
        case["accounts"]
    );
    assert_eq!(json!(take(events)?), case["userEvents"]);
    let token = tokens
        .first()
        .ok_or_else(|| AuthError::internal("token missing"))?;
    let session = store
        .get_session(token)
        .await?
        .ok_or_else(|| AuthError::internal("session missing"))?;
    let user = store
        .get_user_by_id(session.user_id.typed()?)
        .await?
        .ok_or_else(|| AuthError::internal("user missing"))?;
    assert_eq!(session.user_id, user.id);
    assert_eq!(json!(take(events)?), case["sessionEvents"], "{case}");
    tokens.reverse();
    let sessions = store.get_session_snapshots(&tokens, false).await?;
    let mut users = Vec::new();
    for (session, cached) in sessions {
        let user = if let Some(data) = cached {
            data.user
        } else {
            store
                .get_user_by_id(session.user_id.typed()?)
                .await?
                .ok_or_else(|| AuthError::internal("user missing"))?
        };
        assert_eq!(session.user_id, user.id);
        users.push(user.id);
    }
    assert_eq!(json!(users), case["sessions"]);
    assert_eq!(json!(take(events)?), case["batchEvents"]);
    reject.store(true, Ordering::SeqCst);
    let Err(error) = store.get_account_owner("provider-1", "alice-1").await else {
        return Err(AuthError::internal("owner projection should reject"));
    };
    assert_eq!(error.instrumentation_message(), "user projection rejected");
    assert_eq!(take(events)?, ["account:alice-1", "user:alice"]);
    assert_eq!(
        store
            .get_account("provider-1", "alice-1")
            .await?
            .ok_or_else(|| AuthError::internal("account missing"))?
            .access_token,
        Some("alice-1".into())
    );
    Ok(())
}

#[tokio::test]
async fn normal_joins_match_pinned_memory_and_sqlite_contracts() -> AuthResult<()> {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/fallback-joins-upstream.json"))?;
    for case in cases {
        let events = Arc::new(Mutex::new(Vec::new()));
        let reject = Arc::new(AtomicBool::new(false));
        let config = config(case.get("limit").and_then(Value::as_f64), &events, &reject);
        if case.get("backend") == Some(&json!("sqlite")) {
            let database = Database::connect("sqlite::memory:")
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
            migrator::run_migrations(&database)
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
            run(
                &SeaOrmStore::<BundledSchema>::new(config, database),
                &case,
                &events,
                &reject,
            )
            .await?;
        } else {
            run(
                &EphemeralStore::new(Arc::new(config)),
                &case,
                &events,
                &reject,
            )
            .await?;
        }
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Return setup errors while retaining explicit regression assertions."
)]
async fn ephemeral_session_projection_preserves_core_aliases_and_stored_overrides() -> AuthResult<()>
{
    use better_auth_core::store::{SessionStore, UserStore};
    let mut config = AuthConfig::default();
    let _ = config.session.fields_mut().insert(
        "userAgent".into(),
        UserFieldConfig {
            field_name: Some("user_agent".into()),
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(|value| {
                    Ok(Some(json!({"observed":value})))
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let _ = config.session.fields_mut().insert(
        "label".into(),
        UserFieldConfig {
            field_name: Some("stored_label".into()),
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(|value| {
                    Ok(value
                        .map(|value| json!(format!("{}:out", value.as_str().unwrap_or_default()))))
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let store = EphemeralStore::new(Arc::new(config));
    let _ = store
        .create_user(CreateUser {
            id: Some("alice".into()),
            email: Some("alice@example.test".into()),
            name: Some("Alice".into()).into(),
            ..Default::default()
        })
        .await?;
    let session = store
        .create_session(CreateSession {
            user_id: "alice".into(),
            user_agent: Some("browser".into()),
            expires_at: chrono::Utc::now() + chrono::Duration::days(1),
            additional_fields: [("label".into(), json!("work"))].into_iter().collect(),
            ip_address: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?;
    let value = serde_json::to_value(&session)?;
    assert_eq!(value.get("userAgent"), Some(&json!({"observed":"browser"})));
    assert_eq!(value.get("label"), Some(&json!("work:out")));
    assert!(value.get("activeTeamId").is_none());
    assert!(value.get("stored_label").is_none());
    let updated = store
        .update_session_fields(
            &session.token,
            [
                ("userAgent".into(), json!("updated")),
                ("label".into(), json!("home")),
            ]
            .into_iter()
            .collect(),
        )
        .await?
        .ok_or_else(|| AuthError::internal("session update missing"))?;
    let value = serde_json::to_value(updated)?;
    assert_eq!(value.get("userAgent"), Some(&json!({"observed":"updated"})));
    assert_eq!(value.get("label"), Some(&json!("home:out")));
    let value = serde_json::to_value(store.get_session(&session.token).await?)?;
    assert_eq!(value.get("userAgent"), Some(&json!({"observed":"updated"})));
    assert_eq!(value.get("label"), Some(&json!("home:out")));
    Ok(())
}

#[derive(Clone)]
struct Provider;

#[async_trait::async_trait]
impl better_auth::plugins::oauth::OAuthIdTokenVerifier for Provider {
    async fn verify_id_token(
        &self,
        _: &str,
        _: Option<&str>,
        _: Option<better_auth_core::NativeRequest<'_>>,
    ) -> Result<bool, String> {
        Ok(true)
    }
}

#[async_trait::async_trait]
impl better_auth::plugins::oauth::OAuthUserInfoHandler for Provider {
    async fn get_user_info(
        &self,
        _: better_auth::plugins::oauth::OAuthUserInfoRequest,
    ) -> AuthResult<Option<better_auth::plugins::oauth::OAuthUserInfoResponse>> {
        Ok(Some(better_auth::plugins::oauth::OAuthUserInfoResponse {
            user: better_auth::plugins::oauth::OAuthUserInfo {
                id: "alice-google".into(),
                email: Some("alice@example.test".into()).into(),
                name: Some("Alice".into()).into(),
                email_verified: Some(true).into(),
                image: None,
                additional_fields: Default::default(),
            },
            data: json!({"sub":"alice-google","email":"alice@example.test","email_verified":true}),
        }))
    }
}

async fn oauth_read_error<S: AuthSchema>(
    store: Arc<dyn AuthStore<S>>,
    config: AuthConfig,
    events: &Events,
    reject: &AtomicBool,
    owned: bool,
) -> AuthResult<()> {
    use better_auth::plugins::oauth::{OAuthPlugin, OAuthProvider};
    let mut provider = OAuthProvider::google("fixture", "fixture");
    provider.verify_id_token = Some(Arc::new(Provider));
    provider.get_user_info = Some(Arc::new(Provider));
    let auth = better_auth::BetterAuth::new(config)
        .store_arc(store.clone())
        .plugin(OAuthPlugin::new().add_provider("google", provider))
        .build()
        .await?;
    let _ = store
        .create_user(CreateUser {
            id: Some("alice".into()),
            email: Some("alice@example.test".into()),
            name: Some("Alice".into()).into(),
            email_verified: Some(true),
            username: Some(Some("alice".into())),
            ..Default::default()
        })
        .await?;
    let provider_id = if owned { "google" } else { "other" };
    let account_id = if owned { "alice-google" } else { "alice-0" };
    let _ = store
        .create_account(CreateAccount {
            user_id: "alice".into(),
            provider_id: provider_id.into(),
            account_id: account_id.into(),
            access_token: Some("original".into()).into(),
            ..Default::default()
        })
        .await?;
    let _ = take(events)?;
    reject.store(true, Ordering::SeqCst);
    let mut request =
        better_auth_core::AuthRequest::new(better_auth_core::HttpMethod::Post, "/sign-in/social");
    request.body = Some(serde_json::to_vec(
        &json!({"provider":"google","idToken":{"token":"valid-fixture-token","accessToken":"replacement"}}),
    )?);
    let _ = request
        .headers
        .insert("content-type".into(), "application/json".into());
    let response = auth.handle_request(request).await?;
    assert_eq!(response.status, 302);
    assert_eq!(
        response.headers.get("location").map(String::as_str),
        Some("http://localhost:3000/api/auth/error?error=internal_server_error")
    );
    assert_eq!(
        take(events)?,
        if owned {
            ["account:original", "user:alice"]
        } else {
            ["user:alice", "account:original"]
        }
    );
    if !owned {
        assert!(store.get_account("google", "alice-google").await?.is_none());
    }
    reject.store(false, Ordering::SeqCst);
    let account = store
        .get_account(provider_id, account_id)
        .await?
        .ok_or_else(|| AuthError::internal("account missing"))?;
    assert_eq!(account.access_token, Some("original".into()));
    Ok(())
}

#[tokio::test]
async fn oauth_owner_projection_failure_precedes_token_write() -> AuthResult<()> {
    for sqlite in [false, true] {
        for owned in [false, true] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let reject = Arc::new(AtomicBool::new(false));
            let user_reject = if owned {
                reject.clone()
            } else {
                Arc::new(AtomicBool::new(false))
            };
            let mut config = config(None, &events, &user_reject).base_url("http://localhost:3000");
            if !owned {
                let captured_events = events.clone();
                let captured_reject = reject.clone();
                let field = config
                    .account
                    .additional_fields
                    .get_mut("accessToken")
                    .ok_or_else(|| AuthError::internal("field missing"))?;
                field.transform.get_or_insert_default().output =
                    Some(UserFieldTransform::new(move |value| {
                        captured_events
                            .lock()
                            .map_err(|error| AuthError::internal(error.to_string()))?
                            .push(format!(
                                "account:{}",
                                value
                                    .as_ref()
                                    .and_then(Value::as_str)
                                    .unwrap_or("undefined")
                            ));
                        if captured_reject.load(Ordering::SeqCst) {
                            return Err(AuthError::internal("account projection rejected"));
                        }
                        Ok(value)
                    }));
            }
            if sqlite {
                let database = Database::connect("sqlite::memory:")
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                migrator::run_migrations(&database)
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                oauth_read_error(
                    Arc::new(SeaOrmStore::<BundledSchema>::new(config.clone(), database)),
                    config,
                    &events,
                    &reject,
                    owned,
                )
                .await?;
            } else {
                oauth_read_error(
                    Arc::new(EphemeralStore::new(Arc::new(config.clone()))),
                    config,
                    &events,
                    &reject,
                    owned,
                )
                .await?;
            }
        }
    }
    Ok(())
}
