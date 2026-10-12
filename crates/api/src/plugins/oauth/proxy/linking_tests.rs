#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]
#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
//! Explicit proxy linking preserves thrown values and writes completed before a failure.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use better_auth_core::{
    ApiErrorInit, AuthConfig, AuthContext, AuthError, AuthRequest, AuthResult, CreateAccount,
    CreateVerification, FieldMap, FieldValue, HttpMethod,
    store::{
        EphemeralStore, StatelessSchema,
        database_hooks::{
            DatabaseHookContext, DatabaseHookControl, DatabaseHookUpdate, DatabaseHooks,
            DatabaseUpdateResult,
        },
        schema::EntityRole,
    },
    wire::AccountView,
};
use chrono::{Duration, Utc};
use serde_json::json;

use super::OAuthProxyPlugin;

const ORIGIN: &str = "http://preview.proxy-link.test";
const CALLBACK: &str = "http://preview.proxy-link.test/complete";
const SECRET: &str = "proxy-linking-native-errors-secret-at-least-thirty-two-characters";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Success,
    Before,
    After,
    Cancel,
}

struct Hooks {
    stage: Stage,
    armed: AtomicBool,
    thrown: FieldValue,
}

impl Hooks {
    fn fail(&self, stage: Stage) -> AuthResult<()> {
        if self.armed.load(Ordering::SeqCst) && self.stage == stage {
            return Err(AuthError::from_thrown(self.thrown.clone()));
        }
        Ok(())
    }
}

#[better_auth_core::database_hooks()]
impl DatabaseHooks<StatelessSchema> for Hooks {
    async fn before_create_account(
        &self,
        _: &mut CreateAccount,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookControl> {
        self.fail(Stage::Before)?;
        Ok(
            if self.armed.load(Ordering::SeqCst) && self.stage == Stage::Cancel {
                DatabaseHookControl::Cancel
            } else {
                DatabaseHookControl::Continue
            },
        )
    }

    async fn after_create_account(
        &self,
        _: Option<&AccountView>,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        self.fail(Stage::After)
    }

    async fn before_update_account(
        &self,
        _: &mut FieldMap,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.fail(Stage::Before)?;
        Ok(
            if self.armed.load(Ordering::SeqCst) && self.stage == Stage::Cancel {
                DatabaseHookUpdate::Cancel
            } else {
                DatabaseHookUpdate::Continue
            },
        )
    }

    async fn after_update_account(
        &self,
        _: DatabaseUpdateResult<&AccountView>,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        self.fail(Stage::After)
    }
}

async fn fixture(
    hooks: Arc<Hooks>,
    existing: bool,
) -> AuthResult<(
    Arc<AuthContext<StatelessSchema>>,
    Arc<EphemeralStore>,
    AuthRequest,
)> {
    let config = Arc::new(AuthConfig::new(SECRET).base_url(ORIGIN));
    let store = Arc::new(EphemeralStore::new(config.clone()).with_hooks(vec![hooks.clone()]));
    let context = AuthContext::new(config, store.clone())
        .expect("fixture context initializes")
        .initialize_request_context()
        .await?;
    if existing {
        let _ = context
            .database
            .create_account(CreateAccount {
                user_id: "owner".into(),
                account_id: "provider-owner".into(),
                provider_id: "google".into(),
                access_token: Some("old-access".to_owned()).into(),
                ..Default::default()
            })
            .await?;
    }
    let _ = context
        .database
        .create_verification(CreateVerification {
            identifier: "link-state".into(),
            value: json!({
                "callbackURL": CALLBACK,
                "codeVerifier": "verifier",
                "expiresAt": (Utc::now() + Duration::minutes(5)).timestamp_millis(),
                "link": {"userId": "owner", "email": "owner@example.test"},
            })
            .to_string()
            .into(),
            expires_at: (Utc::now() + Duration::minutes(5)).into(),
            ..Default::default()
        })
        .await?;
    let payload = json!({
        "userInfo": {
            "id": "provider-owner", "email": "owner@example.test",
            "name": "Owner", "emailVerified": true,
        },
        "account": {
            "providerId": "google", "accountId": "provider-owner",
            "accessToken": "new-access", "scope": "profile",
        },
        "state": "link-state", "callbackURL": CALLBACK,
        "timestamp": Utc::now().timestamp_millis(),
    });
    let mut request = AuthRequest::new(HttpMethod::Get, "/oauth-proxy-callback");
    request.query = Some(json!({
        "callbackURL": CALLBACK,
        "profile": crate::plugins::symmetric::encrypt(SECRET, &payload.to_string())?,
    }));
    hooks.armed.store(true, Ordering::SeqCst);
    Ok((context, store, request))
}

fn assert_state_consumed(store: &EphemeralStore, request: &AuthRequest) -> AuthResult<()> {
    assert!(store.storage_rows(EntityRole::Verification)?.is_empty());
    assert!(store.storage_rows(EntityRole::Session)?.is_empty());
    let headers = request.take_response_headers()?;
    let cookies: Vec<_> = headers.get_all("set-cookie").collect();
    assert_eq!(
        cookies,
        ["better-auth.state=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"]
    );
    Ok(())
}

#[tokio::test]
async fn explicit_linking_throws_original_errors_and_preserves_completed_writes() -> AuthResult<()>
{
    for existing in [false, true] {
        for stage in [Stage::Before, Stage::After] {
            for api_error in [false, true] {
                let thrown = if api_error {
                    AuthError::try_api_error(ApiErrorInit {
                        status: 409.into(),
                        body: FieldMap::from([
                            ("code".into(), "LINK_WRITE_REJECTED".into()),
                            ("message".into(), "original failure".into()),
                            ("extra".into(), 17.into()),
                        ])
                        .into(),
                        headers: FieldMap::from([("x-link-error".into(), "retained".into())])
                            .into(),
                        ..Default::default()
                    })?
                    .raw_value()
                    .cloned()
                    .ok_or_else(|| AuthError::internal("API error object missing"))?
                } else {
                    FieldMap::from([
                        ("name".into(), "Error".into()),
                        ("message".into(), "original failure".into()),
                    ])
                    .into()
                };
                let (context, store, request) = fixture(
                    Arc::new(Hooks {
                        stage,
                        armed: AtomicBool::new(false),
                        thrown: thrown.clone(),
                    }),
                    existing,
                )
                .await?;
                let error = OAuthProxyPlugin::new()
                    .complete(None, &request, &context)
                    .await
                    .err()
                    .ok_or_else(|| {
                        AuthError::internal("Proxy must throw the original hook error")
                    })?;
                assert!(
                    error
                        .raw_value()
                        .is_some_and(|value| value.strict_equals(&thrown))
                );
                let rows = store.storage_rows(EntityRole::Account)?;
                assert_eq!(rows.len(), usize::from(existing || stage == Stage::After));
                if let Some(row) = rows.first() {
                    assert_eq!(
                        row.get("accessToken"),
                        Some(&if stage == Stage::After {
                            "new-access".into()
                        } else {
                            "old-access".into()
                        })
                    );
                }
                assert_state_consumed(&store, &request)?;
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn explicit_linking_returns_native_redirects_for_success_and_create_cancellation()
-> AuthResult<()> {
    for existing in [false, true] {
        for stage in [Stage::Success, Stage::Cancel] {
            let (context, store, request) = fixture(
                Arc::new(Hooks {
                    stage,
                    armed: AtomicBool::new(false),
                    thrown: FieldValue::Undefined,
                }),
                existing,
            )
            .await?;
            let error = OAuthProxyPlugin::new()
                .complete(None, &request, &context)
                .await
                .err()
                .ok_or_else(|| AuthError::internal("Proxy must throw a native redirect"))?;
            assert!(error.is_found_redirect()?);
            let failed = !existing && stage == Stage::Cancel;
            let headers = better_auth_core::Headers::from_field_value(&error.headers_value()?)?;
            let location = if failed {
                format!("{ORIGIN}/api/auth/error?error=unable_to_link_account")
            } else {
                CALLBACK.to_owned()
            };
            assert_eq!(headers.get("location"), Some(&location));
            assert_eq!(
                store.storage_rows(EntityRole::Account)?.len(),
                usize::from(!failed)
            );
            assert_state_consumed(&store, &request)?;
        }
    }
    Ok(())
}
