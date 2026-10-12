#![expect(
    clippy::panic_in_result_fn,
    reason = "OAuth flow regressions assert native error identity, branch order, cookies, and committed rows."
)]

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResult, CreateAccount, CreateUser, FieldFunction,
    FieldMap, FieldValue, Headers, HttpMethod, RequestHookContext, RequestMeta,
    store::{
        EphemeralStore, StatelessSchema,
        database_hooks::{
            DatabaseHookContext, DatabaseHookControl, DatabaseHookUpdate, DatabaseHooks,
        },
        schema::EntityRole,
    },
};

use super::super::{
    handlers::decode_account_cookie,
    providers::{OAuthProvider, OAuthTokenSet, OAuthUserInfo},
    resolved::ResolvedProvider,
};
use super::{
    OAuthSignInError, OAuthSignInOptions, ProcessOAuthUserResult, process_oauth_sign_in,
    token_account,
};
use crate::plugins::test_helpers;

const EMAIL: &str = "owner@oauth-flow.test";

#[derive(Clone, Copy, Debug)]
enum Seed {
    Account,
    User,
    Empty,
}

struct Trace {
    active: AtomicBool,
    stop: &'static str,
    cancel: bool,
    failure: FieldValue,
    events: Mutex<Vec<(&'static str, bool)>>,
}

impl Trace {
    fn observe(
        &self,
        event: &'static str,
        context: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<bool> {
        if !self.active.load(Ordering::SeqCst) {
            return Ok(false);
        }
        let request = &context
            .request
            .as_ref()
            .ok_or_else(|| AuthError::internal("OAuth write lost request context"))?
            .request;
        let headers = Headers::from_field_value(&request.response_headers_value()?)?;
        let cookie_name = context
            .config
            .auth_cookie("account_data", Default::default())
            .name;
        let cookie = headers
            .get_all("set-cookie")
            .any(|value| value.starts_with(&format!("{cookie_name}=")));
        self.events
            .lock()
            .map_err(|_| AuthError::internal("OAuth write trace lock poisoned"))?
            .push((event, cookie));
        if event == self.stop {
            if self.cancel {
                return Ok(true);
            }
            return Err(AuthError::from_thrown(self.failure.clone()));
        }
        Ok(false)
    }

    fn events(&self) -> AuthResult<Vec<(&'static str, bool)>> {
        Ok(self
            .events
            .lock()
            .map_err(|_| AuthError::internal("OAuth write trace lock poisoned"))?
            .clone())
    }
}

#[better_auth_core::database_hooks]
impl DatabaseHooks<StatelessSchema> for Trace {
    async fn before_create_user(
        &self,
        _: &mut FieldMap,
        context: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        let _ = self.observe("user.create", context)?;
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn before_create_account(
        &self,
        _: &mut CreateAccount,
        context: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookControl> {
        Ok(if self.observe("account.create", context)? {
            DatabaseHookControl::Cancel
        } else {
            DatabaseHookControl::Continue
        })
    }

    async fn before_update_account(
        &self,
        _: &mut FieldMap,
        context: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        Ok(if self.observe("account.update", context)? {
            DatabaseHookUpdate::Cancel
        } else {
            DatabaseHookUpdate::Continue
        })
    }

    async fn before_create_session(
        &self,
        _: &mut FieldMap,
        context: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        let _ = self.observe("session.create", context)?;
        Ok(DatabaseHookUpdate::Continue)
    }
}

async fn context(
    seed: Seed,
    trace: Arc<Trace>,
) -> AuthResult<(AuthContext<StatelessSchema>, Arc<EphemeralStore>)> {
    let mut config = test_helpers::create_test_config();
    config.account.store_account_cookie = Some(true);
    {
        let better_auth_core::LoggerSource::Config(logger_options) = &mut config.logger else {
            return Err(AuthError::config(
                "Fixture requires authored logger options",
            ));
        };
        logger_options.disabled = Some(true);
    }
    let config = Arc::new(config);
    let store = Arc::new(EphemeralStore::new(config.clone()).with_hooks(vec![trace.clone()]));
    let context = test_helpers::initialize_test_context(config, store.clone(), &[]).await?;
    if !matches!(seed, Seed::Empty) {
        let user = context
            .database
            .create_user(CreateUser {
                id: Some("owner".into()),
                email: Some(EMAIL.into()),
                name: Some("Stored owner".into()).into(),
                email_verified: Some(true),
                ..Default::default()
            })
            .await?;
        if matches!(seed, Seed::Account) {
            let _ = context
                .database
                .create_account(CreateAccount {
                    id: "linked-account".into(),
                    user_id: user.id,
                    provider_id: "google".into(),
                    account_id: "provider-owner".into(),
                    access_token: Some("old-access".to_owned()).into(),
                    ..Default::default()
                })
                .await?;
        }
    }
    trace.active.store(true, Ordering::SeqCst);
    Ok((context, store))
}

fn trace(stop: &'static str, cancel: bool, failure: FieldValue) -> Arc<Trace> {
    Arc::new(Trace {
        active: AtomicBool::new(false),
        stop,
        cancel,
        failure,
        events: Mutex::default(),
    })
}

async fn sign_in(
    request: &AuthRequest,
    context: &AuthContext<StatelessSchema>,
) -> Result<ProcessOAuthUserResult, OAuthSignInError> {
    better_auth_core::with_request_hook_context_value(
        RequestHookContext::from_request(request)?,
        process_oauth_sign_in(
            "google",
            &ResolvedProvider {
                config: OAuthProvider::google("client", "secret"),
                generic: None,
            },
            &OAuthUserInfo {
                additional_fields: FieldMap::new(),
                id: "provider-owner".into(),
                email: Some(EMAIL.to_owned()).into(),
                name: Some("Provider owner".to_owned()).into(),
                image: None,
                email_verified: Some(true).into(),
            }
            .into_native(),
            &token_account(
                "google",
                &"provider-owner".into(),
                &OAuthTokenSet {
                    access_token: Some("new-access".into()).into(),
                    ..Default::default()
                }
                .fields()
                .into(),
            )?,
            OAuthSignInOptions {
                request,
                profile: None,
                body: serde_json::Value::Null,
                disable_sign_up: false,
                override_user_info: false,
                callback_url: "/",
                email_verification: None,
            },
            &RequestMeta::from_request_with_config(request, &context.config.advanced.ip_address),
            context,
        ),
    )
    .await
}

fn raw_error() -> FieldValue {
    FieldMap::from([
        ("name".into(), "APIError".into()),
        ("status".into(), "BAD_REQUEST".into()),
        ("statusCode".into(), 400.0.into()),
        (
            "body".into(),
            FieldMap::from([
                ("code".into(), "OAUTH_WRITE_REJECTED".into()),
                ("message".into(), "OAuth write rejected".into()),
            ])
            .into(),
        ),
    ])
    .into()
}

fn assert_raw(
    result: Result<ProcessOAuthUserResult, OAuthSignInError>,
    raw: &FieldValue,
) -> AuthResult<OAuthSignInError> {
    match result {
        Err(OAuthSignInError::Auth(error)) => {
            assert!(
                error
                    .raw_value()
                    .is_some_and(|value| value.strict_equals(raw))
            );
            Ok(OAuthSignInError::Auth(error))
        }
        _ => Err(AuthError::internal(
            "OAuth flow replaced the original write error",
        )),
    }
}

fn account_cookie(
    request: &AuthRequest,
    context: &AuthContext<StatelessSchema>,
) -> AuthResult<Option<super::super::state::AccountCookiePayload>> {
    let headers = request.take_response_headers()?;
    let cookies = headers.get_all("set-cookie").collect::<Vec<_>>();
    let account_name = context
        .config
        .auth_cookie("account_data", Default::default())
        .name;
    assert!(
        cookies
            .iter()
            .all(|cookie| cookie.starts_with(&format!("{account_name}=")))
    );
    let mut cookie_request = AuthRequest::new(HttpMethod::Get, "/account-info");
    let _ = cookie_request.headers.insert(
        "cookie".into(),
        cookies
            .into_iter()
            .filter_map(|cookie| cookie.split(';').next())
            .collect::<Vec<_>>()
            .join("; "),
    );
    decode_account_cookie(&cookie_request, &context.config)
}

#[tokio::test]
async fn account_update_cancellation_stops_session_after_queuing_the_new_token_cookie()
-> AuthResult<()> {
    let hooks = trace("account.update", true, FieldValue::Undefined);
    let (context, store) = context(Seed::Account, hooks.clone()).await?;
    let request = AuthRequest::new(HttpMethod::Post, "/sign-in/social");
    assert!(matches!(sign_in(&request, &context).await,
        Err(OAuthSignInError::Generic(message)) if message == "unable to update account"));
    assert_eq!(hooks.events()?, [("account.update", true)]);
    assert!(store.storage_rows(EntityRole::Session)?.is_empty());
    assert!(request.new_session()?.is_none());
    let stored = store.storage_rows(EntityRole::Account)?;
    assert_eq!(stored.len(), 1);
    assert_eq!(
        stored.first().and_then(|row| row.get("accessToken")),
        Some(&"old-access".into())
    );
    let cookie = account_cookie(&request, &context)?
        .ok_or_else(|| AuthError::internal("Account update discarded its queued cookie"))?;
    assert_eq!(cookie.id.field_value(), "linked-account".into());
    assert_eq!(cookie.access_token.field_value(), "new-access".into());
    Ok(())
}

#[tokio::test]
async fn account_write_errors_keep_raw_identity_until_callback_url_conversion() -> AuthResult<()> {
    for seed in [Seed::Account, Seed::User] {
        let conversions = Arc::new(Mutex::new(Vec::new()));
        let raw = raw_error();
        let body = raw.model_property("body")?;
        let body = body
            .as_object()
            .ok_or_else(|| AuthError::internal("Missing OAuth error body"))?;
        for (field, result) in [
            ("code", "OAUTH_WRITE_REJECTED"),
            ("message", "original description"),
        ] {
            let conversions = conversions.clone();
            let body_for_code = body.clone();
            let value: FieldValue = FieldMap::from([(
                "toString".into(),
                FieldFunction::contextual(move |_, _| {
                    conversions
                        .lock()
                        .map_err(|_| AuthError::internal("OAuth conversion trace lock poisoned"))?
                        .push(field);
                    if field == "code" {
                        body_for_code.set("message", "changed description".into())?;
                    }
                    Ok(result.into())
                })
                .into(),
            )])
            .into();
            body.set(field, value)?;
        }
        let stop = if matches!(seed, Seed::Account) {
            "account.update"
        } else {
            "account.create"
        };
        let hooks = trace(stop, false, raw.clone());
        let (context, store) = context(seed, hooks.clone()).await?;
        let request = AuthRequest::new(HttpMethod::Get, "/callback/google");
        let error = assert_raw(sign_in(&request, &context).await, &raw)?;
        assert!(
            conversions
                .lock()
                .map_err(|_| AuthError::internal("OAuth conversion trace lock poisoned"))?
                .is_empty()
        );
        assert_eq!(hooks.events()?, [(stop, matches!(seed, Seed::Account))]);
        assert_eq!(
            error.redirect_parts()?,
            (
                "OAUTH_WRITE_REJECTED".into(),
                Some("original description".into())
            )
        );
        assert_eq!(
            *conversions
                .lock()
                .map_err(|_| AuthError::internal("OAuth conversion trace lock poisoned"))?,
            ["code", "message"]
        );
        let _ = body.delete("code")?;
        assert_eq!(body.get("message")?, Some("changed description".into()));
        assert!(store.storage_rows(EntityRole::Session)?.is_empty());
        assert_eq!(store.storage_rows(EntityRole::User)?.len(), 1);
        assert_eq!(
            store.storage_rows(EntityRole::Account)?.len(),
            usize::from(matches!(seed, Seed::Account))
        );
        assert_eq!(
            account_cookie(&request, &context)?.is_some(),
            matches!(seed, Seed::Account)
        );
    }
    Ok(())
}

#[tokio::test]
async fn session_failure_preserves_each_branch_account_cookie_and_committed_records()
-> AuthResult<()> {
    for seed in [Seed::Account, Seed::User, Seed::Empty] {
        let raw = raw_error();
        let hooks = trace("session.create", false, raw.clone());
        let (context, store) = context(seed, hooks.clone()).await?;
        let request = AuthRequest::new(HttpMethod::Post, "/sign-in/social");
        let _ = assert_raw(sign_in(&request, &context).await, &raw)?;
        let expected = match seed {
            Seed::Account => vec![("account.update", true), ("session.create", true)],
            Seed::User => vec![("account.create", false), ("session.create", true)],
            Seed::Empty => vec![
                ("user.create", false),
                ("account.create", false),
                ("session.create", true),
            ],
        };
        assert_eq!(hooks.events()?, expected, "{seed:?}");
        assert!(request.new_session()?.is_none());
        assert!(store.storage_rows(EntityRole::Session)?.is_empty());
        let users = store.storage_rows(EntityRole::User)?;
        let accounts = store.storage_rows(EntityRole::Account)?;
        assert_eq!(users.len(), 1);
        assert_eq!(accounts.len(), 1);
        let user = users
            .first()
            .ok_or_else(|| AuthError::internal("Committed OAuth user missing"))?;
        let account = accounts
            .first()
            .ok_or_else(|| AuthError::internal("Committed OAuth account missing"))?;
        assert_eq!(account.get("userId"), user.get("id"));
        assert_eq!(account.get("accessToken"), Some(&"new-access".into()));
        let cookie = account_cookie(&request, &context)?
            .ok_or_else(|| AuthError::internal("Session failure discarded the account cookie"))?;
        assert_eq!(Some(&cookie.user_id.field_value()), user.get("id"));
        assert_eq!(cookie.account_id.field_value(), "provider-owner".into());
        assert_eq!(cookie.access_token.field_value(), "new-access".into());
    }
    Ok(())
}
