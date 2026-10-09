#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Email OTP regressions assert native callback, cookie, and storage values while setup errors propagate"
)]

use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{
    AuthError, AuthInitContext, AuthPlugin, AuthRoute, AuthSchema, CreateSession, CreateUser,
    CreateVerification, FieldMap, FieldValue, HttpMethod,
    config::{CookieCacheConfig, FieldTransforms, UserFieldConfig, UserFieldTransform},
    id::IdGeneration,
    store::{
        EphemeralStore, StatelessSchema,
        database_hooks::{DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks},
    },
    wire::UserView,
};
use chrono::Utc;
use serde_json::json;
use std::sync::Mutex;

use crate::plugins::{
    email_verification::{EmailVerificationCallbacks, EmailVerificationPlugin},
    test_helpers::{create_test_config, initialize_test_context},
};

const EMAIL: &str = "owner@native-otp.test";
const IDENTIFIER: &str = "email-verification-otp-owner@native-otp.test";
type Calls = Arc<Mutex<Vec<(&'static str, FieldValue)>>>;

struct CancelUpdate(bool);

#[better_auth_core::database_hooks]
impl<S: AuthSchema> DatabaseHooks<S> for CancelUpdate {
    async fn before_update_user(
        &self,
        _: &mut FieldMap,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        Ok(if self.0 {
            DatabaseHookUpdate::Cancel
        } else {
            DatabaseHookUpdate::Continue
        })
    }
}

#[async_trait::async_trait]
impl<S: AuthSchema> AuthPlugin<S> for CancelUpdate {
    fn name(&self) -> &'static str {
        "email-otp-update-cancellation"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![]
    }
    async fn on_init(&self, ctx: &mut AuthInitContext<S>) -> AuthResult<()> {
        ctx.register_database_hook(Arc::new(Self(self.0)));
        Ok(())
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

struct Fixture {
    ctx: AuthContext<StatelessSchema>,
    user: UserView,
    calls: Calls,
}

impl Fixture {
    async fn new(cancel: bool, auto_sign_in: bool, numeric_id: bool) -> AuthResult<Self> {
        let calls = Calls::default();
        let before = calls.clone();
        let after = calls.clone();
        let legacy: better_auth_core::email::EmailVerificationHook = Arc::new(|_| {
            Box::pin(async {
                Err(AuthError::internal(
                    "Typed lifecycle must replace the legacy hook",
                ))
            })
        });
        let verification = EmailVerificationPlugin::new()
            .auto_sign_in_after_verification(auto_sign_in)
            .before_email_verification(legacy.clone())
            .after_email_verification(legacy)
            .callbacks(
                EmailVerificationCallbacks::<StatelessSchema>::default()
                    .before(move |user, endpoint| {
                        assert_eq!(endpoint.request.unwrap().path(), "/email-otp/verify-email");
                        let store = endpoint.auth.database.clone();
                        let user = user.clone();
                        let before = before.clone();
                        Ok(Some(Box::pin(async move {
                            assert!(
                                store
                                    .get_verification_including_expired(IDENTIFIER)
                                    .await?
                                    .is_none()
                            );
                            before.lock().unwrap().push(("before", user));
                            Ok(())
                        })))
                    })
                    .after(move |user, endpoint| {
                        assert_eq!(endpoint.request.unwrap().path(), "/email-otp/verify-email");
                        after.lock().unwrap().push(("after", user.clone()));
                        Ok(None)
                    }),
            );
        let mut config = create_test_config();
        config.session.disable_session_refresh = Some(true);
        config.session.cookie_cache = Some(CookieCacheConfig {
            enabled: Some(true),
            ..Default::default()
        });
        if numeric_id {
            config.advanced.database.generate_id = Some(IdGeneration::Serial);
            let _ = config.user.fields_mut().insert(
                "id".into(),
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        input: None,
                        output: Some(UserFieldTransform::new(|_| Ok(1.0.into()))),
                    }),
                    ..Default::default()
                },
            );
        }
        let config = Arc::new(config);
        let ctx = initialize_test_context(
            config.clone(),
            Arc::new(EphemeralStore::new(config)),
            &[&verification, &CancelUpdate(cancel)],
        )
        .await?;
        let user = ctx
            .database
            .create_user(CreateUser::new().with_email(EMAIL))
            .await?;
        let _ = ctx
            .database
            .create_verification(CreateVerification {
                identifier: IDENTIFIER.to_owned().into(),
                value: "123456:0".to_owned().into(),
                expires_at: (Utc::now() + Duration::minutes(5)).into(),
                ..Default::default()
            })
            .await?;
        Ok(Self { ctx, user, calls })
    }

    async fn request(&self, has_session: bool) -> AuthResult<AuthRequest> {
        let mut request = AuthRequest::new(HttpMethod::Post, "/email-otp/verify-email");
        request.body = Some(serde_json::to_vec(
            &json!({"email":EMAIL.to_uppercase(), "otp":"123456"}),
        )?);
        let _ = request
            .headers
            .insert("content-type".into(), "application/json".into());
        if has_session {
            let session = self
                .ctx
                .database
                .create_session(CreateSession {
                    user_id: self.user.id.clone(),
                    expires_at: (Utc::now() + Duration::hours(1)).into(),
                    inherited_fields: Default::default(),
                    additional_fields: Default::default(),
                    ip_address: None,
                    user_agent: None,
                    impersonated_by: None,
                    active_organization_id: None,
                })
                .await?;
            let cookie = format!(
                "{}={}",
                self.ctx
                    .config
                    .auth_cookie("session_token", Default::default())
                    .name,
                better_auth_core::utils::cookie_utils::sign_cookie_value(
                    session.token.typed()?,
                    self.ctx.config.signing_secret()
                )
            );
            let _ = request.headers.insert("cookie".into(), cookie);
        }
        Ok(request)
    }

    async fn assert_consumed(&self) -> AuthResult<()> {
        assert!(
            self.ctx
                .database
                .get_verification_including_expired(IDENTIFIER)
                .await?
                .is_none()
        );
        Ok(())
    }
}

#[tokio::test]
async fn cancelled_verification_keeps_null_callbacks_and_consumes_otp_before_session_branches()
-> AuthResult<()> {
    for auto_sign_in in [false, true] {
        for has_session in [false, true] {
            let fixture = Fixture::new(true, auto_sign_in, false).await?;
            let request = fixture.request(has_session).await?;
            let result = EmailOtpPlugin::new()
                .verify_email(&request, &fixture.ctx)
                .await;
            if auto_sign_in || has_session {
                let field = if auto_sign_in { "id" } else { "emailVerified" };
                let error = result.err().unwrap();
                assert!(matches!(&error, AuthError::TypeError(_)));
                assert_eq!(
                    error.to_string(),
                    format!("Cannot read properties of null (reading '{field}')")
                );
            } else {
                let response = result?;
                assert_eq!(response.status, 200);
                assert_eq!(
                    response.body.json()?,
                    Some(json!({"status":true, "token":null, "user":null}))
                );
            }
            assert_eq!(
                request.native_session_snapshot()?.is_some(),
                has_session && !auto_sign_in
            );
            assert!(request.new_session()?.is_none());
            fixture.assert_consumed().await?;
            let stored = fixture
                .ctx
                .database
                .get_user_by_email(EMAIL)
                .await?
                .unwrap();
            assert_eq!(stored.email_verified.field_value(), false.into());
            assert_eq!(
                *fixture.calls.lock().unwrap(),
                [
                    ("before", FieldMap::from(fixture.user.clone()).into()),
                    ("after", FieldValue::Null),
                ]
            );
            let replay = EmailOtpPlugin::new()
                .verify_email(&fixture.request(false).await?, &fixture.ctx)
                .await;
            assert!(matches!(
                replay,
                Err(AuthError::Upstream {
                    code: "INVALID_OTP",
                    ..
                })
            ));
            assert_eq!(fixture.calls.lock().unwrap().len(), 2);
        }
    }
    Ok(())
}

#[tokio::test]
async fn numeric_user_id_updates_and_refreshes_the_selected_native_session_cache() -> AuthResult<()>
{
    let fixture = Fixture::new(false, false, true).await?;
    assert_eq!(fixture.user.id.field_value(), 1.0.into());
    let request = fixture.request(true).await?;
    let selected = fixture
        .ctx
        .native_session(&request, better_auth_core::session::SessionRead::Cached)
        .await?
        .unwrap();
    assert_eq!(selected.user_property("id")?, &FieldValue::from(1.0));
    assert_eq!(
        selected.user_property("emailVerified")?,
        &FieldValue::from(false)
    );
    let _ = request.take_response_headers()?;
    let response = EmailOtpPlugin::new()
        .verify_email(&request, &fixture.ctx)
        .await?;
    assert_eq!(response.status, 200);
    fixture.assert_consumed().await?;
    let stored = fixture
        .ctx
        .database
        .get_user_by_email(EMAIL)
        .await?
        .unwrap();
    assert_eq!(stored.id.field_value(), 1.0.into());
    assert_eq!(stored.email_verified.field_value(), true.into());
    assert_eq!(
        response.body.json()?,
        Some(
            json!({"status":true, "token":null, "user":FieldMap::from(fixture.ctx.user_view(&stored).await?)})
        )
    );
    assert_eq!(
        *fixture.calls.lock().unwrap(),
        [
            ("before", FieldMap::from(fixture.user.clone()).into()),
            ("after", FieldMap::from(stored).into()),
        ]
    );
    let cache_name = fixture
        .ctx
        .config
        .auth_cookie("session_data", Default::default())
        .name;
    let headers = request.take_response_headers()?;
    let refreshed = headers
        .get_all("set-cookie")
        .map(|value| {
            cookie::Cookie::parse(value.as_str())
                .map_err(|error| AuthError::internal(error.to_string()))
        })
        .collect::<AuthResult<Vec<_>>>()?;
    let cache = refreshed
        .iter()
        .find(|cookie| cookie.name() == cache_name)
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(cache.value())
            .map_err(|error| AuthError::internal(error.to_string()))?,
    )?;
    let mut expected_cache_user = selected
        .public_user(&fixture.ctx.config.user)?
        .enumerable_fields();
    let _ = expected_cache_user.insert("emailVerified".into(), true.into());
    assert_eq!(
        payload.get("session").unwrap().get("user"),
        Some(&serde_json::to_value(expected_cache_user)?)
    );
    assert!(request.new_session()?.is_none());
    Ok(())
}
