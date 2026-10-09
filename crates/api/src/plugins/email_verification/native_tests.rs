#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "The native verification regressions assert complete callback, storage, and read-order results"
)]

use super::*;
use better_auth_core::{
    AuthInitContext, AuthPlugin, AuthRoute, AuthSchema, CreateSession, CreateUser, FieldMap,
    FieldValue, HttpMethod,
    config::{FieldTransforms, UserFieldConfig, UserFieldTransform},
    store::{
        EphemeralStore, StatelessSchema,
        database_hooks::{DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks},
    },
};
use chrono::Utc;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

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
        "email-native-update"
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

fn verify_request(
    ctx: &AuthContext<StatelessSchema>,
    update: Option<(&str, &str)>,
) -> AuthResult<AuthRequest> {
    let token = token::create_email_verification_token(
        ctx.config.signing_secret(),
        "owner@native-email.test",
        update.map(|(email, _)| email),
        Duration::hours(1),
        update.map(|(_, request)| request),
    )?;
    let mut req = AuthRequest::new(HttpMethod::Get, "/verify-email");
    req.query = Some(serde_json::json!({"token":token}));
    Ok(req)
}

fn raw_email_request(
    ctx: &AuthContext<StatelessSchema>,
    email: &str,
    update: Option<(&FieldValue, &FieldValue)>,
) -> AuthResult<AuthRequest> {
    let now = Utc::now().timestamp();
    let claims = token::EmailVerificationClaims {
        email: email.into(),
        update_to: update.map(|(email, _)| email.clone()),
        request_type: update.map(|(_, request)| request.clone()),
        iat: Some(now as f64),
        exp: Some((now + 3600) as f64),
    };
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(ctx.config.signing_secret().as_bytes()),
    )?;
    let mut req = AuthRequest::new(HttpMethod::Get, "/verify-email");
    req.query = Some(serde_json::json!({"token":token}));
    Ok(req)
}

#[tokio::test]
async fn verification_uses_email_selector_and_preserves_raw_nullable_hooks() -> AuthResult<()> {
    for cancel in [false, true] {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let before = calls.clone();
        let after = calls.clone();
        let id_output_calls = Arc::new(AtomicUsize::new(0));
        let id_outputs = id_output_calls.clone();
        let mut config = crate::plugins::test_helpers::create_test_config();
        let _ = config.user.fields_mut().insert(
            "id".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    input: None,
                    output: Some(UserFieldTransform::new(move |_| {
                        let _ = id_outputs.fetch_add(1, Ordering::SeqCst);
                        Ok(17.0.into())
                    })),
                }),
                ..Default::default()
            },
        );
        let _ = config.user.fields_mut().insert(
            "name".into(),
            UserFieldConfig {
                returned: Some(false),
                ..Default::default()
            },
        );
        let config = Arc::new(config);
        let writer: Arc<dyn better_auth_core::store::AuthStore<StatelessSchema>> =
            Arc::new(EphemeralStore::new(config.clone()));
        let before_writer = writer.clone();
        let plugin = EmailVerificationPlugin::new()
            .before_email_verification(Arc::new(move |user| {
                before.lock().unwrap().push(("before", user.clone()));
                let writer = before_writer.clone();
                let user = user.clone();
                Box::pin(async move {
                    let _ = writer
                        .update_user_by_id_value(
                            user.model_property("id")?,
                            better_auth_core::UpdateUser {
                                additional_fields: FieldMap::from([(
                                    "id".into(),
                                    "moved-by-verification-hook".into(),
                                )]),
                                ..Default::default()
                            },
                        )
                        .await?;
                    Ok(())
                })
            }))
            .after_email_verification(Arc::new(move |user| {
                after.lock().unwrap().push(("after", user.clone()));
                Box::pin(async { Ok(()) })
            }));
        let ctx = crate::plugins::test_helpers::initialize_test_context(
            config.clone(),
            writer,
            &[&plugin, &CancelUpdate(cancel)],
        )
        .await?;
        let user = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email("owner@native-email.test")
                    .with_name("Hidden callback field"),
            )
            .await?;
        assert!(user.id.field_value().as_str().is_some());
        assert_eq!(id_output_calls.load(Ordering::SeqCst), 0);
        assert!(!FieldMap::from(ctx.user_view(&user).await?).contains_key("name"));
        let request = raw_email_request(&ctx, "OWNER@NATIVE-EMAIL.TEST", None)?;
        let response = plugin.handle_verify_email(&request, &ctx).await?;
        assert_eq!(
            response.body.json()?,
            Some(serde_json::json!({"status":true,"user":null}))
        );
        assert!(request.new_session()?.is_none());
        let stored = ctx
            .database
            .get_user_by_email("owner@native-email.test")
            .await?
            .unwrap();
        assert_eq!(
            stored.email_verified.field_value(),
            FieldValue::Bool(!cancel)
        );
        assert_eq!(stored.id.field_value(), "moved-by-verification-hook".into());
        assert!(
            ctx.database
                .get_user_by_id_value(&user.id.field_value())
                .await?
                .is_none()
        );
        assert_eq!(id_output_calls.load(Ordering::SeqCst), 0);
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "before");
        assert_eq!(
            calls[0].1.as_object().unwrap().get("name")?,
            Some("Hidden callback field".into())
        );
        assert_eq!(calls[1].0, "after");
        if cancel {
            assert!(calls[1].1.is_null());
        } else {
            let fields = calls[1].1.as_object().unwrap().snapshot_fields()?;
            assert_eq!(fields.get("name"), Some(&"Hidden callback field".into()));
            assert_eq!(fields.get("emailVerified"), Some(&true.into()));
            assert_eq!(fields.get("id"), Some(&"moved-by-verification-hook".into()));
        }
    }
    Ok(())
}

#[tokio::test]
async fn change_email_normalizes_storage_and_tokens_but_preserves_session_ownership()
-> AuthResult<()> {
    for request_type in [
        "change-email-confirmation",
        "change-email-verification",
        "legacy",
    ] {
        for has_session in [false, true] {
            let delivered = Arc::new(Mutex::new(Vec::new()));
            let deliveries = delivered.clone();
            let verified = Arc::new(Mutex::new(Vec::new()));
            let verifications = verified.clone();
            let plugin = EmailVerificationPlugin::new()
                .after_email_verification(Arc::new(move |user| {
                    verifications.lock().unwrap().push(user.clone());
                    Box::pin(async { Ok(()) })
                }))
                .callbacks(EmailVerificationCallbacks::<StatelessSchema>::send(
                    move |message, _| {
                        deliveries.lock().unwrap().push(message.clone());
                        Ok(None)
                    },
                ));
            let config = Arc::new(
                crate::plugins::test_helpers::create_test_config().disable_session_refresh(true),
            );
            let ctx = crate::plugins::test_helpers::initialize_test_context(
                config.clone(),
                Arc::new(EphemeralStore::new(config)),
                &[&plugin],
            )
            .await?;
            let user = ctx
                .database
                .create_user(CreateUser::new().with_email("owner@native-email.test"))
                .await?;
            let original = FieldValue::from(FieldMap::from(user.clone()));
            let mut req = raw_email_request(
                &ctx,
                "OWNER@NATIVE-EMAIL.TEST",
                Some((&"NEW@NATIVE-EMAIL.TEST".into(), &request_type.into())),
            )?;
            if has_session {
                let session = ctx
                    .database
                    .create_session(CreateSession {
                        user_id: user.id.clone(),
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
                    ctx.config
                        .auth_cookie("session_token", Default::default())
                        .name,
                    better_auth_core::utils::cookie_utils::sign_cookie_value(
                        session.token.typed()?,
                        ctx.config.signing_secret(),
                    ),
                );
                let _ = req.headers.insert("cookie".into(), cookie);
            }
            let response = plugin.on_request(&req, &ctx).await;
            let stored = ctx
                .database
                .get_user_by_id_value(&user.id.field_value())
                .await?
                .unwrap();
            let original_email_present = ctx
                .database
                .get_user_by_email("owner@native-email.test")
                .await?
                .is_some();
            let stored = FieldValue::from(FieldMap::from(stored));
            if has_session {
                assert!(matches!(
                    response,
                    Err(AuthError::Upstream {
                        code: "INVALID_USER",
                        ..
                    })
                ));
                assert_eq!(stored, original);
                assert!(req.new_session()?.is_none());
                assert!(verified.lock().unwrap().is_empty());
                assert!(delivered.lock().unwrap().is_empty());
                continue;
            }
            let response = response?.unwrap();
            assert_eq!(response.status, 200);
            let delivered = delivered.lock().unwrap();
            let verified = verified.lock().unwrap();
            if request_type == "change-email-confirmation" {
                assert_eq!(
                    response.body.json()?,
                    Some(serde_json::json!({"status":true}))
                );
                assert_eq!(stored, original);
                assert!(req.new_session()?.is_none());
                assert!(verified.is_empty());
                assert_eq!(delivered.len(), 1);
                let mut expected = original.enumerable_fields()?;
                let _ = expected.insert("email".into(), "NEW@NATIVE-EMAIL.TEST".into());
                assert_eq!(delivered[0].user, FieldValue::from(expected));
                let claims = token::decode_email_verification_token(
                    ctx.config.signing_secret(),
                    &delivered[0].token,
                )?;
                assert_eq!(claims.email, "owner@native-email.test");
                assert_eq!(claims.update_to, Some("new@native-email.test".into()));
                assert_eq!(
                    claims.request_type,
                    Some("change-email-verification".into())
                );
                continue;
            }
            let is_verified = request_type == "change-email-verification";
            let fields = stored.as_object().unwrap().snapshot_fields()?;
            assert_eq!(fields.get("email"), Some(&"new@native-email.test".into()));
            assert_eq!(fields.get("emailVerified"), Some(&is_verified.into()));
            assert!(!original_email_present);
            let mut expected = original.enumerable_fields()?;
            let _ = expected.insert("email".into(), "NEW@NATIVE-EMAIL.TEST".into());
            let _ = expected.insert("emailVerified".into(), is_verified.into());
            assert_eq!(req.new_session()?.unwrap().user, FieldValue::from(expected));
            if is_verified {
                assert_eq!(*verified, [stored]);
                assert!(delivered.is_empty());
            } else {
                assert!(verified.is_empty());
                assert_eq!(delivered.len(), 1);
                assert_eq!(delivered[0].user, stored);
                let claims = token::decode_email_verification_token(
                    ctx.config.signing_secret(),
                    &delivered[0].token,
                )?;
                assert_eq!(claims.email, "new@native-email.test");
                assert!(claims.update_to.is_none());
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn native_change_email_strings_survive_storage_delivery_and_follow_up_tokens()
-> AuthResult<()> {
    let update_to = FieldValue::parse_json(r#""NEW\ud800@EXAMPLE.TEST""#)?;
    let lowercase = FieldValue::parse_json(r#""new\ud800@example.test""#)?;
    for request_type in [
        FieldValue::from("change-email-confirmation"),
        FieldValue::from("change-email-verification"),
        FieldValue::parse_json(r#""legacy\udc00""#)?,
    ] {
        let messages = Arc::new(Mutex::new(Vec::new()));
        let delivered = messages.clone();
        let plugin =
            EmailVerificationPlugin::new().callbacks(
                EmailVerificationCallbacks::<StatelessSchema>::send(move |message, _| {
                    delivered.lock().unwrap().push(message.clone());
                    Ok(None)
                }),
            );
        let config = Arc::new(crate::plugins::test_helpers::create_test_config());
        let ctx = crate::plugins::test_helpers::initialize_test_context(
            config.clone(),
            Arc::new(EphemeralStore::new(config)),
            &[&plugin],
        )
        .await?;
        let user = ctx
            .database
            .create_user(CreateUser::new().with_email("owner@native-email.test"))
            .await?;
        let req = raw_email_request(
            &ctx,
            "owner@native-email.test",
            Some((&update_to, &request_type)),
        )?;
        assert_eq!(plugin.on_request(&req, &ctx).await?.unwrap().status, 200);
        let stored = ctx
            .database
            .get_user_by_id_value(&user.id.field_value())
            .await?
            .unwrap();
        let messages = messages.lock().unwrap();
        if request_type.as_str() == Some("change-email-confirmation") {
            assert_eq!(
                stored.email.field_value(),
                FieldValue::from("owner@native-email.test")
            );
            assert!(req.new_session()?.is_none());
            assert_eq!(messages.len(), 1);
            assert_eq!(
                messages[0].user.as_object().unwrap().get("email")?,
                Some(update_to.clone())
            );
            let claims = token::decode_email_verification_token(
                ctx.config.signing_secret(),
                &messages[0].token,
            )?;
            assert_eq!(claims.email, "owner@native-email.test");
            assert_eq!(claims.update_to, Some(lowercase.clone()));
            assert_eq!(
                claims.request_type,
                Some("change-email-verification".into())
            );
        } else {
            let verified = request_type.as_str() == Some("change-email-verification");
            assert_eq!(stored.email.field_value(), lowercase);
            assert_eq!(
                stored.email_verified.field_value(),
                FieldValue::Bool(verified)
            );
            let session = req.new_session()?.unwrap();
            assert_eq!(session.user_property("email")?, update_to);
            assert_eq!(
                session.user_property("emailVerified")?,
                FieldValue::Bool(verified)
            );
            if verified {
                assert!(messages.is_empty());
            } else {
                assert_eq!(messages.len(), 1);
                assert_eq!(
                    messages[0].user.as_object().unwrap().get("email")?,
                    Some(lowercase.clone())
                );
                let bytes = crate::plugins::jwt::verify_hs256_raw(
                    &messages[0].token,
                    ctx.config.signing_secret(),
                )?;
                let payload = FieldValue::parse_json(std::str::from_utf8(&bytes).unwrap())?;
                assert_eq!(
                    payload.as_object().unwrap().get("email")?,
                    Some(lowercase.clone())
                );
                assert!(matches!(
                    token::decode_email_verification_token(
                        ctx.config.signing_secret(),
                        &messages[0].token
                    ),
                    Err(AuthError::Serialization(_))
                ));
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn typed_lifecycle_awaits_failures_and_replaces_legacy_hooks() -> AuthResult<()> {
    for fail_before in [true, false] {
        let calls = Arc::new(AtomicUsize::new(0));
        let before_calls = calls.clone();
        let after_calls = calls.clone();
        let legacy: better_auth_core::email::EmailVerificationHook = Arc::new(|_| {
            Box::pin(async { Err(AuthError::internal("Legacy verification hook must not run")) })
        });
        let plugin = EmailVerificationPlugin::new()
            .before_email_verification(legacy.clone())
            .after_email_verification(legacy)
            .callbacks(
                EmailVerificationCallbacks::<StatelessSchema>::default()
                    .before(move |user, endpoint| {
                        assert_eq!(
                            user.as_object().unwrap().get("emailVerified")?,
                            Some(false.into())
                        );
                        assert_eq!(endpoint.request.unwrap().path(), "/verify-email");
                        let calls = before_calls.clone();
                        Ok(Some(Box::pin(async move {
                            tokio::task::yield_now().await;
                            assert_eq!(calls.fetch_add(1, Ordering::SeqCst), 0);
                            if fail_before {
                                Err(AuthError::internal("Typed before failed"))
                            } else {
                                Ok(())
                            }
                        })))
                    })
                    .after(move |user, endpoint| {
                        assert_eq!(
                            user.as_object().unwrap().get("emailVerified")?,
                            Some(true.into())
                        );
                        assert_eq!(endpoint.request.unwrap().path(), "/verify-email");
                        let calls = after_calls.clone();
                        Ok(Some(Box::pin(async move {
                            tokio::task::yield_now().await;
                            assert_eq!(calls.fetch_add(1, Ordering::SeqCst), 1);
                            Err(AuthError::internal("Typed after failed"))
                        })))
                    }),
            );
        let config = Arc::new(crate::plugins::test_helpers::create_test_config());
        let ctx = crate::plugins::test_helpers::initialize_test_context(
            config.clone(),
            Arc::new(EphemeralStore::new(config)),
            &[&plugin],
        )
        .await?;
        let _ = ctx
            .database
            .create_user(CreateUser::new().with_email("owner@native-email.test"))
            .await?;
        let request = verify_request(&ctx, None)?;
        let error = plugin.on_request(&request, &ctx).await.err().unwrap();
        assert_eq!(
            error.to_string(),
            if fail_before {
                "Internal server error: Typed before failed"
            } else {
                "Internal server error: Typed after failed"
            }
        );
        let user = ctx
            .database
            .get_user_by_email("owner@native-email.test")
            .await?
            .unwrap();
        assert_eq!(
            user.email_verified.field_value(),
            FieldValue::Bool(!fail_before)
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            if fail_before { 1 } else { 2 }
        );
        assert!(request.new_session()?.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn session_reads_follow_token_branches_and_caught_failures_use_anonymous_flow()
-> AuthResult<()> {
    let rejecting = Arc::new(AtomicBool::new(false));
    let reads = Arc::new(AtomicUsize::new(0));
    let api_error = Arc::new(AtomicBool::new(false));
    let api_failure = api_error.clone();
    let reject = rejecting.clone();
    let count = reads.clone();
    let mut config = crate::plugins::test_helpers::create_test_config();
    let _ = config.session.fields_mut().insert(
        "userId".into(),
        UserFieldConfig {
            references: Some(better_auth_core::config::UserFieldReference {
                model: "user".into(),
                field: "id".into(),
                ..Default::default()
            }),
            transform: Some(FieldTransforms {
                input: None,
                output: Some(UserFieldTransform::new(move |value| {
                    if reject.load(Ordering::SeqCst) {
                        let _ = count.fetch_add(1, Ordering::SeqCst);
                        if api_failure.load(Ordering::SeqCst) {
                            Err(AuthError::Upstream {
                                status: 500,
                                code: "SESSION_POLICY_REJECTED",
                                message: "Session policy rejected",
                            })
                        } else {
                            Err(AuthError::internal("native session read rejected"))
                        }
                    } else {
                        Ok(value)
                    }
                })),
            }),
            ..Default::default()
        },
    );
    let config = Arc::new(config);
    let plugin = EmailVerificationPlugin::new().callbacks(EmailVerificationCallbacks::<
        StatelessSchema,
    >::send(|_, _| Ok(None)));
    let ctx = crate::plugins::test_helpers::initialize_test_context(
        config.clone(),
        Arc::new(EphemeralStore::new(config)),
        &[&plugin],
    )
    .await?;
    let user = ctx
        .database
        .create_user(CreateUser::new().with_email("owner@native-email.test"))
        .await?;
    let session = ctx
        .database
        .create_session(CreateSession {
            user_id: user.id,
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
        ctx.config
            .auth_cookie("session_token", Default::default())
            .name,
        better_auth_core::utils::cookie_utils::sign_cookie_value(
            session.token.typed()?,
            ctx.config.signing_secret()
        )
    );
    rejecting.store(true, Ordering::SeqCst);
    let mut req = verify_request(&ctx, None)?;
    let _ = req.headers.insert("cookie".into(), cookie.clone());
    let response = plugin.on_request(&req, &ctx).await?.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    let mut req = verify_request(&ctx, None)?;
    req.query = Some(serde_json::json!({"token":"invalid"}));
    let _ = req.headers.insert("cookie".into(), cookie.clone());
    let result = handlers::verify_email_core(
        &types::VerifyEmailQuery {
            token: "invalid".into(),
            callback_url: None,
        },
        &EmailVerificationConfig::default(),
        &req,
        &ctx,
    )
    .await;
    assert!(matches!(
        result,
        Err(AuthError::Upstream {
            code: "INVALID_TOKEN",
            ..
        })
    ));
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    let mut req = AuthRequest::new(HttpMethod::Post, "/send-verification-email");
    let _ = req.headers.insert("cookie".into(), cookie);
    let result = handlers::send_verification_email_core(
        &types::SendVerificationEmailRequest {
            email: "owner@native-email.test".into(),
            callback_url: None,
        },
        &req,
        &EmailVerificationConfig::default(),
        &ctx,
    )
    .await;
    assert!(result?.status);
    assert!(req.native_session_snapshot()?.is_none());
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    api_error.store(true, Ordering::SeqCst);
    let direct = ctx
        .session_manager()
        .resolve_native_for_endpoint(&req, better_auth_core::session::SessionRead::Cached)
        .await;
    assert!(matches!(
        direct,
        Err(AuthError::Upstream {
            status: 500,
            code: "SESSION_POLICY_REJECTED",
            ..
        })
    ));
    assert_eq!(reads.load(Ordering::SeqCst), 2);
    assert!(
        ctx.native_session(&req, better_auth_core::session::SessionRead::Cached)
            .await?
            .is_none()
    );
    assert_eq!(reads.load(Ordering::SeqCst), 3);
    Ok(())
}

#[tokio::test]
async fn caught_session_failure_discards_nested_cookie_headers_but_keeps_outer_headers()
-> AuthResult<()> {
    use better_auth_core::{
        config::{CookieCacheConfig, CookieCacheStrategy},
        session::{NativeSessionData, SessionRead},
    };

    let rejecting = Arc::new(AtomicBool::new(false));
    let reads = Arc::new(AtomicUsize::new(0));
    let reject = rejecting.clone();
    let count = reads.clone();
    let mut config = crate::plugins::test_helpers::create_test_config();
    config.session.cookie_cache = Some(CookieCacheConfig {
        enabled: Some(true),
        strategy: Some(CookieCacheStrategy::Compact),
        ..Default::default()
    });
    let _ = config.session.fields_mut().insert(
        "userId".into(),
        UserFieldConfig {
            references: Some(better_auth_core::config::UserFieldReference {
                model: "user".into(),
                field: "id".into(),
                ..Default::default()
            }),
            transform: Some(FieldTransforms {
                input: None,
                output: Some(UserFieldTransform::new(move |value| {
                    if reject.load(Ordering::SeqCst) {
                        let _ = count.fetch_add(1, Ordering::SeqCst);
                        Err(AuthError::internal(
                            "Session output failed after cache expiry",
                        ))
                    } else {
                        Ok(value)
                    }
                })),
            }),
            ..Default::default()
        },
    );
    let config = Arc::new(config);
    let ctx = crate::plugins::test_helpers::initialize_test_context(
        config.clone(),
        Arc::new(EphemeralStore::new(config)),
        &[],
    )
    .await?;
    let user = ctx
        .database
        .create_user(CreateUser::new().with_email("expired-cache@native-email.test"))
        .await?;
    let session = ctx
        .database
        .create_session(CreateSession {
            user_id: user.id.clone(),
            expires_at: (Utc::now() + Duration::hours(1)).into(),
            inherited_fields: Default::default(),
            additional_fields: Default::default(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?;
    let mut expired_cache = session.clone();
    expired_cache.expires_at = (Utc::now() - Duration::minutes(1)).into();
    let issuance = AuthRequest::new(HttpMethod::Post, "/sign-in/email");
    ctx.session_manager()
        .set_native_session_cookie(
            &issuance,
            NativeSessionData {
                user: FieldMap::from(user).into(),
                session: expired_cache,
            },
            None,
        )
        .await?;
    let cookie = issuance
        .take_response_headers()?
        .get_all("set-cookie")
        .map(|header| header.split(';').next().unwrap().to_owned())
        .collect::<Vec<_>>()
        .join("; ");
    let cache_name = format!(
        "{}=",
        ctx.config
            .auth_cookie("session_data", Default::default())
            .name
    );
    assert!(cookie.contains(&cache_name));
    rejecting.store(true, Ordering::SeqCst);

    for nested in [true, false] {
        let mut req = AuthRequest::new(
            HttpMethod::Get,
            if nested {
                "/send-verification-email"
            } else {
                "/get-session"
            },
        );
        let _ = req.headers.insert("cookie".into(), cookie.clone());
        req.set_response_header("x-outer", "kept")?;
        req.set_response_header("cache-control", "private")?;
        req.append_response_header("set-cookie", "outer-marker=1; Path=/".into())?;
        if nested {
            assert!(
                ctx.native_session(&req, SessionRead::Cached)
                    .await?
                    .is_none()
            );
            assert!(req.native_session_snapshot()?.is_none());
        } else {
            let result = ctx
                .session_manager()
                .resolve_native_for_endpoint(&req, SessionRead::Cached)
                .await;
            assert!(matches!(
                result,
                Err(AuthError::Upstream {
                    status: 500,
                    code: "FAILED_TO_GET_SESSION",
                    ..
                })
            ));
        }
        let headers = req.take_response_headers()?;
        assert_eq!(headers.get("x-outer").map(String::as_str), Some("kept"));
        assert_eq!(
            headers.get("cache-control").map(String::as_str),
            Some("private")
        );
        let cookies = headers
            .get_all("set-cookie")
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert!(cookies.contains(&"outer-marker=1; Path=/"));
        if nested {
            assert_eq!(cookies, ["outer-marker=1; Path=/"]);
        } else {
            assert!(
                cookies
                    .iter()
                    .any(|cookie| cookie.starts_with(&cache_name) && cookie.contains("Max-Age=0"))
            );
        }
        assert!(req.new_session()?.is_none());
    }
    assert_eq!(reads.load(Ordering::SeqCst), 2);
    rejecting.store(false, Ordering::SeqCst);
    assert_eq!(
        ctx.database.get_session(session.token.typed()?).await?,
        Some(session)
    );
    Ok(())
}
