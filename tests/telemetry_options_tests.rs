#![expect(
    clippy::panic_in_result_fn,
    reason = "tests propagate setup failures and use assertions for upstream behavior comparisons"
)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_auth::__private_core::{
    self as core, AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute,
};
use better_auth::observability::{
    LogArgument, LogLevel, LogSink, TelemetryEvent, TelemetryTransport,
};
use better_auth::plugins::{
    EmailPasswordPlugin, EmailVerificationPlugin, PasswordManagementPlugin, UserManagementPlugin,
};
use better_auth::{AuthConfig, AuthError, AuthResult, BetterAuth, database_hooks};
use core::config::{CookieCacheConfig, CookieCacheStrategy, SameSite};
use core::middleware::{
    EndpointRateLimit, RateLimitConfig, RateLimitDecision, RateLimitStorage, RateLimitStorageKind,
};
use core::store::{
    StatelessSchema,
    database_hooks::{DatabaseHookContext, DatabaseHookControl, DatabaseHookUpdate, DatabaseHooks},
};
use serde_json::Value;

type S = StatelessSchema;

#[path = "telemetry_options/network.rs"]
mod network;

#[path = "telemetry_options/id.rs"]
mod id;

#[path = "telemetry_options/trusted.rs"]
mod trusted;

#[path = "telemetry_options/plugins.rs"]
mod plugins;

#[path = "telemetry_options/cache.rs"]
mod cache;

#[derive(Default)]
struct Reports(Mutex<Vec<Value>>);
#[async_trait]
impl TelemetryTransport for Reports {
    async fn send(&self, event: &TelemetryEvent) -> AuthResult<()> {
        self.0
            .lock()
            .map_err(|_| AuthError::internal("report capture poisoned"))?
            .push(
                event
                    .payload
                    .get("config")
                    .cloned()
                    .ok_or_else(|| AuthError::internal("init report has no config"))?,
            );
        Ok(())
    }
}
impl Reports {
    fn config(&self) -> AuthResult<Value> {
        let reports = self
            .0
            .lock()
            .map_err(|_| AuthError::internal("report capture poisoned"))?;
        match reports.as_slice() {
            [report] => Ok(report.clone()),
            _ => Err(AuthError::internal("expected exactly one init report")),
        }
    }
}
struct InitOrder(Arc<Reports>);
#[async_trait]
impl AuthPlugin<S> for InitOrder {
    fn name(&self) -> &'static str {
        "init-order"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_init(&self, _: &mut AuthInitContext<S>) -> AuthResult<()> {
        drop(self.0.config()?);
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
struct Callbacks;
impl LogSink for Callbacks {
    fn log(&self, _: LogLevel, _: LogArgument<'_>, _: &[LogArgument<'_>]) {}
}
impl core::api_error::ApiErrorHandler<S> for Callbacks {
    fn on_error(
        &self,
        _: &AuthError,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<core::api_error::ApiErrorTask>> {
        Err(AuthError::internal(
            "telemetry must not invoke API error callbacks",
        ))
    }
}
#[async_trait]
impl RateLimitStorage for Callbacks {
    async fn consume(&self, _: &str, _: EndpointRateLimit) -> AuthResult<RateLimitDecision> {
        Err(AuthError::internal(
            "telemetry must not invoke rate-limit storage",
        ))
    }
}
fn configuration() -> (AuthConfig, Arc<Reports>) {
    let reports = Arc::new(Reports::default());
    let mut config = AuthConfig::new("telemetry-config-secret-more-than-32-characters")
        .base_url("https://example.test");
    config.telemetry.enabled = true;
    config.telemetry.track = Some(reports.clone());
    (config, reports)
}
fn oracle(name: &str) -> AuthResult<Value> {
    let value: Value = serde_json::from_str(include_str!("fixtures/telemetry-options-1.7.6.json"))?;
    value
        .get(name)
        .cloned()
        .ok_or_else(|| AuthError::internal(format!("missing oracle case: {name}")))
}

#[tokio::test]
async fn configured_options_keep_omission_after_storage_normalization() -> AuthResult<()> {
    for name in ["omitted", "explicitDefaults", "explicitValues"] {
        let expected = oracle(name)?;
        let expected_session = if name == "omitted" {
            cache::oracle("stateless-omitted")?
        } else {
            expected.clone()
        };
        let (mut config, reports) = configuration();
        if name != "omitted" {
            let custom = name == "explicitValues";
            config.session.expires_in =
                Some(chrono::Duration::seconds(if custom { 30 } else { 604800 }));
            config.session.update_age =
                Some(chrono::Duration::seconds(if custom { 0 } else { 86400 }));
            config.session.disable_session_refresh = Some(custom);
            config.session.store_session_in_database = Some(custom);
            config.session.preserve_session_in_database = Some(custom);
            config.account.encrypt_oauth_tokens = Some(custom);
            config.account.update_account_on_sign_in = Some(!custom);
            config.account.account_linking.enabled = Some(!custom);
            config.account.account_linking.allow_unlinking_all = Some(custom);
            config.account.account_linking.update_user_info_on_link = Some(custom);
            config.verification.disable_cleanup = Some(custom);
            config.api_error.throw_errors = Some(custom);
            config.logger.disabled = Some(custom);
            config.logger.level = Some(if custom {
                LogLevel::Error
            } else {
                LogLevel::Warn
            });
            config.session.cookie_cache = Some(CookieCacheConfig {
                enabled: Some(custom),
                max_age: Some(chrono::Duration::seconds(if custom { 900 } else { 300 })),
                strategy: Some(if custom {
                    CookieCacheStrategy::Jwe
                } else {
                    CookieCacheStrategy::Compact
                }),
                ..Default::default()
            });
            config.advanced.disable_csrf_check = Some(custom);
            config.advanced.use_secure_cookies = Some(custom);
            config.advanced.database.default_find_many_limit =
                Some(if custom { 0.0 } else { 100.0 });
            config.advanced.default_cookie_attributes.secure = Some(custom);
            config.advanced.default_cookie_attributes.http_only = Some(!custom);
            config.advanced.default_cookie_attributes.same_site = Some(if custom {
                SameSite::None
            } else {
                SameSite::Lax
            });
            config.advanced.default_cookie_attributes.path =
                Some(if custom { "/auth" } else { "/" }.into());
            if custom {
                config.logger.log = Some(Arc::new(Callbacks));
                config.session.fresh_age = Some(chrono::Duration::zero());
                config.advanced.cookie_prefix = Some(String::new());
                config.advanced.default_cookie_attributes.domain = Some("example.test".into());
                config.api_error.error_url = Some("https://example.test/error".into());
            }
        }
        let mut builder = BetterAuth::stateless(config).plugin(InitOrder(reports.clone()));
        if name != "omitted" {
            let mut rate = RateLimitConfig::new().storage(if name == "explicitValues" {
                RateLimitStorageKind::Secondary
            } else {
                RateLimitStorageKind::Memory
            });
            let custom = name == "explicitValues";
            rate.enabled = Some(custom);
            rate.window = Some(if custom { 0.0 } else { 10.0 });
            rate.max_requests = Some(if custom { 0.0 } else { 100.0 });
            builder = if name == "explicitValues" {
                builder
                    .rate_limit(rate.custom_storage(Arc::new(Callbacks)))
                    .on_api_error(Arc::new(Callbacks))
            } else {
                builder.rate_limit(rate)
            };
        }
        let _auth = builder.build().await?;
        let actual = reports.config()?;
        assert_eq!(
            actual.get("session"),
            expected_session.get("session"),
            "{name}"
        );
        for path in [
            "/logger",
            "/account",
            "/verification",
            "/advanced/useSecureCookies",
            "/advanced/disableCSRFCheck",
            "/advanced/cookiePrefix",
            "/advanced/cookieAttributes",
            "/advanced/crossSubDomainCookies/domain",
            "/rateLimit/storage",
            "/rateLimit/customStorage",
            "/rateLimit/enabled",
            "/onAPIError",
        ] {
            assert_eq!(
                actual.pointer(path),
                expected.pointer(path),
                "{name}: {path}"
            );
        }
        for path in ["/rateLimit/window", "/rateLimit/max"] {
            assert_eq!(
                actual.pointer(path).map(Value::as_f64),
                expected.pointer(path).map(Value::as_f64),
                "{name}: {path}"
            );
        }
        // JavaScript numbers do not distinguish an integer from an equal floating-point value.
        let limit = "/advanced/database/defaultFindManyLimit";
        assert_eq!(
            actual.pointer(limit).map(Value::as_f64),
            expected.pointer(limit).map(Value::as_f64),
            "{name}: {limit}"
        );
        assert_eq!(
            actual.get("emailVerification"),
            expected.get("emailVerification")
        );
        assert!(!actual.to_string().contains("telemetry-config-secret"));
    }
    Ok(())
}

#[tokio::test]
async fn session_duration_metadata_preserves_fractional_seconds() -> AuthResult<()> {
    let (mut config, reports) = configuration();
    config.session.expires_in = Some(chrono::Duration::milliseconds(12_250));
    config.session.update_age = Some(chrono::Duration::milliseconds(500));
    config.session.fresh_age = Some(chrono::Duration::milliseconds(-125));
    config.session.cookie_cache = Some(CookieCacheConfig {
        max_age: Some(chrono::Duration::nanoseconds(1)),
        ..Default::default()
    });
    let _auth = BetterAuth::stateless(config).build().await?;
    assert_eq!(
        reports.config()?.get("session"),
        cache::oracle("stateless-fractionalDurations")?.get("session")
    );
    Ok(())
}

#[tokio::test]
async fn plugin_scalars_preserve_omitted_and_explicit_options() -> AuthResult<()> {
    for name in ["pluginOmitted", "pluginDefaults", "pluginValues"] {
        let expected = oracle(name)?;
        let (config, reports) = configuration();
        let mut password = EmailPasswordPlugin::new();
        let mut verification = EmailVerificationPlugin::new();
        let mut reset = PasswordManagementPlugin::new();
        let mut user = UserManagementPlugin::new();
        if name != "pluginOmitted" {
            let custom = name == "pluginValues";
            password = password
                .password_min_length(if custom { 12 } else { 8 })
                .password_max_length(if custom { 24 } else { 128 })
                .auto_sign_in(!custom);
            verification =
                verification.verification_token_expiry(chrono::Duration::seconds(if custom {
                    90
                } else {
                    3600
                }));
            reset = reset.reset_password_token_expires_in(if custom { 0 } else { 3600 });
            user = user.change_email_enabled(custom);
        }
        let _auth = BetterAuth::stateless(config)
            .plugin(password)
            .plugin(verification)
            .plugin(reset)
            .plugin(user)
            .build()
            .await?;
        let actual = reports.config()?;
        for path in [
            "/emailVerification",
            "/emailAndPassword",
            "/user/changeEmail",
        ] {
            assert_eq!(
                actual.pointer(path),
                expected.pointer(path),
                "{name}: {path}"
            );
        }
    }
    Ok(())
}

#[async_trait]
impl core::email::SendVerificationEmail for Callbacks {
    async fn send(&self, _: &core::wire::UserView, _: &str, _: &str) -> AuthResult<()> {
        Err(AuthError::internal(
            "telemetry must not invoke verification delivery",
        ))
    }
}
#[async_trait]
impl better_auth::plugins::password_management::SendResetPassword for Callbacks {
    async fn send(&self, _: &Value, _: &str, _: &str) -> AuthResult<()> {
        Err(AuthError::internal(
            "telemetry must not invoke reset delivery",
        ))
    }
}
#[async_trait]
impl better_auth::plugins::user_management::SendChangeEmailConfirmation for Callbacks {
    async fn send(&self, _: &core::wire::UserView, _: &str, _: &str, _: &str) -> AuthResult<()> {
        Err(AuthError::internal(
            "telemetry must not invoke confirmation delivery",
        ))
    }
}

#[tokio::test]
async fn plugin_callback_metadata_includes_typed_wrappers_before_init() -> AuthResult<()> {
    use better_auth::plugins::{
        email_verification::{EmailVerificationCallbacks, EmailVerificationConfig},
        password_management::{PasswordManagementCallbacks, PasswordManagementConfig},
        user_management::UserManagementCallbacks,
    };
    let expected = oracle("callbacks")?;
    for typed in [false, true] {
        let (config, reports) = configuration();
        let verification = EmailVerificationPlugin::with_config(EmailVerificationConfig {
            send_on_sign_up: Some(true),
            send_on_sign_in: true,
            auto_sign_in_after_verification: true,
            before_email_verification: Some(Arc::new(|_| {
                Box::pin(async { Err(AuthError::internal("must not invoke before hook")) })
            })),
            after_email_verification: Some(Arc::new(|_| {
                Box::pin(async { Err(AuthError::internal("must not invoke after hook")) })
            })),
            send_verification_email: (!typed)
                .then(|| Arc::new(Callbacks) as Arc<dyn core::email::SendVerificationEmail>),
            ..Default::default()
        });
        let reset = PasswordManagementPlugin::with_config(PasswordManagementConfig {
            revoke_sessions_on_password_reset: true,
            on_password_reset: Some(Arc::new(|_| {
                Box::pin(async { Err(AuthError::internal("must not invoke reset hook")) })
            })),
            send_reset_password: (!typed).then(|| {
                Arc::new(Callbacks)
                    as Arc<dyn better_auth::plugins::password_management::SendResetPassword>
            }),
            ..Default::default()
        });
        let user = UserManagementPlugin::new();
        let mut builder = BetterAuth::stateless(config)
            .plugin(
                EmailPasswordPlugin::new()
                    .enable_signup(false)
                    .require_email_verification(true)
                    .password_hasher(Arc::new(core::utils::password::ScryptPasswordHasher)),
            )
            .plugin(InitOrder(reports.clone()));
        if typed {
            builder =
                builder
                    .plugin(
                        verification.callbacks(EmailVerificationCallbacks::send(|_, _| {
                            Err(AuthError::internal(
                                "must not invoke typed verification sender",
                            ))
                        })),
                    )
                    .plugin(
                        reset.callbacks(PasswordManagementCallbacks::send_reset_password(
                            |_, _| Err(AuthError::internal("must not invoke typed reset sender")),
                        )),
                    )
                    .plugin(user.callbacks(
                        UserManagementCallbacks::new().change_email_confirmation(|_, _| {
                            Err(AuthError::internal(
                                "must not invoke typed confirmation sender",
                            ))
                        }),
                    ));
        } else {
            builder = builder
                .plugin(verification)
                .plugin(reset)
                .plugin(user.send_change_email_confirmation(Arc::new(Callbacks)));
        }
        let _auth = builder.build().await?;
        let actual = reports.config()?;
        assert_eq!(
            actual.get("plugins"),
            Some(&serde_json::json!(["init-order"]))
        );
        assert_eq!(
            actual.get("emailVerification"),
            expected.get("emailVerification")
        );
        assert_eq!(
            actual.pointer("/user/changeEmail"),
            expected.pointer("/user/changeEmail")
        );
        for field in [
            "enabled",
            "disableSignUp",
            "requireEmailVerification",
            "sendResetPassword",
            "onPasswordReset",
            "password",
            "revokeSessionsOnPasswordReset",
        ] {
            assert_eq!(
                actual.pointer(&format!("/emailAndPassword/{field}")),
                expected.pointer(&format!("/emailAndPassword/{field}")),
                "{field}, typed={typed}"
            );
        }
    }
    Ok(())
}

struct Hooks;
#[database_hooks]
impl DatabaseHooks<S> for Hooks {
    async fn before_create_user(
        &self,
        _: &mut core::CreateUser,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        Err(AuthError::internal("must not invoke hook"))
    }
    async fn after_update_user(
        &self,
        _: Option<&core::wire::UserView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        Err(AuthError::internal("must not invoke hook"))
    }
    async fn before_delete_user(
        &self,
        _: &core::wire::UserView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        Err(AuthError::internal("must not invoke hook"))
    }
    async fn after_create_session(
        &self,
        _: &core::wire::SessionView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        Err(AuthError::internal("must not invoke hook"))
    }
    async fn before_update_account(
        &self,
        _: &core::UpdateAccount,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<core::UpdateAccount>> {
        Err(AuthError::internal("must not invoke hook"))
    }
    async fn after_create_verification(
        &self,
        _: &core::wire::VerificationView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        Err(AuthError::internal("must not invoke hook"))
    }
}

struct PluginHooks;
#[database_hooks("plugin:telemetry-test")]
impl DatabaseHooks<S> for PluginHooks {
    async fn before_create_account(
        &self,
        _: &mut core::CreateAccount,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        Err(AuthError::internal("must not invoke plugin hook"))
    }
}

#[tokio::test]
async fn adapter_hook_projection_uses_declared_application_callbacks() -> AuthResult<()> {
    let (config, reports) = configuration();
    let _auth = BetterAuth::stateless(config)
        .database_hooks(vec![Arc::new(Hooks), Arc::new(PluginHooks)])
        .build()
        .await?;
    assert_eq!(
        reports.config()?.get("databaseHooks"),
        oracle("databaseHooks")?.get("databaseHooks")
    );
    Ok(())
}
