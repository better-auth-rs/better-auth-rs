#![expect(
    clippy::panic_in_result_fn,
    reason = "The regression asserts logger ownership, hook snapshots, and callback continuation while setup failures propagate."
)]

use async_trait::async_trait;
use better_auth::{AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_api::plugins::captcha::{
    BotIdChecker, BotIdRequestValidator, BotIdVerification, CaptchaPlugin, CaptchaProvider,
};
use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute, FieldFunction, FieldMap,
    FieldObject, FieldValue, HttpMethod,
    endpoint_dispatch::EndpointDispatcher,
    hooks::current_request_hook_context,
    observability::logger,
    store::{EphemeralStore, StatelessSchema as S},
};
use serde_json::json;
use std::{
    future::Future,
    sync::{Arc, Mutex, MutexGuard},
    task::Poll,
    time::Duration,
};
use tokio::sync::Notify;

const ORIGIN_A: &str = "https://captcha-scope-a.test";
const ORIGIN_B: &str = "https://captcha-scope-b.test";
const CAPTCHA_ERROR: &str = "CAPTCHA verification service or callback failed";

fn lock<T>(mutex: &Mutex<T>) -> AuthResult<MutexGuard<'_, T>> {
    mutex
        .lock()
        .map_err(|_| AuthError::internal("Captcha observation lock poisoned"))
}

struct State {
    wait_at: &'static str,
    fail_at: Option<&'static str>,
    logs: Mutex<Vec<(&'static str, String, String)>>,
    started: Notify,
    release: Notify,
    completed: Notify,
    callback_error: FieldValue,
    catch_error: FieldValue,
}

impl State {
    fn new(wait_at: &'static str, fail_at: Option<&'static str>) -> Arc<Self> {
        Arc::new(Self {
            wait_at,
            fail_at,
            logs: Mutex::new(Vec::new()),
            started: Notify::new(),
            release: Notify::new(),
            completed: Notify::new(),
            callback_error: FieldMap::from([("owner".into(), "callback logger".into())]).into(),
            catch_error: FieldMap::from([("owner".into(), "captcha catch logger".into())]).into(),
        })
    }

    fn observe(&self, phase: &'static str) -> AuthResult<()> {
        let hook = current_request_hook_context()
            .ok_or_else(|| AuthError::internal("Bot ID callback lost the HTTP hook context"))?;
        assert!(hook.is_http);
        assert_eq!(hook.path.as_deref(), Some("/api/auth/probe"));
        assert_eq!(hook.request.path(), "/api/auth/probe");
        assert_eq!(hook.method, HttpMethod::Get);
        assert_eq!(hook.headers.get("x-scope"), Some(&"B request".to_owned()));
        assert!(hook.body.is_undefined());
        logger::current().info(phase, &[])
    }

    async fn wait(&self, phase: &'static str) {
        if self.wait_at == phase {
            self.started.notify_one();
            self.release.notified().await;
        }
    }

    fn config(self: &Arc<Self>, owner: &'static str, origin: &str) -> AuthResult<AuthConfig> {
        let options: FieldObject = FieldMap::from([
            ("level".into(), "info".into()),
            ("disableColors".into(), true.into()),
        ])
        .into();
        let expected: FieldValue = options.clone().into();
        let state = self.clone();
        options.set(
            "log",
            FieldFunction::contextual(move |receiver, arguments| {
                assert!(receiver.strict_equals(&expected));
                let [level, message] = arguments else {
                    return Err(AuthError::internal(
                        "Captcha callback log arguments changed",
                    ));
                };
                let level = level
                    .as_str()
                    .ok_or_else(|| AuthError::internal("Expected logger level"))?;
                let message = message
                    .as_str()
                    .ok_or_else(|| AuthError::internal("Expected logger message"))?;
                lock(&state.logs)?.push((owner, level.into(), message.into()));
                if state.fail_at == Some(message) {
                    return Err(AuthError::from_thrown(state.callback_error.clone()));
                }
                if state.fail_at.is_some() && message == CAPTCHA_ERROR {
                    return Err(AuthError::from_thrown(state.catch_error.clone()));
                }
                Ok(FieldValue::Undefined)
            })
            .into(),
        )?;
        let mut config =
            AuthConfig::new("captcha-logger-scope-secret-longer-than-thirty-two-characters")
                .base_url(origin);
        config.telemetry.enabled = false;
        config.logger = options.into();
        Ok(config)
    }
}

#[async_trait]
impl BotIdChecker for State {
    async fn check(&self) -> AuthResult<BotIdVerification> {
        self.observe("checker:enter")?;
        self.wait("checker").await;
        tokio::task::yield_now().await;
        self.observe("checker:resume")?;
        Ok(BotIdVerification {
            is_bot: true,
            is_verified_bot: Some(true),
            verified_bot_name: Some("scope probe".into()),
            verified_bot_category: None,
        })
    }
}

#[async_trait]
impl BotIdRequestValidator for State {
    async fn validate(
        &self,
        request: &AuthRequest,
        verdict: &BotIdVerification,
    ) -> AuthResult<bool> {
        assert_eq!(request.path(), "/api/auth/probe");
        assert_eq!(
            request.headers.get("x-scope"),
            Some(&"B request".to_owned())
        );
        assert!(verdict.is_bot);
        assert_eq!(verdict.is_verified_bot, Some(true));
        assert_eq!(verdict.verified_bot_name.as_deref(), Some("scope probe"));
        assert!(verdict.verified_bot_category.is_none());
        self.observe("validator:enter")?;
        self.wait("validator").await;
        tokio::task::yield_now().await;
        self.observe("validator:resume")?;
        self.completed.notify_one();
        Ok(true)
    }
}

struct Probe;

#[async_trait]
impl AuthPlugin<S> for Probe {
    fn name(&self) -> &'static str {
        "captcha-scope-probe"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::get("/probe", "probe")]
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        AuthResponse::json(200, &json!({"accepted":true})).map(Some)
    }
}

async fn fixture(state: &Arc<State>) -> AuthResult<(AuthContext<S>, BetterAuth<S>)> {
    let config = Arc::new(state.config("A", ORIGIN_A)?);
    let parent = AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config)))?;
    let child = BetterAuth::stateless(state.config("B", ORIGIN_B)?)
        .rate_limit(better_auth_core::middleware::RateLimitConfig {
            enabled: Some(false),
            ..Default::default()
        })
        .plugin(
            CaptchaPlugin::new(CaptchaProvider::VercelBotId {
                check_bot_id: state.clone(),
                validate_request: Some(state.clone()),
            })
            .endpoints(vec!["/probe".into()]),
        )
        .plugin(Probe)
        .build()
        .await?;
    Ok((parent, child))
}

async fn nested(parent: &AuthContext<S>, child: &BetterAuth<S>) -> AuthResult<AuthResponse> {
    let dispatcher = EndpointDispatcher::new(Arc::new(Vec::new()), Default::default(), []);
    dispatcher
        .native(
            AuthRequest::new(HttpMethod::Get, "/nested"),
            AuthRoute::get("/nested", "nested"),
            parent,
            |_, context| async move {
                assert!(context.current_request_context().is_some());
                let mut request = AuthRequest::new(HttpMethod::Get, "/api/auth/probe").with_url(
                    format!("{ORIGIN_B}/api/auth/probe")
                        .parse()
                        .map_err(|error| {
                            AuthError::internal(format!("Invalid test URL: {error}"))
                        })?,
                );
                let _ = request.headers.insert("x-scope".into(), "B request".into());
                let result = child.handle_request(request).await;
                assert!(context.current_request_context().is_some());
                assert!(child.context().current_request_context().is_none());
                let hook = current_request_hook_context()
                    .ok_or_else(|| AuthError::internal("Parent hook context was not restored"))?;
                assert!(!hook.is_http);
                assert_eq!(hook.path.as_deref(), Some("/nested"));
                result
            },
        )
        .await
}

#[tokio::test(start_paused = true)]
async fn bot_id_callbacks_keep_nested_logger_scope_after_await_and_timeout() -> AuthResult<()> {
    for wait_at in ["checker", "validator"] {
        for timeout in [false, true] {
            let state = State::new(wait_at, None);
            let (parent, child) = fixture(&state).await?;
            let mut operation = Box::pin(nested(&parent, &child));
            assert!(
                std::future::poll_fn(|cx| Poll::Ready(operation.as_mut().poll(cx)))
                    .await
                    .is_pending()
            );
            tokio::time::timeout(Duration::from_secs(1), state.started.notified())
                .await
                .map_err(|_| AuthError::internal("Bot ID callback did not reach its gate"))?;
            if timeout {
                tokio::time::advance(Duration::from_secs(10)).await;
            } else {
                state.release.notify_one();
            }
            let response = operation.await?;
            assert_eq!(response.status, if timeout { 500 } else { 200 });
            assert_eq!(
                response.body.json()?,
                Some(if timeout {
                    json!({"message":"Something went wrong","code":"UNKNOWN_ERROR"})
                } else {
                    json!({"accepted":true})
                })
            );
            assert!(parent.current_request_context().is_none());
            assert!(child.context().current_request_context().is_none());
            assert!(current_request_hook_context().is_none());
            state.release.notify_one();
            tokio::time::timeout(Duration::from_secs(1), state.completed.notified())
                .await
                .map_err(|_| {
                    AuthError::internal("Captcha timeout cancelled the application callback")
                })?;
            let mut expected = vec![
                ("A", "info".into(), "checker:enter".into()),
                ("A", "info".into(), "checker:resume".into()),
                ("A", "info".into(), "validator:enter".into()),
                ("A", "info".into(), "validator:resume".into()),
            ];
            if timeout {
                expected.insert(
                    if wait_at == "checker" { 1 } else { 3 },
                    ("A", "error".into(), CAPTCHA_ERROR.into()),
                );
            }
            assert_eq!(*lock(&state.logs)?, expected);
        }
    }
    Ok(())
}

#[tokio::test]
async fn bot_id_callback_and_catch_logger_errors_keep_their_original_owner() -> AuthResult<()> {
    for fail_at in ["checker:enter", "validator:enter"] {
        let state = State::new("none", Some(fail_at));
        let (parent, child) = fixture(&state).await?;
        let error = match nested(&parent, &child).await {
            Err(error) => error.into_thrown_value()?,
            Ok(_) => {
                return Err(AuthError::internal(
                    "Captcha catch logger failure was swallowed",
                ));
            }
        };
        assert!(error.strict_equals(&state.catch_error));
        assert!(!error.strict_equals(&state.callback_error));
        let mut expected = vec![("A", "info".into(), "checker:enter".into())];
        if fail_at == "validator:enter" {
            expected.extend([
                ("A", "info".into(), "checker:resume".into()),
                ("A", "info".into(), "validator:enter".into()),
            ]);
        }
        expected.push(("A", "error".into(), CAPTCHA_ERROR.into()));
        assert_eq!(*lock(&state.logs)?, expected);
        assert!(parent.current_request_context().is_none());
        assert!(child.context().current_request_context().is_none());
        assert!(current_request_hook_context().is_none());
    }
    Ok(())
}
