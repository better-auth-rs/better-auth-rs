#![expect(
    clippy::panic_in_result_fn,
    clippy::indexing_slicing,
    reason = "The contract asserts callback and report lengths before comparing original errors and publication ownership."
)]

use async_trait::async_trait;
use better_auth::{AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_core::{
    AuthContext, FieldFunction, FieldMap, FieldObject, FieldValue,
    observability::telemetry::{Telemetry, TelemetryEvent, TelemetryTransport},
    request_runtime::NativeRequest,
    store::{EphemeralStore, StatelessSchema},
};
use serde_json::{Value, json};
use std::{
    future::Future,
    sync::{Arc, Mutex, MutexGuard},
    task::Poll,
};

fn lock<T>(mutex: &Mutex<T>) -> AuthResult<MutexGuard<'_, T>> {
    mutex
        .lock()
        .map_err(|_| AuthError::internal("Telemetry observation lock poisoned"))
}

struct Transport {
    pending: bool,
    started: tokio::sync::Notify,
    release: tokio::sync::Notify,
    published: Mutex<Vec<TelemetryEvent>>,
    failure: FieldValue,
}

#[async_trait]
impl TelemetryTransport for Transport {
    async fn send(&self, event: &TelemetryEvent) -> AuthResult<()> {
        lock(&self.published)?.push(event.clone());
        self.started.notify_one();
        if self.pending {
            self.release.notified().await;
        }
        Err(AuthError::from_thrown(self.failure.clone()))
    }
}

struct Fixture {
    context: AuthContext<StatelessSchema>,
    config: AuthConfig,
    transport: Arc<Transport>,
    logs: Arc<Mutex<Vec<Vec<FieldValue>>>>,
    option_logs: Arc<Mutex<usize>>,
    logged: Arc<tokio::sync::Notify>,
    logger_failure: FieldValue,
}

impl Fixture {
    fn new(pending: bool) -> AuthResult<Self> {
        let transport = Arc::new(Transport {
            pending,
            started: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
            published: Mutex::new(Vec::new()),
            failure: FieldMap::from([("message".into(), "telemetry transport failure".into())])
                .into(),
        });
        let logger_failure: FieldValue =
            FieldMap::from([("message".into(), "telemetry logger failure".into())]).into();
        let logs = Arc::new(Mutex::new(Vec::new()));
        let logged = Arc::new(tokio::sync::Notify::new());
        let logger_options: FieldObject = FieldMap::from([
            ("level".into(), "error".into()),
            ("disableColors".into(), true.into()),
        ])
        .into();
        let expected: FieldValue = logger_options.clone().into();
        logger_options.set(
            "log",
            FieldFunction::contextual({
                let logs = logs.clone();
                let logged = logged.clone();
                let logger_failure = logger_failure.clone();
                let transport = transport.clone();
                move |receiver, arguments| {
                    assert!(
                        receiver.strict_equals(&expected),
                        "The exported logger retains the native helper scope"
                    );
                    assert_eq!(arguments.len(), 2);
                    assert!(arguments[0].strict_equals(&"error".into()));
                    assert!(arguments[1].strict_equals(&transport.failure));
                    lock(&logs)?.push(arguments.to_vec());
                    logged.notify_one();
                    Err(AuthError::from_thrown(logger_failure.clone()))
                }
            })
            .into(),
        )?;
        let mut scope_config = AuthConfig::default().base_url("https://telemetry-scope.test");
        scope_config.logger = logger_options.into();
        let scope_config = Arc::new(scope_config);
        let context = AuthContext::new(
            scope_config.clone(),
            Arc::new(EphemeralStore::new(scope_config)),
        )?;
        let option_logs = Arc::new(Mutex::new(0));
        let mut config =
            AuthConfig::new("telemetry-ownership-secret-longer-than-thirty-two-characters")
                .base_url("https://telemetry-detached.test");
        config.telemetry.enabled = true;
        config.telemetry.track = Some(transport.clone());
        config.logger = FieldObject::from(FieldMap::from([
            ("level".into(), "error".into()),
            (
                "log".into(),
                FieldFunction::contextual({
                    let option_logs = option_logs.clone();
                    move |_, _| {
                        *lock(&option_logs)? += 1;
                        Ok(FieldValue::Undefined)
                    }
                })
                .into(),
            ),
        ]))
        .into();
        Ok(Self {
            context,
            config,
            transport,
            logs,
            option_logs,
            logged,
            logger_failure,
        })
    }

    fn assert_observation(&self, kind: &str, payload: Option<&Value>) -> AuthResult<()> {
        let published = lock(&self.transport.published)?;
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].kind, kind);
        assert!(!published[0].anonymous_id.is_empty());
        if let Some(payload) = payload {
            assert_eq!(&published[0].payload, payload);
        }
        let logs = lock(&self.logs)?;
        assert_eq!(
            logs.len(),
            1,
            "Terminal reporting must not invoke the failing application sink again"
        );
        assert!(logs[0][1].strict_equals(&self.transport.failure));
        assert_eq!(*lock(&self.option_logs)?, 0);
        Ok(())
    }
}

// The accepted source capture is telemetry-detached-capture.mjs. Rust tracing is not a JavaScript unhandledRejection event.
#[tokio::test]
async fn telemetry_init_keeps_ready_and_pending_logger_failures_unowned() -> AuthResult<()> {
    for pending in [false, true] {
        let fixture = Fixture::new(pending)?;
        let config = fixture.config.clone();
        let auth = fixture
            .context
            .with_native_context(NativeRequest::default(), |_| async move {
                BetterAuth::stateless(config).build().await
            })
            .await?;
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fixture.transport.started.notified(),
        )
        .await
        .map_err(|_| AuthError::internal("Init telemetry did not enter its transport"))?;
        if pending {
            assert!(lock(&fixture.logs)?.is_empty());
        }
        fixture.transport.release.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(5), fixture.logged.notified())
            .await
            .map_err(|_| {
                AuthError::internal("Unowned telemetry lost its native helper logger scope")
            })?;
        fixture.assert_observation("init", None)?;
        drop(auth);
    }
    Ok(())
}

#[tokio::test]
async fn telemetry_publish_returns_the_scoped_logger_failure_to_its_owner() -> AuthResult<()> {
    for pending in [false, true] {
        let fixture = Fixture::new(pending)?;
        let telemetry = Telemetry::new(&fixture.config, None);
        assert!(telemetry.enabled());
        let payload = json!({"value":"retained"});
        let mut operation = Box::pin(
            fixture
                .context
                .with_native_context(NativeRequest::default(), |_| async {
                    telemetry.publish("probe", payload.clone()).await
                }),
        );
        let first = std::future::poll_fn(|cx| Poll::Ready(operation.as_mut().poll(cx))).await;
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fixture.transport.started.notified(),
        )
        .await
        .map_err(|_| AuthError::internal("Owned telemetry did not enter its transport"))?;
        if pending {
            assert!(first.is_pending());
            assert!(lock(&fixture.logs)?.is_empty());
        }
        fixture.transport.release.notify_one();
        let result = match first {
            Poll::Ready(result) => result,
            Poll::Pending => operation.await,
        };
        let error = match result {
            Err(error) => error.into_thrown_value()?,
            Ok(()) => {
                return Err(AuthError::internal(
                    "Owned publication swallowed the logger failure",
                ));
            }
        };
        assert!(error.strict_equals(&fixture.logger_failure));
        fixture.assert_observation("probe", Some(&payload))?;
    }
    Ok(())
}
