#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]
#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
//! Rust ownership regression for custom-session's Promise.all callback scope.

use super::*;
use better_auth_core::{
    AuthConfig, AuthError, BeforeRequestAction, FieldMap,
    endpoint_dispatch::EndpointDispatcher,
    hooks::current_request_hook_context,
    observability::{BeforeEndpointHook, EndpointHooks},
    plugin_runtime::PluginRuntime,
    store::{EphemeralStore, StatelessSchema as S, schema::EntityRole},
};
use serde_json::json;
use std::{sync::Mutex, time::Duration};
use tokio::sync::Notify;

const PATH: &str = "/multi-session/list-device-sessions";
const ROOT: &str = "https://custom-runtime.test/api/auth";
const BEFORE: &str = "http://before.custom-runtime.test";
const FIRST: &str = "http://first.custom-runtime.test";
const SECOND: &str = "http://second.custom-runtime.test";
const RELEASED: &str = "http://released.custom-runtime.test";
const FINISHED: &str = "http://finished.custom-runtime.test";

fn lock<T>(mutex: &Mutex<T>) -> AuthResult<std::sync::MutexGuard<'_, T>> {
    mutex
        .lock()
        .map_err(|_| AuthError::internal("Custom session runtime recorder lock poisoned"))
}

#[derive(Default)]
struct State {
    runtime: PluginRuntime<S>,
    retained: Mutex<Option<Arc<AuthContext<S>>>>,
    events: Mutex<Vec<&'static str>>,
    entered: Notify,
    release: Notify,
    finished: Notify,
}

impl State {
    #[expect(
        clippy::panic_in_result_fn,
        reason = "The regression asserts runtime identity and endpoint scope while propagating recorder errors"
    )]
    fn observe(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
        expected: &str,
    ) -> AuthResult<()> {
        let current = context
            .current_request_context()
            .ok_or_else(|| AuthError::internal("Custom session callback lost its runtime scope"))?;
        let retained = lock(&self.retained)?
            .clone()
            .ok_or_else(|| AuthError::internal("Before hook did not retain its runtime"))?;
        assert!(Arc::ptr_eq(&current, &retained));
        assert!(Arc::ptr_eq(&self.runtime.context()?, &retained));
        assert_eq!(context.base_url(), expected);
        assert_eq!(current.base_url(), expected);
        assert_eq!(request.path(), PATH);
        let hook = current_request_hook_context().ok_or_else(|| {
            AuthError::internal("Custom session callback lost its endpoint scope")
        })?;
        assert_eq!(hook.path.as_deref(), Some(PATH));
        assert_eq!(hook.operation_id.as_deref(), Some("listDeviceSessions"));
        assert!(!hook.is_http);
        Ok(())
    }
}

struct Before(Arc<State>);

#[async_trait]
impl BeforeEndpointHook<S> for Before {
    async fn before(
        &self,
        _: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        *lock(&self.0.retained)? = context.current_request_context();
        context.set_base_url(BEFORE);
        lock(&self.0.events)?.push("before");
        Ok(None)
    }
}

struct Callback {
    state: Arc<State>,
    failure: bool,
    sentinel: FieldValue,
}

#[async_trait]
impl CustomSessionCallback<S> for Callback {
    async fn customize(
        &self,
        input: CustomSessionInput,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Value> {
        let first = input
            .data
            .user_property("id")?
            .strict_equals(&"first".into());
        self.state
            .observe(request, context, if first { BEFORE } else { FIRST })?;
        lock(&self.state.events)?.push(if first { "start:first" } else { "start:second" });
        context.set_base_url(if first { FIRST } else { SECOND });
        if first {
            if self.failure {
                lock(&self.state.events)?.push("reject:first");
                return Err(AuthError::from_thrown(self.sentinel.clone()));
            }
            lock(&self.state.events)?.push("finish:first");
            return Ok(json!({ "id": "first", "baseURL": context.base_url() }));
        }
        self.state.entered.notify_one();
        self.state.release.notified().await;
        self.state.observe(request, context, RELEASED)?;
        context.set_base_url(FINISHED);
        request.set_response_header("x-custom-session", "finished")?;
        lock(&self.state.events)?.push("finish:second");
        self.state.finished.notify_one();
        Ok(json!({ "id": "second", "baseURL": context.base_url() }))
    }
}

#[tokio::test]
async fn list_callbacks_retain_caller_runtime_and_complete_after_first_error() -> AuthResult<()> {
    for failure in [false, true] {
        let state = Arc::new(State::default());
        let config = Arc::new(
            AuthConfig::new("custom-session-runtime-secret-at-least-32-characters")
                .base_url("https://custom-runtime.test"),
        );
        let store = Arc::new(EphemeralStore::new(config.clone()));
        let root = AuthContext::<S>::new(config, store.clone())
            .expect("fixture context initializes")
            .initialize_request_context()
            .await?;
        state.runtime.bind(&root)?;
        let sentinel = AuthError::from_status(
            "CONFLICT",
            FieldMap::from([("message".into(), "first callback failed".into())]).into(),
        )
        .raw_value()
        .cloned()
        .ok_or_else(|| AuthError::internal("Expected native APIError sentinel"))?;
        let route = AuthRoute::new(HttpMethod::Get, PATH, "listDeviceSessions");
        let dispatcher = EndpointDispatcher::new(
            Arc::new(vec![Box::new(
                CustomSessionPlugin::new(Callback {
                    state: state.clone(),
                    failure,
                    sentinel: sentinel.clone(),
                })
                .mutate_list_device_sessions(true),
            )]),
            EndpointHooks {
                before: Some(Arc::new(Before(state.clone()))),
                after: None,
            },
            [route.clone()],
        );
        let operation_root = root.clone();
        let mut operation = tokio::spawn(async move {
            dispatcher
                .native(
                    AuthRequest::new(HttpMethod::Get, PATH),
                    route,
                    &operation_root,
                    |_, _| async {
                        AuthResponse::json(
                            200,
                            &json!([
                                { "session": {}, "user": { "id": "first" } },
                                { "session": {}, "user": { "id": "second" } },
                            ]),
                        )
                    },
                )
                .await
        });
        let entered = tokio::time::timeout(Duration::from_secs(5), state.entered.notified()).await;
        let early = if failure {
            Some(tokio::time::timeout(Duration::from_secs(5), &mut operation).await)
        } else {
            None
        };
        let waiting = !operation.is_finished();
        let retained = lock(&state.retained)?.clone();
        let before_release = retained.as_ref().map(|context| context.base_url());
        if let Some(context) = &retained {
            context.set_base_url(RELEASED);
        }
        state.release.notify_one();
        let finished =
            tokio::time::timeout(Duration::from_secs(5), state.finished.notified()).await;
        let rejected_early = matches!(&early, Some(Ok(Ok(Err(_)))));
        let result = match early {
            Some(Ok(result)) => result,
            Some(Err(_)) | None => {
                match tokio::time::timeout(Duration::from_secs(5), &mut operation).await {
                    Ok(result) => result,
                    Err(_) => {
                        operation.abort();
                        return Err(AuthError::internal(
                            "Custom session dispatch did not finish within 5 seconds after releasing the callback",
                        ));
                    }
                }
            }
        }
        .map_err(|error| {
            AuthError::internal(format!("Custom session dispatch task failed: {error}"))
        })?;
        assert!(
            entered.is_ok(),
            "Both callbacks must start before failure returns"
        );
        assert!(
            finished.is_ok(),
            "The second callback must finish after its gate opens"
        );
        assert_eq!(before_release.as_deref(), Some(SECOND));
        if failure {
            assert!(rejected_early);
            let error = result
                .err()
                .ok_or_else(|| AuthError::internal("Expected the first callback error"))?;
            assert!(
                error
                    .raw_value()
                    .is_some_and(|value| value.strict_equals(&sentinel))
            );
        } else {
            assert!(waiting);
            let response = result?;
            assert_eq!(response.status, 200);
            assert_eq!(
                response.headers.get("x-custom-session").map(String::as_str),
                Some("finished")
            );
            assert_eq!(
                response.body.field_value()?.json()?,
                Some(json!([
                    { "id": "first", "baseURL": FIRST },
                    { "id": "second", "baseURL": FINISHED },
                ]))
            );
        }
        assert_eq!(
            *lock(&state.events)?,
            [
                "before",
                "start:first",
                if failure {
                    "reject:first"
                } else {
                    "finish:first"
                },
                "start:second",
                "finish:second"
            ]
        );
        assert_eq!(
            retained
                .as_ref()
                .map(|context| context.base_url())
                .as_deref(),
            Some(FINISHED)
        );
        assert_eq!(root.base_url(), ROOT);
        assert!(Arc::ptr_eq(&state.runtime.context()?, &root));
        assert!(root.current_request_context().is_none());
        assert!(current_request_hook_context().is_none());
        for role in [
            EntityRole::User,
            EntityRole::Session,
            EntityRole::Account,
            EntityRole::Verification,
        ] {
            assert!(store.storage_rows(role)?.is_empty());
        }
    }
    Ok(())
}
