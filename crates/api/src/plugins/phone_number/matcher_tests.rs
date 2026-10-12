//! Paired with contracts/hook-matcher-input.test.ts through the shared native dispatcher.

#![expect(
    clippy::panic_in_result_fn,
    reason = "Contract assertions compare native error identities, callback order, and complete storage state."
)]

use super::*;
use crate::plugins::{
    api_key::{ApiKeyEndpoint, ApiKeyGetter, ApiKeyPlugin, CreateKeyRequest},
    test_helpers,
};
use async_trait::async_trait;
use better_auth_core::{
    ApiErrorClass, AuthPlugin, AuthRoute, BeforeRequestAction, FieldFunction, FieldMap, FieldValue,
    HttpMethod,
    endpoint_dispatch::EndpointDispatcher,
    endpoint_input::ValidatedBody,
    field_value::{
        FieldObject, FieldObjectSource, FieldProperty, FieldPropertyDefinition,
        FieldPropertyDescriptor,
    },
    observability::{AfterEndpointHook, EndpointHooks, LogArgument, LogLevel, LogSink},
    store::{EphemeralStore, StatelessSchema as S, schema::EntityRole},
};
use std::sync::Mutex;

const MATCHER_MESSAGE: &str =
    "An error occurred during hook matcher execution. Check the logs for more details.";

struct LoggedError {
    level: LogLevel,
    raw: Option<FieldValue>,
    type_error: bool,
}

#[derive(Default)]
struct Trace {
    events: Mutex<Vec<String>>,
    logs: Mutex<Vec<LoggedError>>,
    source: &'static str,
}

fn lock<T>(value: &Mutex<T>) -> AuthResult<std::sync::MutexGuard<'_, T>> {
    value
        .lock()
        .map_err(|_| AuthError::internal("Matcher contract trace lock poisoned"))
}

impl LogSink for Trace {
    #[expect(
        clippy::expect_used,
        reason = "The synchronous log callback must fail immediately when the original error or trace lock is unavailable."
    )]
    fn log(
        &self,
        level: LogLevel,
        message: LogArgument<'_>,
        arguments: &[LogArgument<'_>],
    ) -> better_auth_core::AuthResult<()> {
        if message.to_string()
            != format!(
                "An error occurred during {} hook matcher execution:",
                self.source
            )
        {
            return Ok(());
        }
        assert_eq!(arguments.len(), 1);
        let error = match arguments.first() {
            Some(LogArgument::Error(error)) => error.downcast_ref::<AuthError>(),
            _ => None,
        }
        .expect("Matcher logs must retain the original AuthError");
        self.logs
            .lock()
            .expect("Matcher log lock is available")
            .push(LoggedError {
                level,
                raw: error.raw_value().cloned(),
                type_error: matches!(error, AuthError::TypeError(_)),
            });
        Ok(())
    }
}

struct BodySource {
    case: &'static str,
    trace: Arc<Trace>,
    sentinel: FieldValue,
    unread: FieldFunction,
}

impl BodySource {
    fn new(case: &'static str, trace: Arc<Trace>, sentinel: FieldValue) -> Self {
        let thrown = sentinel.clone();
        Self {
            case,
            trace,
            sentinel,
            unread: FieldFunction::contextual(move |_, _| {
                Err(AuthError::from_thrown(thrown.clone()))
            }),
        }
    }
}

impl FieldObjectSource for BodySource {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        Ok(if self.case == "unread" {
            vec!["unread".into()]
        } else {
            Vec::new()
        })
    }

    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        Ok(
            (self.case == "unread" && name == "unread").then(|| FieldPropertyDescriptor {
                enumerable: true,
                configurable: true,
                property: FieldProperty::Accessor {
                    get: Some(self.unread.clone()),
                    set: None,
                },
            }),
        )
    }

    fn has_property(&self, name: &str) -> AuthResult<bool> {
        if self.case == "unread" {
            return Ok(name == "unread");
        }
        lock(&self.trace.events)?.push(format!("has:{name}"));
        if self.case == "has-throw" {
            return Err(AuthError::from_thrown(self.sentinel.clone()));
        }
        Ok(true)
    }

    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        if self.case == "unread" {
            if name == "unread" {
                return self.unread.call_with(receiver, &[]).map(Some);
            }
            return Ok(None);
        }
        lock(&self.trace.events)?.push(format!("get:{name}"));
        Err(AuthError::from_thrown(self.sentinel.clone()))
    }

    fn set_with_receiver(&self, _: String, _: FieldValue, _: &FieldValue) -> AuthResult<bool> {
        Err(AuthError::type_error("The matcher input is read-only"))
    }

    fn define_own_property(&self, _: String, _: FieldPropertyDefinition) -> AuthResult<bool> {
        Err(AuthError::type_error("The matcher input is read-only"))
    }

    fn delete(&self, _: &str) -> AuthResult<bool> {
        Err(AuthError::type_error("The matcher input is read-only"))
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        self.own_keys()?
            .into_iter()
            .map(|name| {
                Ok((
                    name.clone(),
                    self.get_with_receiver(&name, &FieldValue::Undefined)?
                        .unwrap_or_default(),
                ))
            })
            .collect()
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self).addr()
    }
}

#[derive(Clone)]
struct Following {
    trace: Arc<Trace>,
    body: FieldValue,
    blocker: FieldValue,
}

#[async_trait]
impl AuthPlugin<S> for Following {
    fn name(&self) -> &'static str {
        "following-hook"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn before_request(
        &self,
        request: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        if request.path() == "/update-user" {
            lock(&self.trace.events)?.push("following".into());
            assert!(request.input_field_value()?.strict_equals(&self.body));
            return Err(AuthError::from_thrown(self.blocker.clone()));
        }
        Ok(None)
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

#[async_trait]
impl AfterEndpointHook<S> for Following {
    async fn after(
        &self,
        _: &AuthRequest,
        _: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        lock(&self.trace.events)?.push("after".into());
        Ok(())
    }
}

fn sentinel(message: &str) -> AuthResult<FieldValue> {
    AuthError::from_status(
        "CONFLICT",
        FieldMap::from([("message".into(), message.into())]).into(),
    )
    .raw_value()
    .cloned()
    .ok_or_else(|| AuthError::internal("Expected the native matcher sentinel"))
}

fn assert_wrapper(error: &AuthError) -> AuthResult<()> {
    assert!(error.is_api_error_instance(ApiErrorClass::BetterAuth));
    assert_eq!(error.status_value()?, "INTERNAL_SERVER_ERROR".into());
    assert_eq!(error.status_code()?, 500);
    assert_eq!(
        error.body_value()?.enumerable_fields()?,
        FieldMap::from([("message".into(), MATCHER_MESSAGE.into())]),
    );
    Ok(())
}

#[tokio::test]
async fn native_phone_matcher_retains_input_presence_and_getter_order() -> AuthResult<()> {
    for case in [
        "missing",
        "null",
        "false",
        "number",
        "string",
        "array",
        "empty",
        "phone-null",
        "phone-undefined",
        "phone-value",
        "unread",
        "has-throw",
        "get-throw",
    ] {
        let trace = Arc::new(Trace {
            source: "plugin:phone-number",
            ..Default::default()
        });
        let blocker = sentinel("following hook")?;
        let sentinel = sentinel("matcher sentinel")?;
        let body = match case {
            "missing" => FieldValue::Undefined,
            "null" => FieldValue::Null,
            "false" => false.into(),
            "number" => 7.into(),
            "string" => "text".into(),
            "array" => Vec::<FieldValue>::new().into(),
            "empty" => FieldMap::new().into(),
            "phone-null" => FieldMap::from([("phoneNumber".into(), FieldValue::Null)]).into(),
            "phone-undefined" => {
                FieldMap::from([("phoneNumber".into(), FieldValue::Undefined)]).into()
            }
            "phone-value" => FieldMap::from([("phoneNumber".into(), "+15550000001".into())]).into(),
            _ => FieldObject::from_source(Arc::new(BodySource::new(
                case,
                trace.clone(),
                sentinel.clone(),
            )))
            .into(),
        };
        let following = Following {
            trace: trace.clone(),
            body: body.clone(),
            blocker,
        };
        let phone = PhoneNumberPlugin::new();
        let mut config = test_helpers::create_test_config();
        config.logger = better_auth_core::LoggerConfig {
            level: Some(LogLevel::Debug),
            log: Some(trace.clone()),
            ..Default::default()
        }
        .into();
        let config = Arc::new(config);
        let store = Arc::new(EphemeralStore::new(config.clone()));
        let context =
            test_helpers::initialize_test_context(config, store.clone(), &[&phone, &following])
                .await?;
        let route = AuthRoute::post("/update-user", "updateUser");
        let dispatcher = EndpointDispatcher::new(
            Arc::new(vec![
                Box::new(phone) as Box<dyn AuthPlugin<S>>,
                Box::new(following.clone()),
            ]),
            EndpointHooks {
                after: Some(Arc::new(following.clone())),
                ..Default::default()
            },
            [route.clone()],
        );
        let mut request = AuthRequest::new(HttpMethod::Post, "/update-user");
        request.set_endpoint_body(ValidatedBody::unvalidated_native(body));
        let error = dispatcher
            .native(request, route, &context, |_, _| async {
                Err(AuthError::internal(
                    "The matcher contract must stop before its handler",
                ))
            })
            .await
            .err()
            .ok_or_else(|| AuthError::internal("Expected a matcher or following-hook failure"))?;
        let actual = error
            .raw_value()
            .ok_or_else(|| AuthError::internal("Expected a native endpoint error"))?;
        let logs = lock(&trace.logs)?;
        let expected_events = if matches!(
            case,
            "missing" | "null" | "false" | "number" | "string" | "has-throw" | "get-throw"
        ) {
            assert_wrapper(&error)?;
            assert!(!actual.strict_equals(&sentinel));
            assert_eq!(logs.len(), 1, "{case}");
            let logged = logs
                .first()
                .ok_or_else(|| AuthError::internal("Expected the original matcher error log"))?;
            assert_eq!(logged.level, LogLevel::Error);
            if matches!(case, "has-throw" | "get-throw") {
                assert!(
                    logged
                        .raw
                        .as_ref()
                        .is_some_and(|value| value.strict_equals(&sentinel))
                );
            } else {
                assert!(logged.type_error);
            }
            match case {
                "has-throw" => vec!["has:phoneNumber"],
                "get-throw" => vec!["has:phoneNumber", "get:phoneNumber"],
                _ => Vec::new(),
            }
        } else if matches!(case, "phone-undefined" | "phone-value") {
            test_helpers::assert_coded_api_error(
                &error,
                "BAD_REQUEST",
                400,
                "PHONE_NUMBER_CANNOT_BE_UPDATED",
                "Phone number cannot be updated",
            );
            assert!(logs.is_empty());
            Vec::new()
        } else {
            assert!(actual.strict_equals(&following.blocker));
            assert!(logs.is_empty());
            vec!["following"]
        };
        assert_eq!(*lock(&trace.events)?, expected_events, "{case}");
        for role in [
            EntityRole::User,
            EntityRole::Session,
            EntityRole::Account,
            EntityRole::Verification,
        ] {
            assert!(store.storage_rows(role)?.is_empty(), "{case}: {role:?}");
        }
    }
    Ok(())
}

struct FailingGetter {
    failure_call: usize,
    calls: Mutex<usize>,
    sentinel: FieldValue,
}

impl ApiKeyGetter for FailingGetter {
    fn get(&self, _: ApiKeyEndpoint<'_>) -> AuthResult<Option<String>> {
        let mut calls = lock(&self.calls)?;
        *calls += 1;
        if *calls == self.failure_call {
            return Err(AuthError::from_thrown(self.sentinel.clone()));
        }
        Ok(Some("x".repeat(64)))
    }
}

#[tokio::test]
async fn api_key_wraps_only_the_matcher_getter_for_native_and_typed_calls() -> AuthResult<()> {
    for typed in [false, true] {
        for failure_call in [1, 2] {
            let trace = Arc::new(Trace {
                source: "plugin:api-key",
                ..Default::default()
            });
            let getter = Arc::new(FailingGetter {
                failure_call,
                calls: Mutex::new(0),
                sentinel: sentinel("key getter failure")?,
            });
            let plugin = ApiKeyPlugin::builder()
                .enable_session_for_api_keys(true)
                .custom_api_key_getter(getter.clone())
                .build();
            let mut config = test_helpers::create_test_config();
            config.logger = better_auth_core::LoggerConfig {
                level: Some(LogLevel::Debug),
                log: Some(trace.clone()),
                ..Default::default()
            }
            .into();
            let config = Arc::new(config);
            let store = Arc::new(EphemeralStore::new(config.clone()));
            let context =
                test_helpers::initialize_test_context(config, store.clone(), &[&plugin]).await?;
            let result = if typed {
                plugin
                    .create_key(
                        &context,
                        &CreateKeyRequest {
                            user_id: Some("owner".into()),
                            ..Default::default()
                        },
                    )
                    .await
                    .map(|_| ())
            } else {
                let route = AuthRoute::post("/sign-in/anonymous", "signInAnonymous");
                let dispatcher = EndpointDispatcher::new(
                    Arc::new(vec![Box::new(plugin) as Box<dyn AuthPlugin<S>>]),
                    EndpointHooks::default(),
                    [route.clone()],
                );
                dispatcher
                    .native(
                        AuthRequest::new(HttpMethod::Post, "/sign-in/anonymous"),
                        route,
                        &context,
                        |_, _| async {
                            Err(AuthError::internal(
                                "The API Key getter must stop before its handler",
                            ))
                        },
                    )
                    .await
                    .map(|_| ())
            };
            let error = result
                .err()
                .ok_or_else(|| AuthError::internal("Expected the API Key getter failure"))?;
            assert_eq!(*lock(&getter.calls)?, failure_call);
            let actual = error
                .raw_value()
                .ok_or_else(|| AuthError::internal("Expected the native getter error"))?;
            let logs = lock(&trace.logs)?;
            if failure_call == 1 {
                assert_wrapper(&error)?;
                assert!(!actual.strict_equals(&getter.sentinel));
                assert_eq!(logs.len(), 1);
                let logged = logs
                    .first()
                    .ok_or_else(|| AuthError::internal("Expected the matcher error log"))?;
                assert_eq!(logged.level, LogLevel::Error);
                assert!(
                    logged
                        .raw
                        .as_ref()
                        .is_some_and(|value| value.strict_equals(&getter.sentinel))
                );
            } else {
                assert!(actual.strict_equals(&getter.sentinel));
                assert!(logs.is_empty());
            }
            for role in [
                EntityRole::User,
                EntityRole::Session,
                EntityRole::Account,
                EntityRole::Verification,
                EntityRole::ApiKey,
            ] {
                assert!(store.storage_rows(role)?.is_empty());
            }
        }
    }
    Ok(())
}
