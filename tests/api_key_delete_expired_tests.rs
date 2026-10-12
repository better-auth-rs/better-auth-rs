#![expect(
    clippy::panic_in_result_fn,
    clippy::indexing_slicing,
    reason = "The cleanup contract asserts native identity, callback order, and complete storage after fallible operations."
)]

use async_trait::async_trait;
use better_auth::server_api::NativeEndpointInput;
use better_auth::{AuthConfig, AuthError, AuthResult, BetterAuth, plugins::ApiKeyPlugin};
use better_auth_core::{
    AuthContext, AuthRequest, AuthResponse, BeforeRequestAction, FieldDate, FieldFunction,
    FieldMap, FieldObject, FieldValue, HttpMethod,
    observability::{AfterEndpointHook, BeforeEndpointHook, EndpointHooks},
    store::{EphemeralStore, StatelessSchema, schema::EntityRole},
};
use std::sync::{
    Arc, Mutex, MutexGuard,
    atomic::{AtomicBool, Ordering},
};

fn lock<T>(value: &Mutex<T>) -> AuthResult<MutexGuard<'_, T>> {
    value
        .lock()
        .map_err(|_| AuthError::internal("Cleanup observation lock poisoned"))
}

struct State {
    mode: &'static str,
    events: Mutex<Vec<&'static str>>,
    database_error: FieldValue,
    first_logger_error: FieldValue,
    second_logger_error: FieldValue,
    body: FieldValue,
    query: FieldValue,
    replacement: FieldValue,
}

impl State {
    fn new(mode: &'static str) -> Arc<Self> {
        let marker = |value: &str| FieldMap::from([("owner".into(), value.into())]).into();
        Arc::new(Self {
            mode,
            events: Mutex::new(Vec::new()),
            database_error: marker("database"),
            first_logger_error: marker("firstLogger"),
            second_logger_error: marker("secondLogger"),
            body: marker("body"),
            query: marker("query"),
            replacement: FieldMap::from([
                ("success".into(), "hook value".into()),
                ("error".into(), FieldValue::Undefined),
                ("nested".into(), marker("retained")),
            ])
            .into(),
        })
    }

    fn config(self: &Arc<Self>) -> AuthResult<AuthConfig> {
        let mut config = AuthConfig::new("api-key-delete-expired-contract-secret-more-than-32");
        config.base_url = "https://api-key-delete-expired.test".into();
        let owner: FieldObject = FieldMap::from([("level".into(), "error".into())]).into();
        let expected: FieldValue = owner.clone().into();
        owner.set(
            "log",
            FieldFunction::contextual({
                let state = self.clone();
                move |receiver, arguments| {
                    assert!(receiver.strict_equals(&expected));
                    assert_eq!(arguments.len(), 3);
                    assert!(arguments[0].strict_equals(&"error".into()));
                    let second = lock(&state.events)?.contains(&"logger:first");
                    let (message, original, event) = if second {
                        (
                            "[API KEY PLUGIN] Failed to delete expired API keys:",
                            &state.first_logger_error,
                            "logger:second",
                        )
                    } else {
                        (
                            "Failed to delete expired API keys:",
                            &state.database_error,
                            "logger:first",
                        )
                    };
                    assert!(arguments[1].strict_equals(&message.into()));
                    assert!(arguments[2].strict_equals(original));
                    lock(&state.events)?.push(event);
                    match (second, state.mode) {
                        (false, "first-logger-error" | "second-logger-error") => {
                            Err(AuthError::from_thrown(state.first_logger_error.clone()))
                        }
                        (true, "second-logger-error") => {
                            Err(AuthError::from_thrown(state.second_logger_error.clone()))
                        }
                        _ => Ok(FieldValue::Undefined),
                    }
                }
            })
            .into(),
        )?;
        config.logger = owner.into();
        Ok(config)
    }

    fn input(&self) -> NativeEndpointInput {
        NativeEndpointInput {
            body: self.body.clone(),
            query: self.query.clone(),
            request: Some(AuthRequest::new(HttpMethod::Post, "/original")),
            headers: Some(Default::default()),
        }
    }
}

#[derive(Clone)]
struct Hooks(Arc<State>);

#[async_trait]
impl BeforeEndpointHook<StatelessSchema> for Hooks {
    async fn before(
        &self,
        request: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        let scope = better_auth_core::hooks::current_request_hook_context()
            .ok_or_else(|| AuthError::internal("Cleanup endpoint scope is missing"))?;
        assert_eq!(
            scope.operation_id.as_deref(),
            Some("deleteAllExpiredApiKeys")
        );
        assert!(scope.path.is_none());
        assert_eq!(request.path(), "/");
        assert!(request.input_field_value()?.strict_equals(&self.0.body));
        assert!(
            request
                .input_query_field_value()?
                .strict_equals(&self.0.query)
        );
        assert!(request.original_request().is_some());
        assert!(request.endpoint_headers().is_some());
        lock(&self.0.events)?.push("before");
        Ok((self.0.mode == "before-stop").then(|| {
            BeforeRequestAction::Respond(AuthResponse::native(None, self.0.replacement.clone()))
        }))
    }
}

#[async_trait]
impl AfterEndpointHook<StatelessSchema> for Hooks {
    async fn after(
        &self,
        request: &AuthRequest,
        response: &mut AuthResponse,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<()> {
        assert_eq!(request.path(), "/");
        assert!(
            better_auth_core::hooks::current_request_hook_context()
                .ok_or_else(|| AuthError::internal("Cleanup endpoint scope is missing"))?
                .path
                .is_none()
        );
        lock(&self.0.events)?.push("after");
        let returned = response.body.field_value()?;
        let expected_error = if self.0.mode == "first-logger-error" {
            self.0.first_logger_error.clone()
        } else {
            FieldValue::Null
        };
        assert_eq!(
            returned
                .as_object()
                .ok_or_else(|| AuthError::internal(
                    "Cleanup hook must receive the complete result"
                ))?
                .own_keys()?,
            ["success", "error"]
        );
        assert!(
            returned
                .model_property("success")?
                .strict_equals(&(self.0.mode != "first-logger-error").into())
        );
        assert!(
            returned
                .model_property("error")?
                .strict_equals(&expected_error)
        );
        if self.0.mode == "after-replacement" {
            response.replace_returned(AuthResponse::native(None, self.0.replacement.clone()));
        }
        Ok(())
    }
}

fn row(id: &str, expiration: FieldValue) -> FieldMap {
    FieldMap::from([("id".into(), id.into()), ("expiresAt".into(), expiration)])
}

async fn build(
    state: &Arc<State>,
    rows: Vec<FieldMap>,
    hooks: bool,
) -> AuthResult<(BetterAuth<StatelessSchema>, EphemeralStore)> {
    let config = state.config()?;
    let store = EphemeralStore::from_storage(
        Arc::new(config.clone()),
        [
            ("user".into(), Vec::new()),
            ("session".into(), Vec::new()),
            ("account".into(), Vec::new()),
            ("verification".into(), Vec::new()),
            ("apikey".into(), rows),
        ],
    )?;
    let mut builder = BetterAuth::stateless(config)
        .store(store.clone())
        .plugin(ApiKeyPlugin::builder().build());
    if hooks {
        builder = builder.hooks(EndpointHooks {
            before: Some(Arc::new(Hooks(state.clone()))),
            after: Some(Arc::new(Hooks(state.clone()))),
        });
    }
    Ok((builder.build().await?, store))
}

#[tokio::test]
async fn cleanup_retains_both_logger_catches_and_original_errors() -> AuthResult<()> {
    for mode in [
        "database-error",
        "first-logger-error",
        "second-logger-error",
    ] {
        let state = State::new(mode);
        let expiration = FieldMap::from([(
            "valueOf".into(),
            FieldFunction::contextual({
                let state = state.clone();
                move |_, _| {
                    lock(&state.events)?.push("database");
                    Err(AuthError::from_thrown(state.database_error.clone()))
                }
            })
            .into(),
        )]);
        let original = vec![
            row("retained", expiration.into()),
            row("never", FieldValue::Null),
        ];
        let (auth, store) = build(&state, original.clone(), true).await?;
        let result = auth.api_keys()?.delete_all_expired(state.input()).await;
        let mut expected = vec!["before", "database", "logger:first"];
        if mode != "database-error" {
            expected.push("logger:second");
        }
        if mode == "second-logger-error" {
            let error = result
                .err()
                .ok_or_else(|| AuthError::internal("Second Logger failure must propagate"))?;
            assert!(
                error
                    .into_thrown_value()?
                    .strict_equals(&state.second_logger_error)
            );
        } else {
            expected.push("after");
            let result = result?;
            let expected_error = if mode == "first-logger-error" {
                state.first_logger_error.clone()
            } else {
                FieldValue::Null
            };
            let fields = result
                .as_object()
                .ok_or_else(|| AuthError::internal("Cleanup result must remain an object"))?;
            assert_eq!(fields.own_keys()?, ["success", "error"]);
            assert!(
                result
                    .model_property("success")?
                    .strict_equals(&(mode == "database-error").into())
            );
            assert!(
                result
                    .model_property("error")?
                    .strict_equals(&expected_error)
            );
        }
        assert_eq!(*lock(&state.events)?, expected);
        assert_eq!(store.plugin_storage_rows(EntityRole::ApiKey)?, original);
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

#[tokio::test]
async fn cleanup_bypasses_the_interval_and_preserves_hook_replacements() -> AuthResult<()> {
    for mode in ["bypass", "before-stop", "after-replacement"] {
        let state = State::new(mode);
        let expire = Arc::new(AtomicBool::new(false));
        let expiration = FieldMap::from([(
            "valueOf".into(),
            FieldFunction::contextual({
                let expire = expire.clone();
                let state = state.clone();
                move |_, _| {
                    lock(&state.events)?.push("database");
                    Ok(if expire.load(Ordering::SeqCst) {
                        0.0
                    } else {
                        4_102_444_800_000.0
                    }
                    .into())
                }
            })
            .into(),
        )]);
        let never = row("never", FieldValue::Null);
        let second = row("expire-next", expiration.into());
        let original = vec![
            row("expired", FieldDate::from_milliseconds(0.0).into()),
            second.clone(),
            never.clone(),
        ];
        let (auth, store) = build(&state, original.clone(), true).await?;
        let first = auth.api_keys()?.delete_all_expired(state.input()).await?;
        if mode == "bypass" {
            assert_eq!(
                first.json()?,
                Some(serde_json::json!({"success": true, "error": null}))
            );
            assert_eq!(
                store.plugin_storage_rows(EntityRole::ApiKey)?,
                [second, never.clone()]
            );
            expire.store(true, Ordering::SeqCst);
            let second = auth.api_keys()?.delete_all_expired(state.input()).await?;
            assert_eq!(second.json()?, first.json()?);
            assert_eq!(store.plugin_storage_rows(EntityRole::ApiKey)?, [never]);
            assert_eq!(
                *lock(&state.events)?,
                [
                    "before", "database", "database", "after", "before", "database", "database",
                    "after"
                ]
            );
        } else {
            assert!(first.strict_equals(&state.replacement));
            if mode == "before-stop" {
                assert_eq!(store.plugin_storage_rows(EntityRole::ApiKey)?, original);
                assert_eq!(*lock(&state.events)?, ["before"]);
            } else {
                assert_eq!(
                    store.plugin_storage_rows(EntityRole::ApiKey)?,
                    [second, never]
                );
                assert_eq!(
                    *lock(&state.events)?,
                    ["before", "database", "database", "after"]
                );
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn cleanup_has_no_public_http_route() -> AuthResult<()> {
    let state = State::new("http");
    let original = vec![row("expired", FieldDate::from_milliseconds(0.0).into())];
    let (auth, store) = build(&state, original.clone(), false).await?;
    for path in ["/api-key/delete-all-expired", "/deleteAllExpiredApiKeys"] {
        let response = auth
            .handle_request(AuthRequest::new(HttpMethod::Post, path))
            .await?;
        assert_eq!(response.status, 404);
    }
    assert_eq!(store.plugin_storage_rows(EntityRole::ApiKey)?, original);
    assert!(lock(&state.events)?.is_empty());
    Ok(())
}
