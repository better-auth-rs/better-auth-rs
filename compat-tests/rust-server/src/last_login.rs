use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use better_auth::plugins::{
    BeforeStoreLastLoginCookie, EmailPasswordPlugin, LastLoginMethodConfig, LastLoginMethodPlugin,
    LastLoginMethodResolver, SessionManagementPlugin, endpoint_context::EndpointContext,
};
use better_auth::{
    AuthBuilder, AuthConfig, AuthError, AuthResult, AuthSchema, BetterAuth, PasswordHasher,
    integrations::axum::AxumIntegration,
};
use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute, AuthUser, BeforeRequestAction,
    CreateSession, CreateUser, UpdateUser,
    config::{CookieCacheConfig, UserFieldConfig},
    hooks::RequestHookContext,
    middleware::RateLimitConfig,
    store::{
        SecondaryStorage,
        database_hooks::{
            DatabaseHookContext, DatabaseHookControl, DatabaseHookUpdate, DatabaseHooks,
        },
    },
};
use better_auth_seaorm::{
    SeaOrmStore,
    hooks::{HookControl, SeaOrmHookContext, SeaOrmHooks},
};
use serde_json::{Value, json};

#[derive(Default)]
struct Trace {
    events: Vec<Value>,
    controls: Value,
    resolves: usize,
}
#[derive(Clone, Default)]
struct Events(Arc<Mutex<Trace>>);

fn rejected() -> AuthError {
    AuthResponse::json(
        403,
        &json!({"code":"LOGIN_FIXTURE_REJECTED","message":"Login fixture rejected"}),
    )
    .unwrap()
    .into()
}

impl Events {
    fn record(&self, kind: &str, request: Option<&RequestHookContext>, value: Option<Value>) {
        let mut event = json!({"kind":kind,"path":request.map(|request|request.path.as_str()),"http":request.is_some_and(|request|request.is_http)});
        if let Some(value) = value {
            event["value"] = value;
        }
        self.0.lock().unwrap().events.push(event);
    }
    fn fails(&self, kind: &str) -> bool {
        self.0.lock().unwrap().controls["fail"] == kind
    }
}

impl<S: AuthSchema> LastLoginMethodResolver<S> for Events {
    fn resolve(&self, context: &EndpointContext<'_, S>) -> AuthResult<Option<String>> {
        let mut trace = self.0.lock().unwrap();
        trace.resolves += 1;
        trace
            .events
            .push(json!({"kind":"resolve","path":context.path,"http":context.request.is_some(),"header":context.headers().and_then(|headers|headers.get("x-login-context"))}));
        let mode = trace.controls["resolve"].as_str();
        if mode == Some("body") {
            trace.events.last_mut().unwrap()["bodyName"] = context.body["name"].clone();
            return Ok(Some(
                context.body["name"].as_str().unwrap_or("missing").into(),
            ));
        }
        if mode == Some("error") || mode == Some("session-error") && trace.resolves == 2 {
            return Err(rejected());
        }
        Ok(match mode {
            Some("empty") => Some(String::new()),
            Some("custom") => Some("custom method".into()),
            _ => None,
        })
    }
}

#[async_trait::async_trait]
impl<S: AuthSchema> BeforeStoreLastLoginCookie<S> for Events {
    async fn before_store_cookie(
        &self,
        context: &EndpointContext<'_, S>,
        method: &str,
    ) -> AuthResult<bool> {
        let mut trace = self.0.lock().unwrap();
        trace.events.push(json!({"kind":"cookie","path":context.path,"http":context.request.is_some(),"value":method}));
        if trace.controls["resolve"] == "body" {
            trace.events.last_mut().unwrap()["bodyName"] = context.body["name"].clone();
        }
        match trace.controls["veto"].as_str() {
            Some("error") => Err(rejected()),
            Some("deny") => Ok(false),
            _ => Ok(true),
        }
    }
}

#[async_trait::async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Events {
    fn name(&self) -> &'static str {
        "last-login-fixture"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
    async fn before_request(
        &self,
        request: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        let controls = self.0.lock().unwrap().controls.clone();
        let Some(name) = controls["replaceName"].as_str() else {
            return Ok(None);
        };
        let mut body: Value = request.body_as_json()?;
        body["name"] = name.into();
        Ok(Some(BeforeRequestAction::ReplaceBody(serde_json::to_vec(
            &body,
        )?)))
    }
}

macro_rules! hooks {
    ($hook:ident, $context:ident, $control:ident $(, $id:ident)?) => {
        #[async_trait::async_trait]
        impl<S: AuthSchema> $hook<S> for Events {
            async fn before_create_user(&self, user: &mut CreateUser, context: &$context<'_,S>) -> AuthResult<$control> {
                self.record("user.before", context.request.as_ref(), Some(user.additional_fields.get("lastLoginMethod").cloned().unwrap_or(Value::Null)));
                Ok($control::Continue)
            }
            async fn after_create_user(&self, _: &S::User, context: &$context<'_,S>) -> AuthResult<()> { self.record("user.after", context.request.as_ref(), None); Ok(()) }
            async fn before_update_user(&self, $($id: &str,)? user: &UpdateUser, context: &$context<'_,S>) -> AuthResult<DatabaseHookUpdate<UpdateUser>> {
                self.record("user.update", context.request.as_ref(), Some(user.additional_fields.get("lastLoginMethod").cloned().unwrap_or(Value::Null)));
                if self.fails("update") { return Err(rejected()); }
                Ok(DatabaseHookUpdate::Continue)
            }
            async fn after_update_user(&self, _: Option<&S::User>, context: &$context<'_,S>) -> AuthResult<()> { self.record("user.updated", context.request.as_ref(), None); Ok(()) }
            async fn before_create_session(&self, _: &mut CreateSession, context: &$context<'_,S>) -> AuthResult<$control> {
                self.record("session.before", context.request.as_ref(), None);
                if self.fails("session") { return Err(rejected()); }
                Ok($control::Continue)
            }
            async fn after_create_session(&self, _: &S::Session, context: &$context<'_,S>) -> AuthResult<()> { self.record("session.after", context.request.as_ref(), None); Ok(()) }
        }
    };
}
hooks!(DatabaseHooks, DatabaseHookContext, DatabaseHookControl);
hooks!(SeaOrmHooks, SeaOrmHookContext, HookControl, _id);

struct FixtureHasher;
#[async_trait::async_trait]
impl PasswordHasher for FixtureHasher {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        Ok(format!("fixture:{password}"))
    }
    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
        Ok(hash == format!("fixture:{password}"))
    }
}

#[derive(Default)]
struct Cache(Mutex<BTreeMap<String, String>>);
#[async_trait::async_trait]
impl SecondaryStorage for Cache {
    async fn get(&self, key: &str) -> AuthResult<Option<Value>> {
        Ok(self.0.lock().unwrap().get(key).cloned().map(Value::String))
    }
    async fn set(&self, key: &str, value: &str, _: Option<u64>) -> AuthResult<()> {
        let _ = self.0.lock().unwrap().insert(key.into(), value.into());
        Ok(())
    }
    async fn delete(&self, key: &str) -> AuthResult<()> {
        let _ = self.0.lock().unwrap().remove(key);
        Ok(())
    }
    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<Value>> {
        Ok(self.0.lock().unwrap().remove(key).map(Value::String))
    }
}

fn configure(profile: &str, base_url: &str) -> AuthConfig {
    let mut config =
        AuthConfig::new("compat-test-only-key-not-real-minimum-32chars").base_url(base_url);
    config.session.cookie_cache = Some(CookieCacheConfig {
        enabled: Some(true),
        ..Default::default()
    });
    if profile == "last-login-fields" {
        let _ = config.user.additional_fields.insert(
            "lastLoginMethod".into(),
            UserFieldConfig {
                required: Some(true),
                input: true,
                returned: false,
                field_name: Some("alias".into()),
                input_transform: Some(Arc::new(|value| {
                    Ok(Some(json!(format!(
                        "{}:in",
                        value
                            .and_then(|value| value.as_str().map(str::to_owned))
                            .unwrap_or("undefined".into())
                    ))))
                })),
                output_transform: Some(Arc::new(|value| {
                    Ok(Some(json!(format!(
                        "{}:out",
                        value
                            .and_then(|value| value.as_str().map(str::to_owned))
                            .unwrap_or("undefined".into())
                    ))))
                })),
                ..Default::default()
            },
        );
    }
    config
}

pub async fn router(profile: &str, base_url: &str) -> AuthResult<Router> {
    let config = configure(profile, base_url);
    let events = Events::default();
    let cache = Arc::new(Cache::default());
    if profile == "last-login-ephemeral" {
        let builder = BetterAuth::stateless(config).database_hooks(vec![Arc::new(events.clone())]);
        finish(builder, events, cache, profile).await
    } else {
        let database = better_auth_seaorm::sea_orm::Database::connect("sqlite::memory:")
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        crate::user_fields::add_columns(&database)
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let store = SeaOrmStore::<crate::user_fields::Schema>::new(config.clone(), database)
            .with_hooks(vec![Arc::new(events.clone())]);
        finish(
            AuthBuilder::new(config).store(store),
            events,
            cache,
            profile,
        )
        .await
    }
}

struct Fixture<S: AuthSchema> {
    auth: Arc<BetterAuth<S>>,
    events: Events,
    cache: Arc<Cache>,
}
impl<S: AuthSchema> Clone for Fixture<S> {
    fn clone(&self) -> Self {
        Self {
            auth: self.auth.clone(),
            events: self.events.clone(),
            cache: self.cache.clone(),
        }
    }
}

async fn finish<S: AuthSchema>(
    mut builder: AuthBuilder<S>,
    events: Events,
    cache: Arc<Cache>,
    profile: &str,
) -> AuthResult<Router> {
    if profile == "last-login-secondary" {
        builder = builder.secondary_storage(cache.clone());
    }
    let plugin = LastLoginMethodPlugin::new(LastLoginMethodConfig {
        store_in_database: profile != "last-login-cookie",
        cookie_name: if profile == "last-login-cookie" {
            "__Host-login_hint".into()
        } else {
            LastLoginMethodConfig::default().cookie_name
        },
        max_age: if profile == "last-login-cookie" {
            90.9
        } else {
            LastLoginMethodConfig::default().max_age
        },
        field_name: Some("storedLabel".into()),
        ..Default::default()
    })
    .custom_resolve_method(Arc::new(events.clone()))
    .before_store_cookie(Arc::new(events.clone()));
    let auth = Arc::new(
        builder
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(plugin)
            .plugin(events.clone())
            .plugin(EmailPasswordPlugin::new().password_hasher(Arc::new(FixtureHasher)))
            .plugin(SessionManagementPlugin::new())
            .build()
            .await?,
    );
    let api = Router::new()
        .nest("/api/auth", auth.clone().axum_router())
        .with_state(auth.clone());
    Ok(api.merge(
        Router::new()
            .route("/health", get(|| async { Json(json!({"status":"ok"})) }))
            .route("/__health", get(|| async { Json(json!({"status":"ok"})) }))
            .route("/__test/reset-state", post(reset::<S>))
            .route("/__test/last-login/native", post(native_signup::<S>))
            .route("/__test/last-login", get(snapshot::<S>).post(control::<S>))
            .with_state(Fixture {
                auth,
                events,
                cache,
            }),
    ))
}

async fn snapshot<S: AuthSchema>(State(fixture): State<Fixture<S>>) -> Json<Value> {
    let users = fixture
        .auth
        .store()
        .list_users(Default::default())
        .await
        .unwrap()
        .0
        .into_iter()
        .map(|user| {
            let view = fixture.auth.context().internal_user_view(&user).unwrap();
            json!({"email":user.email(),"method":view.additional_fields.get("lastLoginMethod")})
        })
        .collect::<Vec<_>>();
    let events = fixture.events.0.lock().unwrap().events.clone();
    let cache = fixture
        .cache
        .0
        .lock()
        .unwrap()
        .values()
        .filter(|value| value.contains("\"user\""))
        .map(|value| {
            let value: Value = serde_json::from_str(value).unwrap();
            json!({"method":value["user"]["lastLoginMethod"]})
        })
        .collect::<Vec<_>>();
    Json(json!({"events":events,"users":users,"cache":cache}))
}
async fn control<S: AuthSchema>(
    State(fixture): State<Fixture<S>>,
    Json(value): Json<Value>,
) -> Json<Value> {
    *fixture.events.0.lock().unwrap() = Trace {
        controls: value,
        ..Default::default()
    };
    snapshot(State(fixture)).await
}
async fn reset<S: AuthSchema>(State(fixture): State<Fixture<S>>) -> Json<Value> {
    for user in fixture
        .auth
        .store()
        .list_users(Default::default())
        .await
        .unwrap()
        .0
    {
        fixture.auth.store().delete_user(&user.id()).await.unwrap();
    }
    *fixture.events.0.lock().unwrap() = Trace::default();
    fixture.cache.0.lock().unwrap().clear();
    Json(json!({"success":true}))
}

async fn native_signup<S: AuthSchema>(
    State(fixture): State<Fixture<S>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let response = fixture
        .auth
        .call_endpoint(
            better_auth_core::HttpMethod::Post,
            "/sign-up/email",
            better_auth::server_api::EndpointInput {
                body: Some(body),
                headers: Some([("x-login-context".into(), "native-header".into())].into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    Json(
        json!({ "body":body, "cookies":response.headers.get_all("set-cookie").collect::<Vec<_>>() }),
    )
}
