use std::sync::{Arc, Mutex, RwLock};

use axum::{
    Json, Router,
    extract::{Form, FromRef, State},
    response::IntoResponse,
    routing::{get, post},
};
use better_auth::{
    AuthConfig, AuthError, AuthResult, BetterAuth, PasswordHasher,
    config::{CookieCacheConfig, CookieCacheRefresh, CookieCacheStrategy, OAuthStateStrategy},
    integrations::axum::{AxumIntegration, CachedSession},
    plugins::{
        AccountManagementPlugin, EmailPasswordPlugin, OAuthPlugin, SessionManagementPlugin,
        oauth::GenericOAuthConfig,
    },
    store::{DatabaseHookContext, DatabaseHookControl, DatabaseHooks, StatelessSchema},
};
use better_auth_core::{
    CreateSession, CreateUser, SessionView, UserView,
    middleware::RateLimitConfig,
    store::{CacheAdapter, MemoryCacheAdapter},
};
use chrono::Duration;
use serde_json::{Value, json};

#[derive(Default)]
struct Trace {
    events: Vec<Value>,
    tokens: Vec<Value>,
}

#[derive(Clone)]
struct Fixture {
    auth: Arc<RwLock<Arc<BetterAuth<StatelessSchema>>>>,
    profile: String,
    base_url: String,
    trace: Arc<Mutex<Trace>>,
    cache: Arc<MemoryCacheAdapter>,
}

impl FromRef<Fixture> for Arc<BetterAuth<StatelessSchema>> {
    fn from_ref(value: &Fixture) -> Self {
        value.auth.read().unwrap().clone()
    }
}

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

struct Hooks(Arc<Mutex<Trace>>);
impl Hooks {
    fn record(
        &self,
        kind: &str,
        email: Option<&str>,
        context: &DatabaseHookContext<'_, StatelessSchema>,
    ) {
        self.0.lock().unwrap().events.push(json!({ "kind":kind, "email":email, "path": context.request.as_ref().and_then(|request| request.path.as_deref()), "http":context.request.as_ref().is_some_and(|request|request.is_http) }));
    }
}
#[better_auth::database_hooks()]
impl DatabaseHooks<StatelessSchema> for Hooks {
    async fn before_create_user(
        &self,
        user: &mut CreateUser,
        ctx: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookControl> {
        self.record("user.before", user.email.as_deref(), ctx);
        Ok(DatabaseHookControl::Continue)
    }
    async fn after_create_user(
        &self,
        user: &UserView,
        ctx: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        self.record("user.after", user.email.as_deref(), ctx);
        Ok(())
    }
    async fn before_create_session(
        &self,
        _: &mut CreateSession,
        ctx: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookControl> {
        self.record("session.before", None, ctx);
        Ok(DatabaseHookControl::Continue)
    }
    async fn after_create_session(
        &self,
        _: &SessionView,
        ctx: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        self.record("session.after", None, ctx);
        Ok(())
    }
}

async fn build(
    profile: &str,
    base_url: &str,
    trace: Arc<Mutex<Trace>>,
    cache: Arc<MemoryCacheAdapter>,
) -> AuthResult<Arc<BetterAuth<StatelessSchema>>> {
    let mut config =
        AuthConfig::new("compat-test-only-key-not-real-minimum-32chars").base_url(base_url);
    config.session.expires_in = Duration::seconds(600);
    match profile {
        "stateless-explicit" => {
            config.account.store_account_cookie = Some(false);
            config.account.store_state_strategy = Some(OAuthStateStrategy::Database);
            config.session.cookie_cache = Some(CookieCacheConfig {
                enabled: Some(false),
                refresh: Some(CookieCacheRefresh::Disabled),
                ..Default::default()
            });
        }
        "stateless-refresh" | "stateless-no-refresh" => {
            config.session.cookie_cache = Some(CookieCacheConfig {
                max_age: Some(Duration::seconds(5)),
                refresh: Some(if profile == "stateless-refresh" {
                    CookieCacheRefresh::After(Duration::seconds(4))
                } else {
                    CookieCacheRefresh::Disabled
                }),
                ..Default::default()
            })
        }
        "stateless-secondary" => {
            config.session.cookie_cache = Some(CookieCacheConfig {
                enabled: Some(true),
                max_age: Some(Duration::seconds(60)),
                strategy: Some(CookieCacheStrategy::Jwe),
                refresh: Some(CookieCacheRefresh::Enabled),
                ..Default::default()
            })
        }
        _ => {}
    }
    let mut builder = BetterAuth::stateless(config)
        .database_hooks(vec![Arc::new(Hooks(trace))])
        .rate_limit(RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new().password_hasher(Arc::new(FixtureHasher)))
        .plugin(SessionManagementPlugin::new())
        .plugin(AccountManagementPlugin::new())
        .plugin(OAuthPlugin::new().add_generic_provider(
            "mock",
            GenericOAuthConfig {
                client_id: "fixture-client".into(),
                client_secret: Some("fixture-secret".into()),
                authorization_url: Some(format!("{base_url}/__test/provider/authorize")),
                token_url: Some(format!("{base_url}/__test/provider/token")),
                user_info_url: Some(format!("{base_url}/__test/provider/user")),
                scopes: vec!["email".into()],
                ..Default::default()
            },
        ));
    if profile == "stateless-secondary" {
        builder = builder.secondary_storage(cache);
    }
    Ok(Arc::new(builder.build().await?))
}

pub async fn router(profile: &str, base_url: &str) -> AuthResult<Router> {
    let trace = Arc::new(Mutex::new(Trace::default()));
    let cache = Arc::new(MemoryCacheAdapter::new());
    let auth = build(profile, base_url, trace.clone(), cache.clone()).await?;
    let fixture = Fixture {
        auth: Arc::new(RwLock::new(auth.clone())),
        profile: profile.into(),
        base_url: base_url.into(),
        trace,
        cache,
    };
    Ok(Router::new()
        .nest("/api/auth", auth.axum_router_with_state::<Fixture>())
        .route("/health", get(|| async { Json(json!({"status":"ok"})) }))
        .route("/__health", get(|| async { Json(json!({"status":"ok"})) }))
        .route("/__test/reset-state", post(reset))
        .route("/__test/stateless", get(snapshot).post(control))
        .route("/__test/cached-session", get(cached_session))
        .route("/__test/provider/token", post(token))
        .route("/__test/provider/user", get(|| async { Json(json!({"id":"provider-user", "email":"stateless@example.com", "email_verified":true, "name":"Stateless"})) }))
        .with_state(fixture))
}

async fn cached_session(session: CachedSession<StatelessSchema>) -> impl IntoResponse {
    let body = Json(json!({"user":session.user,"session":session.session}));
    (session, body)
}

async fn snapshot(State(fixture): State<Fixture>) -> Result<Json<Value>, AuthError> {
    let auth = Arc::<BetterAuth<StatelessSchema>>::from_ref(&fixture);
    let users = auth.store().list_users(Default::default()).await?.1;
    let trace = fixture.trace.lock().unwrap();
    Ok(Json(
        json!({"events":trace.events, "tokenRequests":trace.tokens, "users":users}),
    ))
}

async fn reset(State(fixture): State<Fixture>) -> Result<Json<Value>, AuthError> {
    CacheAdapter::clear(fixture.cache.as_ref()).await?;
    *fixture.trace.lock().unwrap() = Trace::default();
    let auth = build(
        &fixture.profile,
        &fixture.base_url,
        fixture.trace.clone(),
        fixture.cache.clone(),
    )
    .await?;
    *fixture.auth.write().unwrap() = auth;
    Ok(Json(json!({"success":true})))
}

async fn control(
    State(fixture): State<Fixture>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    async {
        if body["restart"] == true {
            let auth = build(
                &fixture.profile,
                &fixture.base_url,
                fixture.trace.clone(),
                fixture.cache.clone(),
            )
            .await?;
            *fixture.auth.write().unwrap() = auth;
        }
        let auth = Arc::<BetterAuth<StatelessSchema>>::from_ref(&fixture);
        if let Some(token) = body["revoke"].as_str() {
            auth.store().delete_session(token).await?;
        }
        if body["clearEvents"] == true {
            fixture.trace.lock().unwrap().events.clear();
        }
        snapshot(State(fixture)).await
    }
    .await
    .into_response()
}

async fn token(
    State(fixture): State<Fixture>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Json<Value> {
    let grant = form.get("grant_type");
    fixture.trace.lock().unwrap().tokens.push(json!({"grant":grant,"verifier":form.get("code_verifier").is_some_and(|value|!value.is_empty()),"refresh":form.get("refresh_token")}));
    Json(
        json!({"access_token":if grant.is_some_and(|grant|grant=="refresh_token") {"refreshed-access"} else {"initial-access"},"refresh_token":"refresh-token","token_type":"Bearer","expires_in":60,"scope":"email"}),
    )
}
