use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
};

use axum::{
    Json, Router,
    extract::{FromRef, State},
    routing::{get, post},
};
use better_auth::{
    AuthConfig, AuthError, AuthResult, BetterAuth, integrations::axum::AxumIntegration,
};
use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute, AuthSchema,
    middleware::{
        CustomRateLimitRule, EndpointRateLimit, PluginRateLimit, RateLimitConfig,
        RateLimitDecision, RateLimitOverride, RateLimitRuleResolver, RateLimitStorage,
        RateLimitStorageKind,
    },
    store::SecondaryStorage,
};
use better_auth_seaorm::{
    Database, SeaOrmStore,
    sea_orm::{self, EntityTrait, QueryOrder},
    store::{
        __private_test_support::{bundled_schema::BundledSchema, migrator},
        entities::rate_limit,
    },
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Options {
    backend: Option<String>,
    policy: Option<String>,
    window: Option<String>,
    max: Option<String>,
    #[serde(default)]
    custom: bool,
    #[serde(default)]
    secondary: bool,
    #[serde(default)]
    disabled_ip: bool,
}

fn number_string(value: f64) -> String {
    if value == f64::INFINITY {
        "Infinity".into()
    } else if value == f64::NEG_INFINITY {
        "-Infinity".into()
    } else {
        value.to_string()
    }
}

fn database_error(error: sea_orm::DbErr) -> AuthError {
    AuthError::internal(format!("Rate limit fixture database: {error}"))
}

#[derive(Default)]
struct Trace {
    events: Vec<Value>,
    counters: HashMap<String, (f64, f64)>,
}

#[derive(Clone)]
struct Fixture {
    auth: Arc<RwLock<Arc<BetterAuth<BundledSchema>>>>,
    options: Arc<Mutex<Options>>,
    base_url: String,
    trace: Arc<Mutex<Trace>>,
    database: sea_orm::DatabaseConnection,
}

impl FromRef<Fixture> for Arc<BetterAuth<BundledSchema>> {
    fn from_ref(fixture: &Fixture) -> Self {
        fixture.auth.read().unwrap().clone()
    }
}

struct LimitPlugin {
    index: usize,
    trace: Arc<Mutex<Trace>>,
}
#[async_trait::async_trait]
impl<S: AuthSchema> AuthPlugin<S> for LimitPlugin {
    fn name(&self) -> &'static str {
        if self.index == 0 {
            "fixture-limit-0"
        } else {
            "fixture-limit-1"
        }
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    fn rate_limits(&self) -> AuthResult<Vec<PluginRateLimit>> {
        let trace = self.trace.clone();
        let index = self.index;
        Ok(vec![PluginRateLimit::new(
            EndpointRateLimit {
                window: 21.0 + index as f64,
                max_requests: 4.0 + index as f64,
            },
            move |path| {
                trace
                    .lock()
                    .unwrap()
                    .events
                    .push(json!({"kind":"matcher","index":index,"path":path}));
                Ok(true)
            },
        )])
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

struct Resolver {
    policy: String,
    trace: Arc<Mutex<Trace>>,
}
#[async_trait::async_trait]
impl RateLimitRuleResolver for Resolver {
    async fn resolve(
        &self,
        request: &AuthRequest,
        current: EndpointRateLimit,
    ) -> AuthResult<RateLimitOverride> {
        let path = request
            .url()
            .map(|url| match url.query() {
                Some(query) => format!("{}?{query}", url.path()),
                None => url.path().to_owned(),
            })
            .unwrap_or_else(|| request.path().to_owned());
        self.trace.lock().unwrap().events.push(json!({"kind":"rule","path":path,"window":number_string(current.window),"max":number_string(current.max_requests)}));
        tokio::task::yield_now().await;
        Ok(match self.policy.as_str() {
            "disabled" => RateLimitOverride::Disabled,
            "unchanged" => RateLimitOverride::Unchanged,
            _ => RateLimitOverride::Limit(EndpointRateLimit {
                window: 7.5,
                max_requests: 1.5,
            }),
        })
    }
}

struct CustomStorage(Arc<Mutex<Trace>>);
#[async_trait::async_trait]
impl RateLimitStorage for CustomStorage {
    async fn consume(&self, key: &str, rule: EndpointRateLimit) -> AuthResult<RateLimitDecision> {
        self.0.lock().unwrap().events.push(json!({"kind":"consume","key":key,"window":number_string(rule.window),"max":number_string(rule.max_requests)}));
        Ok(RateLimitDecision {
            allowed: false,
            retry_after: None,
        })
    }
}

struct MissingIncrement;
#[async_trait::async_trait]
impl SecondaryStorage for MissingIncrement {
    async fn get(&self, _: &str) -> AuthResult<Option<Value>> {
        Ok(None)
    }
    async fn set(&self, _: &str, _: &str, _: Option<u64>) -> AuthResult<()> {
        Ok(())
    }
    async fn delete(&self, _: &str) -> AuthResult<()> {
        Ok(())
    }
    async fn get_and_delete(&self, _: &str) -> AuthResult<Option<Value>> {
        Ok(None)
    }
}

struct CounterStorage(Arc<Mutex<Trace>>);
#[async_trait::async_trait]
impl SecondaryStorage for CounterStorage {
    async fn get(&self, _: &str) -> AuthResult<Option<Value>> {
        Ok(None)
    }
    async fn set(&self, _: &str, _: &str, _: Option<u64>) -> AuthResult<()> {
        Ok(())
    }
    async fn delete(&self, _: &str) -> AuthResult<()> {
        Ok(())
    }
    async fn get_and_delete(&self, _: &str) -> AuthResult<Option<Value>> {
        Ok(None)
    }
    async fn increment(&self, key: &str, ttl: f64) -> AuthResult<f64> {
        let mut trace = self.0.lock().unwrap();
        trace
            .events
            .push(json!({"kind":"increment","key":key,"ttl":number_string(ttl)}));
        let now = chrono::Utc::now().timestamp_millis() as f64;
        let (count, expires) = trace
            .counters
            .get(key)
            .copied()
            .filter(|(_, expires)| now < *expires)
            .unwrap_or((0.0, now + ttl * 1000.0));
        let count = count + 1.0;
        trace.counters.insert(key.to_owned(), (count, expires));
        Ok(count)
    }
}

async fn build(
    base_url: &str,
    options: &Options,
    trace: Arc<Mutex<Trace>>,
    database: sea_orm::DatabaseConnection,
) -> AuthResult<Arc<BetterAuth<BundledSchema>>> {
    let mut config = AuthConfig::new("rate-limit-fixture-secret-at-least-thirty-two-characters")
        .base_url(base_url)
        .base_path("/api/limits");
    config.advanced.ip_address.disable_ip_tracking = options.disabled_ip;
    let mut rate = RateLimitConfig::new().enabled(true);
    rate.storage = match options.backend.as_deref().unwrap_or("memory") {
        "auto" => None,
        "database" => Some(RateLimitStorageKind::Database),
        "secondary" | "missing" => Some(RateLimitStorageKind::Secondary),
        _ => Some(RateLimitStorageKind::Memory),
    };
    if options.custom {
        rate.custom_storage = Some(Arc::new(CustomStorage(trace.clone())));
    }
    match options.policy.as_deref() {
        Some("numeric") => {
            rate = rate.rule(
                "/**",
                EndpointRateLimit {
                    window: options
                        .window
                        .as_deref()
                        .unwrap_or("10")
                        .parse()
                        .map_err(|error| {
                            AuthError::validation(format!("Invalid fixture window: {error}"))
                        })?,
                    max_requests: options.max.as_deref().unwrap_or("100").parse().map_err(
                        |error| AuthError::validation(format!("Invalid fixture maximum: {error}")),
                    )?,
                },
            );
        }
        Some(policy @ ("first" | "disabled" | "unchanged")) => {
            rate = rate
                .rule(
                    "/**",
                    CustomRateLimitRule::Dynamic(Arc::new(Resolver {
                        policy: policy.to_owned(),
                        trace: trace.clone(),
                    })),
                )
                .rule("/ok", RateLimitOverride::Disabled);
        }
        _ => {}
    }
    let store = SeaOrmStore::<BundledSchema>::new(config.clone(), database);
    let mut builder = BetterAuth::new(config).store(store).rate_limit(rate);
    if matches!(
        options.policy.as_deref(),
        Some("plugins" | "first" | "disabled" | "unchanged")
    ) {
        builder = builder
            .plugin(LimitPlugin {
                index: 0,
                trace: trace.clone(),
            })
            .plugin(LimitPlugin {
                index: 1,
                trace: trace.clone(),
            });
    }
    if options.secondary
        || matches!(
            options.backend.as_deref(),
            Some("secondary" | "auto" | "missing")
        )
    {
        builder = if options.backend.as_deref() == Some("missing") {
            builder.secondary_storage(Arc::new(MissingIncrement))
        } else {
            builder.secondary_storage(Arc::new(CounterStorage(trace)))
        };
    }
    Ok(Arc::new(builder.build().await?))
}

pub async fn router(base_url: &str) -> AuthResult<Router> {
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(database_error)?;
    migrator::run_migrations(&database)
        .await
        .map_err(database_error)?;
    let trace = Arc::new(Mutex::new(Trace::default()));
    let options = Options::default();
    let auth = build(base_url, &options, trace.clone(), database.clone()).await?;
    let fixture = Fixture {
        auth: Arc::new(RwLock::new(auth.clone())),
        options: Arc::new(Mutex::new(options)),
        base_url: base_url.to_owned(),
        trace,
        database,
    };
    Ok(Router::new()
        .nest("/api/limits", auth.axum_router_with_state::<Fixture>())
        .route("/health", get(|| async { Json(json!({"status":"ok"})) }))
        .route("/__health", get(|| async { Json(json!({"status":"ok"})) }))
        .route("/__test/reset-state", post(reset))
        .route("/__test/rate-limit", get(snapshot).post(control))
        .with_state(fixture))
}

async fn snapshot(State(fixture): State<Fixture>) -> Result<Json<Value>, AuthError> {
    let rows = rate_limit::Entity::find()
        .order_by_asc(rate_limit::Column::Key)
        .all(&fixture.database)
        .await
        .map_err(database_error)?;
    let rows: Vec<Value> = rows
        .into_iter()
        .map(|row| json!({"key":row.key,"count":f64::from(row.count)}))
        .collect();
    Ok(Json(
        json!({"events":fixture.trace.lock().unwrap().events,"rows":rows}),
    ))
}

async fn reset(State(fixture): State<Fixture>) -> Result<Json<Value>, AuthError> {
    let _ = rate_limit::Entity::delete_many()
        .exec(&fixture.database)
        .await
        .map_err(database_error)?;
    *fixture.trace.lock().unwrap() = Trace::default();
    *fixture.options.lock().unwrap() = Options::default();
    let auth = build(
        &fixture.base_url,
        &Options::default(),
        fixture.trace.clone(),
        fixture.database.clone(),
    )
    .await?;
    *fixture.auth.write().unwrap() = auth;
    Ok(Json(json!({"success":true})))
}

async fn control(
    State(fixture): State<Fixture>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AuthError> {
    if let Some(config) = body.get("config") {
        *fixture.options.lock().unwrap() = serde_json::from_value(config.clone())
            .map_err(|error| AuthError::validation(error.to_string()))?;
    }
    if body["clearEvents"] == true {
        fixture.trace.lock().unwrap().events.clear();
    }
    if body.get("config").is_some() || body["restart"] == true {
        let options = fixture.options.lock().unwrap().clone();
        let auth = build(
            &fixture.base_url,
            &options,
            fixture.trace.clone(),
            fixture.database.clone(),
        )
        .await?;
        *fixture.auth.write().unwrap() = auth;
    }
    snapshot(State(fixture)).await
}
