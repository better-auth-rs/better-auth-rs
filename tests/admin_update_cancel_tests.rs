use async_trait::async_trait;
use better_auth::plugins::AdminPlugin;
use better_auth::server_api::EndpointInput;
use better_auth::{AuthBuilder, BetterAuth};
use better_auth_core::middleware::RateLimitConfig;
use better_auth_core::store::database_hooks::{
    DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks,
};
use better_auth_core::store::{EphemeralStore, StatelessSchema};
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse,
    AuthResult, AuthRoute, AuthSchema, AuthStore, CookieCacheConfig, CreateSession, CreateUser,
    HttpMethod, SchemaValue, UpdateUser, UserView, utils::cookie_utils::sign_cookie_value,
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

const ORIGIN: &str = "http://admin-update-cancel.test";
const SECRET: &str = "ordinary-admin-display-update-secret-at-least-32-characters";
const MESSAGE: &str = "ordinary display hook error";
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clone)]
struct Observer {
    mode: &'static str,
    events: Arc<Mutex<Vec<Value>>>,
}

impl Observer {
    fn record(&self, phase: &str, name: Option<Value>) -> AuthResult<()> {
        self.events
            .lock()
            .map_err(|_| AuthError::internal("ordinary trace lock poisoned"))?
            .push(json!({"phase":phase,"name":name}));
        Ok(())
    }
}

#[better_auth::database_hooks]
impl<S: AuthSchema> DatabaseHooks<S> for Observer {
    async fn before_update_user(
        &self,
        update: &UpdateUser,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<UpdateUser>> {
        self.record("before", update.name.json()?)?;
        match self.mode {
            "cancel" => Ok(DatabaseHookUpdate::Cancel),
            "error" => Err(AuthError::internal(MESSAGE)),
            _ => Ok(DatabaseHookUpdate::Continue),
        }
    }

    async fn after_update_user(
        &self,
        user: Option<&UserView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record(
            "after",
            user.map(|user| user.name.json()).transpose()?.flatten(),
        )
    }
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Observer {
    fn name(&self) -> &'static str {
        "ordinary-admin-display-hook"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.register_database_hook(Arc::new(self.clone()));
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

fn config() -> AuthConfig {
    let mut config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .disable_session_refresh(true)
        .session_cookie_cache(CookieCacheConfig {
            enabled: Some(false),
            ..Default::default()
        });
    config.logger.disabled = Some(true);
    config
}

fn response_user(mut body: Value) -> Result<Value> {
    if body.is_null() {
        return Ok(body);
    }
    let updated = body
        .as_object_mut()
        .and_then(|body| body.get_mut("updatedAt"))
        .ok_or("The successful response must contain an update timestamp")?;
    let _ = DateTime::parse_from_rfc3339(updated.as_str().ok_or("String update timestamp")?)?;
    *updated = json!("<timestamp>");
    Ok(body)
}

async fn observe<S: AuthSchema>(
    store: impl AuthStore<S> + 'static,
    backend: &str,
    channel: &str,
    mode: &'static str,
) -> Result<Value> {
    let observer = Observer {
        mode,
        events: Arc::default(),
    };
    let auth: BetterAuth<S> = AuthBuilder::new(config())
        .store(store)
        .rate_limit(RateLimitConfig::new().enabled(false))
        .plugin(AdminPlugin::new())
        .plugin(observer.clone())
        .build()
        .await?;
    let created_at: DateTime<Utc> = "2025-01-01T00:00:00Z".parse()?;
    for (id, name, role) in [
        ("actor", "Ordinary Admin", "admin"),
        ("target", "Original", "user"),
    ] {
        let _ = auth
            .store()
            .create_user(CreateUser {
                id: Some(id.into()),
                name: Some(name.into()).into(),
                image: SchemaValue::Typed(None),
                email: Some(format!("{id}@admin-update-cancel.test")),
                email_verified: Some(true),
                role: Some(role.into()),
                banned: Some(false),
                created_at: Some(created_at),
                updated_at: Some(created_at),
                ..Default::default()
            })
            .await?;
    }
    let actor = auth
        .store()
        .create_session(CreateSession {
            user_id: "actor".into(),
            expires_at: "2099-01-01T00:00:00Z".parse()?,
            additional_fields: Default::default(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?;
    let headers = [
        ("content-type".into(), "application/json".into()),
        ("origin".into(), ORIGIN.into()),
        (
            "cookie".into(),
            format!(
                "better-auth.session_token={}",
                sign_cookie_value(&actor.token, SECRET)
            ),
        ),
    ]
    .into();
    let body = json!({"userId":"target","data":{"name":"Changed"}});
    let before = auth
        .store()
        .get_user_by_id("target")
        .await?
        .ok_or("Seeded display user")?;
    let mut returned = None;
    let outcome = if channel == "http" {
        let response = auth
            .handle_request(
                AuthRequest::from_parts(
                    HttpMethod::Post,
                    "/api/auth/admin/update-user".into(),
                    headers,
                    Some(serde_json::to_vec(&body)?),
                    None,
                )
                .with_url(format!("{ORIGIN}/api/auth/admin/update-user").parse()?),
            )
            .await?;
        let mut headers: Vec<_> = response
            .headers
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
            .collect();
        headers.sort();
        if response.status < 300 {
            let body: Value = serde_json::from_slice(&response.body.bytes()?)?;
            returned = Some(body.clone());
            json!({"status":response.status,"headers":headers,"body":response_user(body)?})
        } else {
            json!({"status":response.status,"headers":headers,"bodyText":String::from_utf8(response.body.into_bytes()?)?})
        }
    } else {
        match auth
            .call_endpoint(
                HttpMethod::Post,
                "/admin/update-user",
                EndpointInput {
                    headers: Some(headers),
                    body: Some(body),
                    ..Default::default()
                },
            )
            .await
        {
            Ok(response) => {
                let body: Value = serde_json::from_slice(&response.body.bytes()?)?;
                returned = Some(body.clone());
                json!({"body":response_user(body)?})
            }
            Err(AuthError::Internal(message)) if message == MESSAGE => {
                json!({"error":{"message":message,"original":true}})
            }
            Err(error) => return Err(error.into()),
        }
    };
    let after = auth
        .store()
        .get_user_by_id("target")
        .await?
        .ok_or("Seeded display user")?;
    let response_matches_stored = if let Some(body) = returned.filter(|body| !body.is_null()) {
        Some(body == serde_json::to_value(auth.context().user_view(&after).await?)?)
    } else {
        None
    };
    let events = observer
        .events
        .lock()
        .map_err(|_| "ordinary trace lock poisoned")?
        .clone();
    Ok(json!({
        "backend":backend,"channel":channel,"mode":mode,"outcome":outcome,"events":events,
        "storedName":after.name,"storedUnchanged":before == after,
        "responseMatchesStored":response_matches_stored,
    }))
}

fn expected(backend: &str) -> Result<Value> {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/admin-update-cancel-1.7.6.json"))?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("Captured cases")?;
    Ok(Value::Array(
        cases
            .iter()
            .filter(|case| case.get("backend").and_then(Value::as_str) == Some(backend))
            .cloned()
            .collect(),
    ))
}

#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "A failed setup or observation must stop the ordinary captured contract."
)]
async fn memory_admin_display_updates_preserve_nullable_hook_results() {
    let mut actual = Vec::new();
    for channel in ["http", "native"] {
        for mode in ["success", "cancel", "error"] {
            actual.push(
                observe::<StatelessSchema>(
                    EphemeralStore::new(Arc::new(config())),
                    "memory",
                    channel,
                    mode,
                )
                .await
                .expect("ordinary Memory display update"),
            );
        }
    }
    assert_eq!(
        json!(actual),
        expected("memory").expect("captured Memory cases")
    );
}

#[cfg(feature = "seaorm2")]
#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "A failed SQLite setup or observation must stop the ordinary captured contract."
)]
async fn sqlite_admin_display_updates_preserve_nullable_hook_results() {
    use better_auth_seaorm::{
        SeaOrmStore,
        sea_orm::Database,
        store::__private_test_support::{bundled_schema::BundledSchema, migrator},
    };
    let mut actual = Vec::new();
    for channel in ["http", "native"] {
        for mode in ["success", "cancel", "error"] {
            let database = Database::connect("sqlite::memory:")
                .await
                .expect("ordinary SQLite database");
            migrator::run_migrations(&database)
                .await
                .expect("ordinary SQLite schema");
            actual.push(
                observe(
                    SeaOrmStore::<BundledSchema>::new(config(), database),
                    "sqlite",
                    channel,
                    mode,
                )
                .await
                .expect("ordinary SQLite display update"),
            );
        }
    }
    assert_eq!(
        json!(actual),
        expected("sqlite").expect("captured SQLite cases")
    );
}
