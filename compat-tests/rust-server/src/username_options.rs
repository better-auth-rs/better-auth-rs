use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    routing::{get, post},
};
use better_auth::plugins::{
    EmailPasswordPlugin, SessionManagementPlugin, UserManagementPlugin, UsernameConfig,
    UsernameNormalization, UsernamePlugin, UsernameValidationOrder, UsernameValidator,
};
use better_auth::plugins::{
    admin::{AdminApi, AdminPlugin, CreateAdminUser},
    email_otp::{EmailOtpCallbacks, EmailOtpPlugin},
    phone_number::PhoneNumberPlugin,
};
use better_auth::{
    AuthBuilder, AuthConfig, AuthError, AuthResult, AuthSchema, BetterAuth, PasswordHasher,
    integrations::axum::AxumIntegration,
};
use better_auth_core::{
    AuthUser, CreateUser, HttpMethod, UpdateUser, config::CookieCacheConfig,
    middleware::RateLimitConfig,
};
use better_auth_seaorm::{
    SeaOrmStore,
    hooks::{DatabaseHookUpdate, HookControl, SeaOrmHookContext, SeaOrmHooks},
    sea_orm::{
        ConnectionTrait, DatabaseConnection, DbBackend, Schema as DatabaseSchema, Statement,
    },
};
use serde_json::{Map, Value, json};

mod models;

struct Schema<U>(std::marker::PhantomData<U>);
impl<U: AuthUser> AuthSchema for Schema<U> {
    type User = U;
    type Session = better_auth_seaorm::store::entities::session::Model;
    type Account = better_auth_seaorm::store::entities::account::Model;
    type Verification = better_auth_seaorm::store::entities::verification::Model;
}

#[derive(Default)]
struct Trace {
    calls: Vec<String>,
    events: Vec<Value>,
    controls: Value,
}
#[derive(Clone, Default)]
struct Events(Arc<Mutex<Trace>>);
impl Events {
    fn record(
        &self,
        kind: &str,
        username: &Option<Option<String>>,
        display: &Option<Option<String>>,
        fields: &Map<String, Value>,
        request: Option<&better_auth_core::RequestHookContext>,
    ) {
        let mut event = json!({"kind":kind,"path":request.map(|value|&value.path),"http":request.is_some_and(|value|value.is_http)});
        for name in ["username", "displayUsername"] {
            if let Some(value) = fields.get(name) {
                event[name] = value.clone();
            }
        }
        if let Some(value) = username {
            event["username"] = json!(value);
        }
        if let Some(value) = display {
            event["displayUsername"] = json!(value);
        }
        self.0.lock().unwrap().events.push(event);
    }
    fn normalize(&self, prefix: &'static str, value: &str, output: String) -> AuthResult<String> {
        self.0
            .lock()
            .unwrap()
            .calls
            .push(format!("{prefix}:{value}"));
        Ok(output)
    }
}

struct Validator {
    events: Events,
    display: bool,
}
#[async_trait]
impl UsernameValidator for Validator {
    async fn validate(&self, value: &str) -> AuthResult<bool> {
        let (prefix, control) = if self.display {
            ("display-validate", "displayValidator")
        } else {
            ("validate", "validator")
        };
        let mode = {
            let mut state = self.events.0.lock().unwrap();
            state.calls.push(format!("{prefix}:{value}"));
            state.controls[control].clone()
        };
        tokio::task::yield_now().await;
        if mode == "error" {
            return Err(AuthError::Upstream {
                status: 403,
                code: "USERNAME_CALLBACK_REJECTED",
                message: "Username callback rejected",
            });
        }
        Ok(mode != "deny")
    }
}

#[better_auth::database_hooks()]
impl<S: AuthSchema> SeaOrmHooks<S> for Events {
    async fn before_create_user(
        &self,
        user: &mut CreateUser,
        context: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<HookControl> {
        self.record(
            "create",
            &user.username,
            &user.display_username,
            &user.additional_fields,
            context.request.as_ref(),
        );
        Ok(HookControl::Continue)
    }
    async fn before_update_user(
        &self,
        _: &str,
        update: &UpdateUser,
        context: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<UpdateUser>> {
        self.record(
            "update",
            &update.username,
            &update.display_username,
            &update.additional_fields,
            context.request.as_ref(),
        );
        Ok(if self.0.lock().unwrap().controls["echoUpdate"] == true {
            DatabaseHookUpdate::Patch(update.clone())
        } else {
            DatabaseHookUpdate::Continue
        })
    }
}

struct FixtureHasher;
#[async_trait]
impl PasswordHasher for FixtureHasher {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        Ok(format!("fixture:{password}"))
    }
    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
        Ok(hash == format!("fixture:{password}"))
    }
}

fn configure(profile: &str, events: &Events) -> UsernameConfig {
    let mut config = UsernameConfig::default();
    if profile.starts_with("username-order-") || profile == "username-writes" {
        config.min_username_length = 1.0;
        config.username_validator = Some(Arc::new(Validator {
            events: events.clone(),
            display: false,
        }));
        let trace = events.clone();
        config.username_normalization = UsernameNormalization::Custom(Arc::new(move |value| {
            trace.normalize("normalize", value, format!("n{value}"))
        }));
        let trace = events.clone();
        config.display_username_normalization =
            UsernameNormalization::Custom(Arc::new(move |value| {
                trace.normalize("display", value, format!("d{value}"))
            }));
        if !matches!(profile, "username-order-default" | "username-writes") {
            let order = if profile == "username-order-post" {
                UsernameValidationOrder::PostNormalization
            } else {
                UsernameValidationOrder::PreNormalization
            };
            config.username_validation_order = Some(order);
            config.display_username_validation_order = Some(order);
        }
    } else if profile == "username-immutable-validation" {
        config.immutable_username = true;
        config.min_username_length = 3.5;
        config.max_username_length = 6.5;
        config.username_validator = Some(Arc::new(Validator {
            events: events.clone(),
            display: false,
        }));
        config.display_username_validator = Some(Arc::new(Validator {
            events: events.clone(),
            display: true,
        }));
        let trace = events.clone();
        config.display_username_normalization =
            UsernameNormalization::Custom(Arc::new(move |value| {
                trace.normalize("display", value, value.trim().into())
            }));
        config.display_username_validation_order = Some(UsernameValidationOrder::PostNormalization);
    } else if profile == "username-no-display" {
        config.display_username = false;
    } else {
        config.username_normalization = UsernameNormalization::Disabled;
        config.display_username_normalization = UsernameNormalization::Disabled;
    }
    if profile == "username-order-post" {
        config.username_field_name = Some("login_name".into());
        config.display_username_field_name = Some("display_label".into());
    }
    config
}

pub async fn router(profile: &str, base: &str) -> AuthResult<Router> {
    let mut config =
        AuthConfig::new("username-fixture-secret-with-at-least-32-characters").base_url(base);
    config.session.cookie_cache = Some(CookieCacheConfig {
        enabled: Some(false),
        ..Default::default()
    });
    let database = better_auth_seaorm::Database::connect("sqlite::memory:")
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    let schema = DatabaseSchema::new(DbBackend::Sqlite);
    for statement in [
        schema.create_table_from_entity(better_auth_seaorm::store::entities::session::Entity),
        schema.create_table_from_entity(better_auth_seaorm::store::entities::account::Entity),
        schema.create_table_from_entity(better_auth_seaorm::store::entities::verification::Entity),
    ] {
        database
            .execute(&statement)
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
    }
    let events = Events::default();
    macro_rules! build {
        ($model:ident) => {{
            database
                .execute(&schema.create_table_from_entity(models::$model::Entity))
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
            let store =
                SeaOrmStore::<Schema<models::$model::Model>>::new(config.clone(), database.clone())
                    .with_hooks(vec![Arc::new(events.clone())]);
            finish(
                AuthBuilder::new(config).store(store),
                database,
                events,
                profile,
            )
            .await
        }};
    }
    match profile {
        "username-order-post" => build!(mapped),
        "username-no-display" => build!(no_display),
        _ => build!(ordinary),
    }
}

struct Fixture<S: AuthSchema> {
    auth: Arc<BetterAuth<S>>,
    database: DatabaseConnection,
    events: Events,
    mapped: bool,
    display: bool,
}
impl<S: AuthSchema> Clone for Fixture<S> {
    fn clone(&self) -> Self {
        Self {
            auth: self.auth.clone(),
            database: self.database.clone(),
            events: self.events.clone(),
            mapped: self.mapped,
            display: self.display,
        }
    }
}

async fn finish<S: AuthSchema>(
    builder: AuthBuilder<S>,
    database: DatabaseConnection,
    events: Events,
    profile: &str,
) -> AuthResult<Router> {
    let builder = if profile == "username-writes" {
        builder
            .plugin(
                EmailOtpPlugin::new().callbacks(
                    EmailOtpCallbacks::<S>::default()
                        .generate(|_, _, _| Ok(Some("123456".into())))
                        .send(|_, _| Box::pin(async { Ok(()) })),
                ),
            )
            .plugin(
                PhoneNumberPlugin::new()
                    .send_otp(|_, _| async { Ok(()) })
                    .verify_otp(|message, _| async move { Ok(message.code == "246810") })
                    .sign_up_on_verification(|phone| {
                        format!("{}@phone.example.com", phone.trim_start_matches('+'))
                    }),
            )
            .plugin(AdminPlugin::new())
    } else {
        builder
    };
    let auth = Arc::new(
        builder
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(UsernamePlugin::new(configure(profile, &events)))
            .plugin(EmailPasswordPlugin::new().password_hasher(Arc::new(FixtureHasher)))
            .plugin(SessionManagementPlugin::new())
            .plugin(UserManagementPlugin::new())
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
            .route("/__test/username", get(snapshot::<S>).post(control::<S>))
            .route("/__test/username/native", post(native::<S>))
            .with_state(Fixture {
                auth,
                database,
                events,
                mapped: profile == "username-order-post",
                display: profile != "username-no-display",
            }),
    ))
}

async fn state<S: AuthSchema>(fixture: &Fixture<S>) -> AuthResult<Value> {
    let table = if fixture.mapped {
        "username_users"
    } else {
        "users"
    };
    let username = if fixture.mapped {
        "login_name"
    } else {
        "username"
    };
    let display = if fixture.mapped {
        "display_label"
    } else {
        "display_username"
    };
    let suffix = if fixture.display {
        format!(", \"{display}\" AS displayUsername")
    } else {
        String::new()
    };
    let rows = fixture
        .database
        .query_all_raw(Statement::from_string(
            DbBackend::Sqlite,
            format!(
                "SELECT email, \"{username}\" AS username{suffix} FROM \"{table}\" ORDER BY rowid"
            ),
        ))
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    let mut raw = Vec::new();
    let mut users = Vec::new();
    for row in rows {
        let email: String = row
            .try_get("", "email")
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let username: Option<String> = row
            .try_get("", "username")
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let mut value = json!({"email":email,"username":username});
        if fixture.display {
            let display: Option<String> = row
                .try_get("", "displayUsername")
                .map_err(|error| AuthError::internal(error.to_string()))?;
            value["displayUsername"] = json!(display);
        }
        raw.push(value);
        let user = fixture
            .auth
            .store()
            .get_user_by_email(&email)
            .await?
            .unwrap();
        let view = fixture.auth.context().user_view(&user)?;
        let mut user = json!({"email":email,"username":view.username});
        if fixture.display {
            user["displayUsername"] = json!(view.display_username);
        }
        users.push(user);
    }
    let columns = fixture
        .database
        .query_all_raw(Statement::from_string(
            DbBackend::Sqlite,
            format!("PRAGMA table_info(\"{table}\")"),
        ))
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    let columns = columns
        .iter()
        .map(|row| row.try_get::<String>("", "name"))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| AuthError::internal(error.to_string()))?;
    let trace = fixture.events.0.lock().unwrap();
    Ok(
        json!({"calls":trace.calls,"events":trace.events,"schema":{"username":columns.iter().any(|name|name == username),"displayUsername":columns.iter().any(|name|name == display),"mapped":fixture.mapped},"users":users,"rows":raw}),
    )
}
async fn snapshot<S: AuthSchema>(State(fixture): State<Fixture<S>>) -> Json<Value> {
    Json(state(&fixture).await.unwrap())
}
async fn control<S: AuthSchema>(
    State(fixture): State<Fixture<S>>,
    Json(value): Json<Value>,
) -> Json<Value> {
    *fixture.events.0.lock().unwrap() = Trace {
        controls: value,
        ..Default::default()
    };
    Json(state(&fixture).await.unwrap())
}
async fn reset<S: AuthSchema>(State(fixture): State<Fixture<S>>) -> Json<Value> {
    for table in [
        "sessions",
        "accounts",
        if fixture.mapped {
            "username_users"
        } else {
            "users"
        },
    ] {
        fixture
            .database
            .execute_unprepared(&format!("DELETE FROM \"{table}\""))
            .await
            .unwrap();
    }
    *fixture.events.0.lock().unwrap() = Trace::default();
    Json(json!({"success":true}))
}
async fn invoke<S: AuthSchema>(
    fixture: &Fixture<S>,
    headers: HeaderMap,
    input: Value,
) -> AuthResult<Value> {
    let data = input["data"].as_object().unwrap().clone();
    let fields: Map<String, Value> = data
        .iter()
        .filter(|(key, _)| ["username", "displayUsername", "id"].contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    match input["operation"].as_str().unwrap() {
        "admin-create" => {
            let body: CreateAdminUser = serde_json::from_value(input["data"].clone())?;
            Ok(serde_json::to_value(
                AdminApi::from_context(fixture.auth.context())?
                    .create_user(&body, None)
                    .await?,
            )?)
        }
        "create" => {
            let mut user = CreateUser::new().with_email(data["email"].as_str().unwrap());
            user.name = data.get("name").and_then(Value::as_str).map(str::to_owned);
            user.additional_fields = fields;
            let user = fixture.auth.store().create_user(user).await?;
            Ok(serde_json::to_value(
                fixture.auth.context().user_view(&user)?,
            )?)
        }
        "update" => {
            let user = fixture
                .auth
                .store()
                .get_user_by_email(input["email"].as_str().unwrap())
                .await?
                .unwrap();
            let user = fixture
                .auth
                .store()
                .update_user(
                    user.id().typed().unwrap(),
                    UpdateUser {
                        additional_fields: fields,
                        ..Default::default()
                    },
                )
                .await?;
            Ok(serde_json::to_value(
                fixture.auth.context().user_view(&user)?,
            )?)
        }
        operation => {
            let path = if operation == "endpoint-update" {
                "/update-user"
            } else {
                "/sign-up/email"
            };
            let response = fixture
                .auth
                .call_endpoint(
                    HttpMethod::Post,
                    path,
                    better_auth::server_api::EndpointInput {
                        headers: Some(
                            headers
                                .iter()
                                .map(|(name, value)| {
                                    (name.to_string(), value.to_str().unwrap().to_owned())
                                })
                                .collect(),
                        ),
                        body: Some(Value::Object(data)),
                        ..Default::default()
                    },
                )
                .await?;
            if response.status != 200 {
                return Err(AuthError::from(response));
            }
            Ok(serde_json::from_slice(&response.body)?)
        }
    }
}
async fn native<S: AuthSchema>(
    State(fixture): State<Fixture<S>>,
    headers: HeaderMap,
    Json(input): Json<Value>,
) -> Json<Value> {
    match invoke(&fixture, headers, input).await {
        Ok(body) => Json(json!({"status":200,"body":body})),
        Err(error) => {
            let response = error.to_auth_response();
            let body: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
            Json(json!({"status":response.status,"body":body}))
        }
    }
}
