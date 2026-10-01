use better_auth::config::UserFieldTransform;
mod account;
mod verification;

use async_trait::async_trait;
use axum::{Json, Router, routing::post};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult, AuthSchema, BetterAuth};
use better_auth_core::{
    AuthRequest, CreateAccount, CreateUser, CreateVerification, HttpMethod, UpdateAccount,
    store::database_hooks::VerificationUpdate,
    store::{AuthTransaction, SecondaryStorage, transaction},
    user_fields::UserFieldConfig,
    wire::{AccountView, VerificationView},
};
use better_auth_seaorm::{
    HookControl, SeaOrmHookContext, SeaOrmHooks, SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, EntityTrait, QueryOrder},
    store::{__private_test_support::migrator, entities},
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::sync::{Arc, Mutex};

struct Schema;
impl AuthSchema for Schema {
    type User = entities::user::Model;
    type Session = entities::session::Model;
    type Account = account::Model;
    type Verification = verification::Model;
}

#[derive(Clone, Deserialize)]
struct Input {
    mode: String,
    model: String,
    scenario: String,
    fault: Option<String>,
    transaction: Option<String>,
}

#[derive(Default)]
struct State {
    events: Vec<Value>,
    entries: Map<String, Value>,
    fail: Option<String>,
    patch: Map<String, Value>,
}
type Shared = Arc<Mutex<State>>;

fn event(state: &Shared, kind: impl Into<String>, value: Value) -> AuthResult<()> {
    let kind = kind.into();
    let mut state = state.lock().unwrap();
    state.events.push(json!({"kind": kind, "value": value}));
    if state.fail.as_deref() == Some(&kind) {
        return Err(AuthError::internal(format!("fixture {kind} rejected")));
    }
    Ok(())
}

fn fields(value: &Value) -> Value {
    if value.is_null() {
        return Value::Null;
    }
    Value::Object(
        ["label", "hidden", "protected", "value"]
            .into_iter()
            .filter_map(|key| value.get(key).map(|value| (key.into(), value.clone())))
            .collect(),
    )
}

fn hook_fields(value: &Value) -> Value {
    ["label", "hidden", "protected"]
        .into_iter()
        .map(|key| {
            (
                key.into(),
                value.get(key).cloned().unwrap_or(json!("<undefined>")),
            )
        })
        .collect::<Map<_, _>>()
        .into()
}

struct Cache(Shared);
#[async_trait]
impl SecondaryStorage for Cache {
    async fn get(&self, key: &str) -> AuthResult<Option<Value>> {
        event(&self.0, "cache.get", json!(key))?;
        Ok(self.0.lock().unwrap().entries.get(key).cloned())
    }
    async fn set(&self, key: &str, value: &str, _: Option<u64>) -> AuthResult<()> {
        event(&self.0, "cache.set", json!(key))?;
        self.0
            .lock()
            .unwrap()
            .entries
            .insert(key.into(), json!(value));
        Ok(())
    }
    async fn delete(&self, key: &str) -> AuthResult<()> {
        event(&self.0, "cache.delete", json!(key))?;
        self.0.lock().unwrap().entries.remove(key);
        Ok(())
    }
    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<Value>> {
        event(&self.0, "cache.getAndDelete", json!(key))?;
        Ok(self.0.lock().unwrap().entries.remove(key))
    }
}

fn db_error(error: better_auth_seaorm::sea_orm::DbErr) -> AuthError {
    AuthError::internal(format!("Field fixture database: {error}"))
}

fn cached(state: &Shared) -> AuthResult<Value> {
    state
        .lock()
        .unwrap()
        .entries
        .get("verification:code")
        .map(|value| serde_json::from_str(value.as_str().unwrap()).map_err(Into::into))
        .unwrap_or(Ok(Value::Null))
}

struct Hooks(Shared);
impl Hooks {
    fn before(&self, model: &str, operation: &str, value: Value) -> AuthResult<()> {
        event(
            &self.0,
            format!("{model}.{operation}.before"),
            hook_fields(&value),
        )
    }
    async fn after(
        &self,
        model: &str,
        operation: &str,
        value: Value,
        ctx: &SeaOrmHookContext<'_, Schema>,
    ) -> AuthResult<()> {
        let mut result = hook_fields(&value);
        let rows = if model == "account" {
            account::Entity::find()
                .all(ctx.db)
                .await
                .map_err(db_error)?
                .len()
        } else {
            verification::Entity::find()
                .all(ctx.db)
                .await
                .map_err(db_error)?
                .len()
        };
        if let Some(result) = result.as_object_mut() {
            result.insert("rows".into(), json!(rows));
            result.insert(
                "cacheLabel".into(),
                cached(&self.0)?
                    .get("label")
                    .cloned()
                    .unwrap_or(json!("<undefined>")),
            );
        }
        event(
            &self.0,
            format!("{model}.{operation}.after"),
            if value.is_null() { Value::Null } else { result },
        )
    }
}

#[better_auth::database_hooks()]
impl SeaOrmHooks<Schema> for Hooks {
    async fn before_create_account(
        &self,
        data: &mut CreateAccount,
        _: &SeaOrmHookContext<'_, Schema>,
    ) -> AuthResult<HookControl> {
        self.before("account", "create", Value::Object(data.fields()?))?;
        data.additional_fields
            .extend(self.0.lock().unwrap().patch.clone());
        Ok(HookControl::Continue)
    }
    async fn after_create_account(
        &self,
        data: &AccountView,
        ctx: &SeaOrmHookContext<'_, Schema>,
    ) -> AuthResult<()> {
        self.after("account", "create", serde_json::to_value(data)?, ctx)
            .await
    }
    async fn before_update_account(
        &self,
        _: &str,
        data: &UpdateAccount,
        _: &SeaOrmHookContext<'_, Schema>,
    ) -> AuthResult<better_auth_seaorm::DatabaseHookUpdate<UpdateAccount>> {
        self.before("account", "update", Value::Object(data.fields()?))?;
        Ok(better_auth_seaorm::DatabaseHookUpdate::Continue)
    }
    async fn after_update_account(
        &self,
        data: Option<&AccountView>,
        ctx: &SeaOrmHookContext<'_, Schema>,
    ) -> AuthResult<()> {
        self.after("account", "update", serde_json::to_value(data)?, ctx)
            .await
    }
    async fn before_create_verification(
        &self,
        data: &mut CreateVerification,
        _: &SeaOrmHookContext<'_, Schema>,
    ) -> AuthResult<HookControl> {
        self.before("verification", "create", Value::Object(data.fields()?))?;
        data.additional_fields
            .extend(self.0.lock().unwrap().patch.clone());
        Ok(HookControl::Continue)
    }
    async fn after_create_verification(
        &self,
        data: &VerificationView,
        ctx: &SeaOrmHookContext<'_, Schema>,
    ) -> AuthResult<()> {
        self.after("verification", "create", serde_json::to_value(data)?, ctx)
            .await
    }
    async fn before_update_verification(
        &self,
        _: &str,
        data: &VerificationUpdate,
        _: &SeaOrmHookContext<'_, Schema>,
    ) -> AuthResult<better_auth_seaorm::DatabaseHookUpdate<VerificationUpdate>> {
        self.before("verification", "update", Value::Object(data.fields()?))?;
        Ok(better_auth_seaorm::DatabaseHookUpdate::Continue)
    }
    async fn after_update_verification(
        &self,
        data: Option<&VerificationView>,
        ctx: &SeaOrmHookContext<'_, Schema>,
    ) -> AuthResult<()> {
        self.after("verification", "update", serde_json::to_value(data)?, ctx)
            .await
    }
    async fn before_delete_verification(
        &self,
        data: &VerificationView,
        _: &SeaOrmHookContext<'_, Schema>,
    ) -> AuthResult<HookControl> {
        self.before("verification", "delete", serde_json::to_value(data)?)?;
        Ok(HookControl::Continue)
    }
    async fn after_delete_verification(
        &self,
        data: &VerificationView,
        ctx: &SeaOrmHookContext<'_, Schema>,
    ) -> AuthResult<()> {
        self.after("verification", "delete", serde_json::to_value(data)?, ctx)
            .await
    }
}

fn policy(model: &'static str, state: &Shared) -> [(String, UserFieldConfig); 3] {
    let defaults = state.clone();
    let updates = state.clone();
    let input = state.clone();
    let output = state.clone();
    [
        (
            "label".into(),
            UserFieldConfig {
                required: Some(false),
                field_name: Some("stored_label".into()),
                default_value_fn: Some(Arc::new(move || {
                    event(&defaults, format!("{model}.default"), json!("<undefined>")).unwrap();
                    json!("default")
                })),
                on_update: Some(Arc::new(move || {
                    event(&updates, format!("{model}.onUpdate"), json!("<undefined>")).unwrap();
                    json!("updated")
                })),
                input_transform: Some(UserFieldTransform::new(move |value| {
                    event(
                        &input,
                        format!("{model}.input"),
                        value.clone().unwrap_or(json!("<undefined>")),
                    )?;
                    let value = value.unwrap_or(json!("undefined"));
                    Ok(Some(json!(format!(
                        "{}:in",
                        value
                            .as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| value.to_string())
                    ))))
                })),
                output_transform: Some(UserFieldTransform::new(move |value| {
                    event(
                        &output,
                        format!("{model}.output"),
                        value.clone().unwrap_or(json!("<undefined>")),
                    )?;
                    let value = value.unwrap_or(json!("undefined"));
                    Ok(Some(json!(format!(
                        "{}:out",
                        value
                            .as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| value.to_string())
                    ))))
                })),
                ..Default::default()
            },
        ),
        (
            "hidden".into(),
            UserFieldConfig {
                required: Some(false),
                returned: false,
                default_value: Some(json!("secret")),
                ..Default::default()
            },
        ),
        (
            "protected".into(),
            UserFieldConfig {
                required: Some(false),
                input: false,
                default_value: Some(json!("server")),
                ..Default::default()
            },
        ),
    ]
}

struct Fixture {
    auth: Arc<BetterAuth<Schema>>,
    db: DatabaseConnection,
    state: Shared,
    user_id: String,
}

impl Fixture {
    async fn new(mode: &str) -> AuthResult<Self> {
        let db = Database::connect("sqlite::memory:")
            .await
            .map_err(db_error)?;
        migrator::run_migrations(&db).await.map_err(db_error)?;
        for table in ["accounts", "verifications"] {
            for field in ["stored_label", "hidden", "protected"] {
                db.execute_unprepared(&format!("ALTER TABLE {table} ADD COLUMN {field} TEXT"))
                    .await
                    .map_err(db_error)?;
            }
        }
        let state = Arc::new(Mutex::new(State::default()));
        let mut config =
            AuthConfig::new("account-verification-field-fixture-secret-thirty-two-characters");
        config.base_url = "http://localhost:3000".into();
        config.account.additional_fields = policy("account", &state).into_iter().collect();
        config.verification.additional_fields =
            policy("verification", &state).into_iter().collect();
        config.verification.store_in_database = mode != "cache";
        config.verification.disable_cleanup = Some(true);
        config.session.store_session_in_database = Some(true);
        let store =
            SeaOrmStore::<Schema>::new(config.clone(), db.clone()).hook(Hooks(state.clone()));
        let mut builder = AuthBuilder::<Schema>::new(config)
            .store(store)
            .plugin(better_auth::plugins::account_management::AccountManagementPlugin::new());
        if mode != "database" {
            builder = builder.secondary_storage(Arc::new(Cache(state.clone())));
        }
        let auth = Arc::new(builder.build().await?);
        let user = auth
            .store()
            .create_user(
                CreateUser::new()
                    .with_email("fields@example.com")
                    .with_name("Fields")
                    .with_email_verified(true),
            )
            .await?;
        Ok(Self {
            user_id: user.id.typed().unwrap().clone(),
            auth,
            db,
            state,
        })
    }
    fn clear(&self) {
        self.state.lock().unwrap().events.clear();
    }
    fn fail(&self, fail: String) {
        self.state.lock().unwrap().fail = Some(fail);
    }
    fn has_after(&self, name: &str) -> bool {
        self.state
            .lock()
            .unwrap()
            .events
            .iter()
            .any(|value| value["kind"] == name)
    }
    async fn snapshot(&self) -> AuthResult<Value> {
        let accounts = account::Entity::find()
            .order_by_asc(account::Column::Id)
            .all(&self.db)
            .await
            .map_err(db_error)?;
        let verifications = verification::Entity::find()
            .order_by_asc(verification::Column::Id)
            .all(&self.db)
            .await
            .map_err(db_error)?;
        Ok(json!({
            "accounts": accounts.into_iter().map(|row| json!({"label": row.stored_label, "hidden": row.hidden, "protected": row.protected})).collect::<Vec<_>>(),
            "verifications": verifications.into_iter().map(|row| json!({"label": row.stored_label, "hidden": row.hidden, "protected": row.protected, "value": row.value})).collect::<Vec<_>>(),
            "cached": fields(&cached(&self.state)?), "events": self.state.lock().unwrap().events,
        }))
    }
    async fn checkpoint(
        &self,
        output: &mut Map<String, Value>,
        name: &str,
        value: &Value,
    ) -> AuthResult<()> {
        output.insert(
            name.into(),
            json!({"value": fields(value), "state": self.snapshot().await?}),
        );
        Ok(())
    }
    async fn create(
        &self,
        model: &str,
        input: Value,
        tx: Option<&dyn AuthTransaction<Schema>>,
    ) -> AuthResult<Value> {
        let extras = input.as_object().unwrap().clone();
        if model == "account" {
            let data = CreateAccount {
                user_id: self.user_id.clone().into(),
                provider_id: "mock".into(),
                account_id: "provider-account".into(),
                access_token: Some("private-token".into()).into(),
                password: Some("private-password".into()).into(),
                scope: Some("read, write".into()).into(),
                additional_fields: extras,
                ..Default::default()
            };
            Ok(serde_json::to_value(match tx {
                Some(tx) => tx.create_account(data).await?,
                None => self.auth.store().create_account(data).await?,
            })?)
        } else {
            let data = CreateVerification {
                identifier: "code".into(),
                value: "123456".into(),
                expires_at: "2100-01-02T03:04:05Z"
                    .parse::<chrono::DateTime<chrono::Utc>>()
                    .unwrap()
                    .into(),
                additional_fields: extras,
                ..Default::default()
            };
            Ok(serde_json::to_value(match tx {
                Some(tx) => tx.create_verification(data).await?,
                None => self.auth.store().create_verification(data).await?,
            })?)
        }
    }
    async fn update(
        &self,
        model: &str,
        id: &str,
        input: Value,
        tx: Option<&dyn AuthTransaction<Schema>>,
    ) -> AuthResult<Value> {
        let extras = input.as_object().unwrap().clone();
        if model == "account" {
            let data = UpdateAccount {
                access_token: Some("refreshed-token".into()).into(),
                additional_fields: extras,
                ..Default::default()
            };
            assert!(
                tx.is_none(),
                "The account update scenario runs outside a transaction"
            );
            Ok(serde_json::to_value(
                self.auth.store().update_account(id, data).await?,
            )?)
        } else {
            let data = VerificationUpdate {
                value: "654321".into(),
                additional_fields: extras,
                ..Default::default()
            };
            Ok(serde_json::to_value(match tx {
                Some(tx) => tx.update_verification("code", data).await?,
                None => self.auth.store().update_verification("code", data).await?,
            })?)
        }
    }
    async fn read(&self, model: &str) -> AuthResult<Value> {
        if model == "account" {
            Ok(serde_json::to_value(
                self.auth
                    .store()
                    .get_user_accounts(&self.user_id)
                    .await?
                    .first(),
            )?)
        } else {
            Ok(serde_json::to_value(
                self.auth
                    .store()
                    .get_verification_including_expired("code")
                    .await?,
            )?)
        }
    }
    async fn listed(&self) -> AuthResult<Value> {
        let session = self
            .auth
            .store()
            .create_session(better_auth_core::CreateSession {
                additional_fields: Default::default(),
                user_id: self.user_id.clone().into(),
                expires_at: chrono::Utc::now() + chrono::Duration::days(1),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await?;
        let cookie = better_auth_core::utils::cookie_utils::sign_cookie_value(
            &session.token,
            "account-verification-field-fixture-secret-thirty-two-characters",
        );
        let mut request = AuthRequest::new(HttpMethod::Get, "/list-accounts");
        request.headers.insert(
            "cookie".into(),
            format!("better-auth.session_token={cookie}"),
        );
        let response = self.auth.handle_request(request).await?;
        let body: Vec<Value> = serde_json::from_slice(&response.body)?;
        let body = body
            .into_iter()
            .map(|value| {
                let mut projected = fields(&value).as_object().unwrap().clone();
                projected.insert("scopes".into(), value["scopes"].clone());
                projected.insert(
                    "privateKeys".into(),
                    json!(
                        [
                            "password",
                            "accessToken",
                            "refreshToken",
                            "idToken",
                            "accessTokenExpiresAt",
                            "refreshTokenExpiresAt",
                            "scope"
                        ]
                        .into_iter()
                        .filter(|key| value.get(key).is_some())
                        .collect::<Vec<_>>()
                    ),
                );
                Value::Object(projected)
            })
            .collect::<Vec<_>>();
        Ok(json!({"status": response.status, "body": body}))
    }
}

fn captured(result: AuthResult<Value>) -> Value {
    match result {
        Ok(value) => json!({"error": null, "value": fields(&value)}),
        Err(AuthError::Internal(message)) => json!({"error": message, "value": null}),
        Err(error) => json!({"error": error.to_string(), "value": null}),
    }
}

async fn run(input: Input) -> AuthResult<Value> {
    let f = Arc::new(Fixture::new(&input.mode).await?);
    let mut out = Map::new();
    match input.scenario.as_str() {
        "lifecycle" => {
            let created = f.create(&input.model, json!({}), None).await?;
            f.checkpoint(&mut out, "created", &created).await?;
            f.clear();
            f.checkpoint(&mut out, "read", &f.read(&input.model).await?)
                .await?;
            f.clear();
            let id = created["id"].as_str().unwrap_or("");
            f.checkpoint(
                &mut out,
                "updated",
                &f.update(&input.model, id, json!({}), None).await?,
            )
            .await?;
            f.clear();
            f.checkpoint(
                &mut out,
                "explicit",
                &f.update(&input.model, id, json!({"label":"explicit"}), None)
                    .await?,
            )
            .await?;
            f.checkpoint(&mut out, "readExplicit", &f.read(&input.model).await?)
                .await?;
            if input.model == "account" {
                out.insert("listed".into(), f.listed().await?);
            }
        }
        "explicit-null" | "hook-fields" => {
            let data = if input.scenario == "explicit-null" {
                json!({"label": null, "protected":"native", "hidden":"native-secret"})
            } else {
                f.state.lock().unwrap().patch =
                    json!({"label":"hook", "hidden":"hook-secret", "protected":"hook-protected"})
                        .as_object()
                        .unwrap()
                        .clone();
                json!({"label":"request"})
            };
            f.checkpoint(
                &mut out,
                "created",
                &f.create(&input.model, data, None).await?,
            )
            .await?;
        }
        "create-error" | "after-error" | "create-rollback" | "create-cache-error" => {
            if input.scenario == "create-error" {
                f.fail(format!(
                    "{}.{}",
                    input.model,
                    input.fault.as_deref().unwrap()
                ));
            }
            if input.scenario == "after-error" {
                f.fail(format!("{}.create.after", input.model));
            }
            if input.scenario == "create-cache-error" {
                f.fail("cache.set".into());
            }
            let inside = Arc::new(Mutex::new(Map::new()));
            let result = if input.transaction.as_deref() == Some("outside") {
                f.create(&input.model, json!({"label":"value"}), None).await
            } else {
                let work = f.clone();
                let input = input.clone();
                let inside = inside.clone();
                transaction(f.auth.store().as_ref(), move |tx| {
                    Box::pin(async move {
                        let data = if input.scenario == "create-rollback" {
                            json!({"label":"value","hidden":"hidden-value"})
                        } else {
                            json!({"label":"value"})
                        };
                        let result = work.create(&input.model, data, Some(tx)).await;
                        if input.transaction.as_deref() == Some("caught") {
                            inside
                                .lock()
                                .unwrap()
                                .insert("caught".into(), captured(result));
                            return Ok(Value::Null);
                        }
                        let created = result?;
                        if input.scenario == "create-rollback" {
                            inside
                                .lock()
                                .unwrap()
                                .insert("inside".into(), fields(&created));
                        }
                        if matches!(input.scenario.as_str(), "after-error" | "create-rollback") {
                            inside.lock().unwrap().insert(
                                "insideAfter".into(),
                                json!(work.has_after(&format!("{}.create.after", input.model))),
                            );
                        }
                        if input.scenario == "create-rollback" {
                            return Err(AuthError::internal("rollback requested"));
                        }
                        Ok(created)
                    })
                })
                .await
            };
            out.extend(inside.lock().unwrap().clone());
            out.insert("result".into(), captured(result));
            f.checkpoint(&mut out, "final", &Value::Null).await?;
        }
        "update-error" | "update-rollback" | "update-cache-error" => {
            let initial = f
                .create("verification", json!({"label":"initial"}), None)
                .await?;
            f.clear();
            let id = initial["id"].as_str().unwrap_or("").to_owned();
            let result = if input.scenario == "update-rollback" {
                let inside = Arc::new(Mutex::new(Map::new()));
                let work = f.clone();
                let output = inside.clone();
                let result = transaction(f.auth.store().as_ref(), move |tx| {
                    Box::pin(async move {
                        let updated = work
                            .update(
                                "verification",
                                &id,
                                json!({"label":"replacement"}),
                                Some(tx),
                            )
                            .await?;
                        output
                            .lock()
                            .unwrap()
                            .insert("inside".into(), fields(&updated));
                        output.lock().unwrap().insert(
                            "insideAfter".into(),
                            json!(work.has_after("verification.update.after")),
                        );
                        Err::<Value, _>(AuthError::internal("rollback requested"))
                    })
                })
                .await;
                out.extend(inside.lock().unwrap().clone());
                result
            } else {
                f.fail(if input.scenario == "update-cache-error" {
                    "cache.set".into()
                } else {
                    format!("verification.{}", input.fault.as_deref().unwrap())
                });
                f.update("verification", &id, json!({"label":"replacement"}), None)
                    .await
            };
            out.insert("result".into(), captured(result));
            f.checkpoint(&mut out, "final", &Value::Null).await?;
        }
        "consume" => {
            f.create(
                "verification",
                json!({"label":"value","hidden":"consume-secret"}),
                None,
            )
            .await?;
            f.clear();
            let consumed = serde_json::to_value(
                f.auth
                    .store()
                    .consume_verification_by_identifier("code")
                    .await?,
            )?;
            f.checkpoint(&mut out, "consumed", &consumed).await?;
            let again = serde_json::to_value(
                f.auth
                    .store()
                    .consume_verification_by_identifier("code")
                    .await?,
            )?;
            f.checkpoint(&mut out, "again", &again).await?;
        }
        _ => return Err(AuthError::internal("Unknown field fixture scenario")),
    }
    Ok(Value::Object(out))
}

pub fn router() -> Router {
    Router::new().route(
        "/__test/account-verification-fields",
        post(|Json(input): Json<Input>| async move { run(input).await.map(Json) }),
    )
}
