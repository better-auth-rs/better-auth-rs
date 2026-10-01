use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_core::{
    AuthSchema, CreateAccount, CreateSession, CreateUser,
    store::{
        SecondaryStorage,
        database_hooks::{DatabaseHookUpdate, SessionUpdate},
    },
};
use better_auth_seaorm::{
    HookControl, SeaOrmHookContext, SeaOrmHooks, SeaOrmStore,
    schema::{SeaOrmAccountModel, SeaOrmSessionModel, SeaOrmUserModel},
    sea_orm::{
        self, ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait,
        QueryFilter, QueryOrder, Set,
    },
    store::entities::{account, user},
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};

type Schema = crate::user_fields::Schema;
type Session = <Schema as AuthSchema>::Session;
type SessionEntity = <Session as SeaOrmSessionModel>::Entity;
const CREATED_AT: &str = "2020-01-02T03:04:05.000Z";
const UPDATED_AT: &str = "2021-02-03T04:05:06.000Z";
const EXPIRES_AT: &str = "2100-01-02T03:04:05.000Z";

fn date(value: &str) -> DateTime<Utc> {
    value.parse().unwrap()
}
fn database_error(error: sea_orm::DbErr) -> AuthError {
    AuthError::internal(format!("Lifecycle fixture database: {error}"))
}
fn rejected() -> AuthError {
    AuthError::internal("Fixture lifecycle rejected")
}
fn stored_session_view(session: &Session) -> Value {
    json!({"id":session.id,"token":session.token,"userId":session.user_id,
        "label":session.device_label,
        "createdAt":session.created_at.to_rfc3339_opts(SecondsFormat::Millis,true),
        "updatedAt":session.updated_at.to_rfc3339_opts(SecondsFormat::Millis,true),
        "expiresAt":session.expires_at.to_rfc3339_opts(SecondsFormat::Millis,true)})
}

fn session_view(session: &better_auth_core::SessionView) -> Value {
    json!({"id":session.id,"token":session.token,"userId":session.user_id,
        "label":session.additional_fields.get("label"),
        "createdAt":session.created_at.to_rfc3339_opts(SecondsFormat::Millis,true),
        "updatedAt":session.updated_at.to_rfc3339_opts(SecondsFormat::Millis,true),
        "expiresAt":session.expires_at.to_rfc3339_opts(SecondsFormat::Millis,true)})
}

#[derive(Default)]
struct Trace {
    options: Value,
    events: Vec<Value>,
    cache: BTreeMap<String, String>,
    held_delete: Option<(Arc<tokio::sync::Semaphore>, Arc<tokio::sync::Semaphore>)>,
}
#[derive(Clone)]
struct Events {
    database: DatabaseConnection,
    trace: Arc<Mutex<Trace>>,
    stores_sessions: bool,
}
impl Events {
    async fn sessions(&self) -> AuthResult<Vec<Value>> {
        if !self.stores_sessions {
            return Ok(Vec::new());
        }
        Ok(SessionEntity::find()
            .order_by_asc(Session::id_column())
            .all(&self.database)
            .await
            .map_err(database_error)?
            .iter()
            .map(stored_session_view)
            .collect())
    }
    async fn record(&self, kind: &str, data: Value) -> AuthResult<()> {
        let sessions = self
            .sessions()
            .await?
            .into_iter()
            .map(|row| json!({"id":row["id"],"label":row["label"]}))
            .collect::<Vec<_>>();
        self.trace
            .lock()
            .unwrap()
            .events
            .push(json!({"kind":kind,"data":data,"databaseSessions":sessions}));
        Ok(())
    }
    fn options(&self) -> Value {
        self.trace.lock().unwrap().options.clone()
    }
    async fn before_delete(&self, model: &str, id: &str) -> AuthResult<HookControl> {
        let kind = format!("{model}.delete.before");
        self.record(&kind, json!({"id":id})).await?;
        let options = self.options();
        if options["fail"] == format!("{kind}:{id}") {
            return Err(rejected());
        }
        Ok(if options["cancel"] == format!("{model}:{id}") {
            HookControl::Cancel
        } else {
            HookControl::Continue
        })
    }
    async fn after_delete(&self, model: &str, id: &str) -> AuthResult<()> {
        let kind = format!("{model}.delete.after");
        self.record(&kind, json!({"id":id})).await?;
        if self.options()["fail"] == format!("{kind}:{id}") {
            return Err(rejected());
        }
        Ok(())
    }
    async fn snapshot(&self) -> AuthResult<Value> {
        let users = user::Entity::find()
            .order_by_asc(user::Column::Id)
            .all(&self.database)
            .await
            .map_err(database_error)?
            .into_iter()
            .map(|row| row.id)
            .collect::<Vec<_>>();
        let accounts = account::Entity::find()
            .order_by_asc(account::Column::Id)
            .all(&self.database)
            .await
            .map_err(database_error)?
            .into_iter()
            .map(|row| row.id)
            .collect::<Vec<_>>();
        let sessions = self.sessions().await?;
        let trace = self.trace.lock().unwrap();
        let mut cache = Vec::new();
        let mut references = Vec::new();
        for (key, value) in &trace.cache {
            // Keep malformed entries visible in the snapshot without repairing the cache.
            let value: Value = serde_json::from_str(value).unwrap_or(Value::Null);
            if key.starts_with("active-sessions-") {
                let mut tokens = value
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|row| row["token"].clone())
                    .collect::<Vec<_>>();
                tokens.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
                references.push(json!({"key":key,"tokens":tokens}));
            } else {
                let row = &value["session"];
                if row.is_null() {
                    cache.push(json!({"key":key,"session":null}));
                    continue;
                }
                cache.push(json!({"key":key,"session":{
                    "id":row["id"],"token":row["token"],"userId":row["userId"],"label":row["label"],
                    "createdAt":date(row["createdAt"].as_str().unwrap()).to_rfc3339_opts(SecondsFormat::Millis,true),
                    "updatedAt":date(row["updatedAt"].as_str().unwrap()).to_rfc3339_opts(SecondsFormat::Millis,true),
                    "expiresAt":date(row["expiresAt"].as_str().unwrap()).to_rfc3339_opts(SecondsFormat::Millis,true)}}));
            }
        }
        Ok(
            json!({"users":users,"accounts":accounts,"sessions":sessions,"cache":cache,"references":references,"events":trace.events}),
        )
    }
}

#[async_trait]
impl SecondaryStorage for Events {
    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<Value>> {
        self.record("cache.getAndDelete", json!({"key":key}))
            .await?;
        if self.options()["cacheFailure"] == "delete" || self.options()["failDeleteKey"] == key {
            return Err(rejected());
        }
        Ok(self
            .trace
            .lock()
            .unwrap()
            .cache
            .remove(key)
            .map(Value::String))
    }
    async fn get(&self, key: &str) -> AuthResult<Option<Value>> {
        self.record("cache.get", json!({"key":key})).await?;
        if self.options()["cacheFailure"] == "get" {
            return Err(rejected());
        }
        Ok(self
            .trace
            .lock()
            .unwrap()
            .cache
            .get(key)
            .cloned()
            .map(Value::String))
    }
    async fn set(&self, key: &str, value: &str, _: Option<u64>) -> AuthResult<()> {
        self.record("cache.set", json!({"key":key})).await?;
        if self.options()["cacheFailure"] == "set" {
            return Err(rejected());
        }
        let _ = self
            .trace
            .lock()
            .unwrap()
            .cache
            .insert(key.into(), value.into());
        Ok(())
    }
    async fn delete(&self, key: &str) -> AuthResult<()> {
        self.record("cache.delete", json!({"key":key})).await?;
        let held = {
            let trace = self.trace.lock().unwrap();
            (trace.options["holdDeleteKey"] == key).then(|| trace.held_delete.clone().unwrap())
        };
        if let Some((released, _)) = &held {
            released.acquire().await.unwrap().forget();
        }
        if self.options()["cacheFailure"] == "delete" || self.options()["failDeleteKey"] == key {
            return Err(rejected());
        }
        let _ = self.trace.lock().unwrap().cache.remove(key);
        if let Some((_, completed)) = held {
            completed.add_permits(1);
        }
        Ok(())
    }
}

#[better_auth::database_hooks()]
impl SeaOrmHooks<Schema> for Events {
    async fn before_delete_user(
        &self,
        row: &better_auth_core::wire::UserView,
        _: &SeaOrmHookContext<'_, Schema>,
    ) -> AuthResult<HookControl> {
        self.before_delete("user", row.id.typed().unwrap()).await
    }
    async fn after_delete_user(
        &self,
        row: &better_auth_core::wire::UserView,
        _: &SeaOrmHookContext<'_, Schema>,
    ) -> AuthResult<()> {
        self.after_delete("user", row.id.typed().unwrap()).await
    }
    async fn before_delete_account(
        &self,
        row: &better_auth_core::wire::AccountView,
        _: &SeaOrmHookContext<'_, Schema>,
    ) -> AuthResult<HookControl> {
        self.before_delete("account", row.id.typed()?).await
    }
    async fn after_delete_account(
        &self,
        row: &better_auth_core::wire::AccountView,
        _: &SeaOrmHookContext<'_, Schema>,
    ) -> AuthResult<()> {
        self.after_delete("account", row.id.typed()?).await
    }
    async fn before_delete_session(
        &self,
        row: &better_auth_core::wire::SessionView,
        _: &SeaOrmHookContext<'_, Schema>,
    ) -> AuthResult<HookControl> {
        self.before_delete("session", row.id.typed().unwrap()).await
    }
    async fn after_delete_session(
        &self,
        row: &better_auth_core::wire::SessionView,
        _: &SeaOrmHookContext<'_, Schema>,
    ) -> AuthResult<()> {
        self.after_delete("session", row.id.typed().unwrap()).await
    }
    async fn before_update_session(
        &self,
        _: &str,
        patch: &SessionUpdate,
        _: &SeaOrmHookContext<'_, Schema>,
    ) -> AuthResult<DatabaseHookUpdate<SessionUpdate>> {
        self.record(
            "session.update.before",
            Value::Object(patch.clone().into_public_fields()?),
        )
        .await?;
        let options = self.options();
        if options["fail"] == "session.update.before" {
            return Err(rejected());
        }
        if options["cancel"] == "session.update" {
            return Ok(DatabaseHookUpdate::Cancel);
        }
        let Some(patch) = options.get("patch") else {
            return Ok(DatabaseHookUpdate::Continue);
        };
        let mut fields = patch.as_object().unwrap().clone();
        let mut update = SessionUpdate::default();
        if let Some(value) = fields.remove("token") {
            update.token = Some(value.as_str().unwrap().into());
        }
        if let Some(value) = fields.remove("createdAt") {
            update.created_at = Some(date(value.as_str().unwrap()));
        }
        if let Some(value) = fields.remove("updatedAt") {
            update.updated_at = Some(date(value.as_str().unwrap()));
        }
        update.additional_fields = fields;
        Ok(DatabaseHookUpdate::Patch(update))
    }
    async fn after_update_session(
        &self,
        row: Option<&better_auth_core::wire::SessionView>,
        _: &SeaOrmHookContext<'_, Schema>,
    ) -> AuthResult<()> {
        self.record(
            "session.update.after",
            row.map(session_view).unwrap_or(Value::Null),
        )
        .await?;
        if self.options()["fail"] == "session.update.after" {
            return Err(rejected());
        }
        Ok(())
    }
}

#[derive(Clone)]
struct Fixture {
    auth: Arc<BetterAuth<Schema>>,
    events: Events,
    secondary: bool,
    preserve: bool,
}

pub async fn router(profile: &str, base_url: &str) -> AuthResult<Router> {
    let database = sea_orm::Database::connect("sqlite::memory:")
        .await
        .map_err(database_error)?;
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .map_err(database_error)?;
    crate::user_fields::add_columns(&database)
        .await
        .map_err(database_error)?;
    let secondary = profile != "database-lifecycle";
    let stores_sessions = profile != "database-lifecycle-cache";
    let preserve = profile == "database-lifecycle-preserved";
    let mut config =
        AuthConfig::new("database-lifecycle-fixture-secret-at-least-thirty-two-characters")
            .base_url(base_url);
    config.session.store_session_in_database = Some(stores_sessions);
    config.session.preserve_session_in_database = Some(preserve);
    let _ = config.session.additional_fields.insert(
        "label".into(),
        better_auth::config::UserFieldConfig {
            required: Some(false),
            field_name: Some("deviceLabel".into()),
            ..Default::default()
        },
    );
    let events = Events {
        database: database.clone(),
        trace: Default::default(),
        stores_sessions,
    };
    let store = SeaOrmStore::<Schema>::new(config.clone(), database)
        .with_hooks(vec![Arc::new(events.clone())]);
    let mut builder = AuthBuilder::new(config).store(store);
    if secondary {
        builder = builder.secondary_storage(Arc::new(events.clone()));
    }
    let fixture = Fixture {
        auth: Arc::new(builder.build().await?),
        events,
        secondary,
        preserve,
    };
    Ok(Router::new()
        .route("/health", get(|| async { Json(json!({"status":"ok"})) }))
        .route("/__health", get(|| async { Json(json!({"status":"ok"})) }))
        .route(
            "/__test/reset-state",
            post(|| async { Json(json!({"success":true})) }),
        )
        .route("/__test/database-lifecycle", post(control))
        .with_state(fixture))
}

impl Fixture {
    async fn seed(&self) -> AuthResult<()> {
        *self.events.trace.lock().unwrap() = Trace::default();
        let db = &self.events.database;
        db.execute_unprepared("DROP TRIGGER IF EXISTS fixture_reject_session_update")
            .await
            .map_err(database_error)?;
        db.execute_unprepared("DROP TRIGGER IF EXISTS fixture_reject_session_batch")
            .await
            .map_err(database_error)?;
        let _ = account::Entity::delete_many()
            .exec(db)
            .await
            .map_err(database_error)?;
        let _ = SessionEntity::delete_many()
            .exec(db)
            .await
            .map_err(database_error)?;
        let _ = user::Entity::delete_many()
            .exec(db)
            .await
            .map_err(database_error)?;
        let mut user = <Schema as AuthSchema>::User::new_active(
            Some("u1".into()),
            CreateUser {
                email_verified: Some(true),
                ..CreateUser::new()
                    .with_email("lifecycle@example.test")
                    .with_name("Lifecycle")
            },
            date(CREATED_AT),
        )?;
        user.updated_at = Set(date(UPDATED_AT));
        let user = user.insert(db).await.map_err(database_error)?;
        for id in ["a1", "a2"] {
            let mut account = account::Model::new_active(
                Some(id.into()),
                CreateAccount {
                    account_id: id.into(),
                    provider_id: id.into(),
                    user_id: "u1".into(),
                    password: Default::default(),
                    access_token: Default::default(),
                    refresh_token: Default::default(),
                    id_token: Default::default(),
                    access_token_expires_at: Default::default(),
                    refresh_token_expires_at: Default::default(),
                    scope: Default::default(),
                    ..Default::default()
                }
                .with_timestamps(date(CREATED_AT))
                .fields()?,
            )?;
            account.updated_at = Set(date(UPDATED_AT));
            let _ = account.insert(db).await.map_err(database_error)?;
        }
        for id in ["s1", "s2"] {
            let mut session = Session::new_active(
                Some(id.into()),
                format!("{id}-token"),
                CreateSession {
                    additional_fields: Default::default(),
                    user_id: "u1".into(),
                    expires_at: date(EXPIRES_AT),
                    ip_address: None,
                    user_agent: None,
                    impersonated_by: None,
                    active_organization_id: None,
                },
                date(CREATED_AT),
            );
            session.updated_at = Set(date(UPDATED_AT));
            session.device_label = Set(Some(format!("{id}-old")));
            if self.events.stores_sessions {
                let _ = session.insert(db).await.map_err(database_error)?;
            }
            if self.secondary {
                let cached = json!({"session":{"id":id,"token":format!("{id}-token"),"userId":"u1","label":format!("{id}-old"),
                    "createdAt":CREATED_AT,"updatedAt":UPDATED_AT,"expiresAt":EXPIRES_AT},"user":self.auth.context().internal_user_view(&user).await?});
                let _ = self
                    .events
                    .trace
                    .lock()
                    .unwrap()
                    .cache
                    .insert(format!("{id}-token"), serde_json::to_string(&cached)?);
            }
        }
        if self.secondary {
            let refs = ["s1","s2"].map(|id|json!({"token":format!("{id}-token"),"expiresAt":date(EXPIRES_AT).timestamp_millis()}));
            let _ = self
                .events
                .trace
                .lock()
                .unwrap()
                .cache
                .insert("active-sessions-u1".into(), serde_json::to_string(&refs)?);
        }
        self.events.trace.lock().unwrap().events.clear();
        Ok(())
    }
    async fn configure(&self, options: Value) -> AuthResult<()> {
        {
            let mut trace = self.events.trace.lock().unwrap();
            trace.options = options.clone();
            trace.held_delete = options["holdDeleteKey"].as_str().map(|_| {
                (
                    Arc::new(tokio::sync::Semaphore::new(0)),
                    Arc::new(tokio::sync::Semaphore::new(0)),
                )
            });
        }
        let db = &self.events.database;
        if options["databaseUpdateFailure"] == true {
            db.execute_unprepared("CREATE TRIGGER fixture_reject_session_update BEFORE UPDATE ON sessions BEGIN SELECT RAISE(ABORT, 'fixture session update rejected'); END").await.map_err(database_error)?;
        }
        if options["batchWriteFailure"] == true {
            let operation = if self.preserve { "UPDATE" } else { "DELETE" };
            db.execute_unprepared(&format!("CREATE TRIGGER fixture_reject_session_batch BEFORE {operation} ON sessions BEGIN SELECT RAISE(ABORT, 'fixture session batch rejected'); END")).await.map_err(database_error)?;
        }
        if options["expireSecond"] == true && self.events.stores_sessions {
            let mut active = <<Session as SeaOrmSessionModel>::ActiveModel as Default>::default();
            active.expires_at = Set(date("2000-01-01T00:00:00Z"));
            let _ = SessionEntity::update_many()
                .set(active)
                .filter(Session::id_column().eq("s2"))
                .exec(db)
                .await
                .map_err(database_error)?;
        }
        if options["evictCache"] == true {
            let _ = self.events.trace.lock().unwrap().cache.remove("s1-token");
        }
        if options["missingIndex"] == true {
            let _ = self
                .events
                .trace
                .lock()
                .unwrap()
                .cache
                .remove("active-sessions-u1");
        }
        if options["corruptSession"] == true {
            let _ = self
                .events
                .trace
                .lock()
                .unwrap()
                .cache
                .insert("s1-token".into(), "not-json".into());
        }
        if options["deleteDatabaseSession"] == true && self.events.stores_sessions {
            let _ = SessionEntity::delete_many()
                .filter(Session::id_column().eq("s1"))
                .exec(db)
                .await
                .map_err(database_error)?;
        }
        self.events.trace.lock().unwrap().events.clear();
        Ok(())
    }
    async fn execute(&self, body: &Value) -> AuthResult<Value> {
        let store = self.auth.store();
        match body["operation"].as_str().unwrap() {
            "delete-user-sessions" => store.delete_user_sessions("u1").await?,
            "delete-user" => store.delete_user("u1").await?,
            "delete-sessions" => {
                let tokens: Vec<String> = body.get("tokens").map_or_else(
                    || vec!["s1-token".into(), "s2-token".into()],
                    |tokens| serde_json::from_value(tokens.clone()).unwrap(),
                );
                store.delete_sessions(&tokens).await?;
            }
            "delete-session" => store.delete_session("s1-token").await?,
            "update-session" => {
                let patch = body
                    .get("patch")
                    .cloned()
                    .unwrap_or_else(|| json!({"label":"request"}));
                return Ok(store
                    .update_session_fields("s1-token", patch.as_object().unwrap().clone())
                    .await?
                    .as_ref()
                    .map(session_view)
                    .unwrap_or(Value::Null));
            }
            _ => return Err(AuthError::bad_request("Unknown fixture operation")),
        }
        Ok(Value::Null)
    }
}

async fn control(State(fixture): State<Fixture>, Json(body): Json<Value>) -> Json<Value> {
    match body["action"].as_str() {
        Some("seed") => fixture.seed().await.unwrap(),
        Some("configure") => fixture.configure(body["options"].clone()).await.unwrap(),
        Some("release-delete") => {
            let (released, completed) = fixture
                .events
                .trace
                .lock()
                .unwrap()
                .held_delete
                .clone()
                .unwrap();
            released.add_permits(1);
            completed.acquire().await.unwrap().forget();
        }
        Some("execute") => {
            let result = fixture.execute(&body).await;
            return Json(
                json!({"ok":result.is_ok(),"result":result.unwrap_or(Value::Null),"state":fixture.events.snapshot().await.unwrap()}),
            );
        }
        _ => {}
    }
    Json(json!({"ok":true,"state":fixture.events.snapshot().await.unwrap()}))
}
