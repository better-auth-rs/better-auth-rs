#![cfg(feature = "seaorm2")]
#![allow(
    unreachable_pub,
    reason = "SeaORM entity derives require public generated model types"
)]

use better_auth::config::SessionFieldConfig;
use better_auth::plugins::{EmailPasswordPlugin, SessionManagementPlugin};
use better_auth::prelude::{AuthRequest, HttpMethod};
use better_auth::seaorm::sea_orm::{self, ConnectionTrait, Schema, entity::prelude::*};
use better_auth::seaorm::{AuthEntity, Database, SeaOrmStore};
use better_auth::store::{MemoryCacheAdapter, SecondaryStorage};
use better_auth::{AuthConfig, AuthSchema, BetterAuth};
use serde_json::{Value, json};
use std::sync::Arc;

mod session {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "session")]
    #[sea_orm(table_name = "application_sessions")]
    #[serde(rename_all = "camelCase")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub expires_at: DateTimeUtc,
        pub token: String,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        pub ip_address: Option<String>,
        pub user_agent: Option<String>,
        pub user_id: String,
        pub active: bool,
        #[serde(rename(serialize = "storedLabel"))]
        pub display_label: Option<String>,
        pub internal_note: Option<String>,
        pub device_color: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

struct AppSchema;
impl AuthSchema for AppSchema {
    type User = better_auth_seaorm::store::entities::user::Model;
    type Session = session::Model;
    type Account = better_auth_seaorm::store::entities::account::Model;
    type Verification = better_auth_seaorm::store::entities::verification::Model;
}

fn request(path: &str, cookie: &str, body: Option<Value>) -> AuthRequest {
    let mut req = AuthRequest::new(
        if body.is_some() {
            HttpMethod::Post
        } else {
            HttpMethod::Get
        },
        path,
    );
    if !cookie.is_empty() {
        let _ = req.headers.insert("cookie".into(), cookie.into());
        let _ = req
            .headers
            .insert("origin".into(), "http://localhost:3000".into());
    }
    if let Some(body) = body {
        req.body = Some(body.to_string().into_bytes());
        let _ = req
            .headers
            .insert("content-type".into(), "application/json".into());
    }
    req
}

// Rust-specific surface: application-owned SeaORM fields must preserve the upstream update-session input and output contract.
#[tokio::test]
async fn update_session_persists_only_allowed_fields_and_returns_the_configured_shape() {
    check_session_fields("storedLabel", None).await;
}

#[tokio::test]
async fn session_storage_aliases_survive_database_and_secondary_round_trips() {
    for alias in ["display_label", "displayLabel", "storedLabel"] {
        for database in [false, true] {
            check_session_fields(alias, Some(database)).await;
        }
    }
}

async fn check_session_fields(alias: &str, secondary: Option<bool>) {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&db)
        .await
        .unwrap();
    let backend = db.get_database_backend();
    let _ = db
        .execute(&Schema::new(backend).create_table_from_entity(session::Entity))
        .await
        .unwrap();
    let mut config = AuthConfig::new("session-fields-test-secret-at-least-32-chars")
        .base_url("http://localhost:3000");
    let _ = config.session.fields_mut().insert(
        "label".into(),
        SessionFieldConfig {
            field_name: Some(alias.into()),
            ..Default::default()
        },
    );
    let _ = config.session.fields_mut().insert(
        "internalNote".into(),
        SessionFieldConfig {
            field_name: Some("internalNote".into()),
            input: Some(false),
            returned: Some(false),
            ..Default::default()
        },
    );
    let _ = config
        .session
        .fields_mut()
        .insert("deviceColor".into(), SessionFieldConfig::default());
    config.session.store_session_in_database = Some(secondary.unwrap_or(true));
    let cache = Arc::new(MemoryCacheAdapter::new());
    let mut builder = BetterAuth::<AppSchema>::new(config.clone())
        .store(SeaOrmStore::<AppSchema>::new(config, db.clone()));
    if secondary.is_some() {
        builder = builder.secondary_storage(cache.clone());
    }
    let auth = builder
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(SessionManagementPlugin::new())
        .build()
        .await
        .unwrap();
    let signup = auth
        .handle_request(request(
            "/sign-up/email",
            "",
            Some(json!({
                "email": "fields@example.com", "password": "Password123!", "name": "Fields",
            })),
        ))
        .await
        .unwrap();
    assert_eq!(signup.status, 200);
    let cookie = signup
        .headers
        .get_all("set-cookie")
        .find(|cookie| cookie.starts_with("better-auth.session_token="))
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let response = auth.handle_request(request("/update-session", cookie, Some(json!({
        "label": "Work laptop", "deviceColor": "silver", "token": "attacker", "expiresAt": "2099-01-01T00:00:00Z",
    })))).await.unwrap();
    assert_eq!(response.status, 200);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["session"]["label"], "Work laptop");
    assert_ne!(body["session"]["token"], "attacker");
    assert!(body["session"].get("internalNote").is_none());
    if secondary != Some(false) {
        let stored = session::Entity::find().one(&db).await.unwrap().unwrap();
        assert_eq!(stored.display_label.as_deref(), Some("Work laptop"));
        assert_eq!(stored.device_color.as_deref(), Some("silver"));
        assert!(stored.internal_note.is_none());
    } else {
        assert!(session::Entity::find().one(&db).await.unwrap().is_none());
    }
    let token = body["session"]["token"].as_str().unwrap().to_owned();
    if secondary.is_some() {
        let cached = cache.get(&token).await.unwrap().unwrap();
        let cached: Value = serde_json::from_str(cached.as_str().unwrap()).unwrap();
        assert_eq!(cached["session"]["label"], "Work laptop");
        assert!(cached["session"].get(alias).is_none());
    }
    let response = auth
        .handle_request(request("/get-session", cookie, None))
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["session"]["label"], "Work laptop");
    assert_eq!(body["session"]["deviceColor"], "silver");
    for (input, code) in [
        (
            json!({"internalNote": "secret", "label": "blocked"}),
            Some("FIELD_NOT_ALLOWED"),
        ),
        (json!({"internalNote": false}), None),
        (json!({"unknown": "ignored"}), None),
    ] {
        let response = auth
            .handle_request(request("/update-session", cookie, Some(input)))
            .await
            .unwrap();
        assert_eq!(response.status, 400);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body.get("code").and_then(Value::as_str), code);
    }
    if secondary != Some(false) {
        let stored = session::Entity::find().one(&db).await.unwrap().unwrap();
        assert_eq!(stored.display_label.as_deref(), Some("Work laptop"));
    }
    let response = auth
        .handle_request(request(
            "/update-session",
            "",
            Some(json!({"label": "anonymous"})),
        ))
        .await
        .unwrap();
    assert_eq!(response.status, 401);
    let response = auth
        .handle_request(request(
            "/update-session",
            cookie,
            Some(json!({"label":null})),
        ))
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    let cleared: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(cleared["session"].get("label"), Some(&Value::Null));
    let response = auth
        .handle_request(request("/get-session", cookie, None))
        .await
        .unwrap();
    let cleared: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(cleared["session"].get("label"), Some(&Value::Null));
    assert_eq!(cleared["session"]["deviceColor"], "silver");
    if secondary != Some(false) {
        let stored = session::Entity::find().one(&db).await.unwrap().unwrap();
        assert!(stored.display_label.is_none());
    }
}
