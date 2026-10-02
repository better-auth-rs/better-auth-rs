#![cfg(all(feature = "axum", feature = "seaorm2"))]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Captured fixture keys and local SQLite setup must exist; failures stop the contract."
)]

use better_auth::plugins::AdminPlugin;
use better_auth::{AuthBuilder, AuthConfig};
use better_auth_core::{
    AuthRequest, CookieCacheConfig, CreateSession, CreateUser, HttpMethod,
    utils::cookie_utils::sign_cookie_value,
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DbBackend, Statement},
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

const ORIGIN: &str = "http://admin-duration.test";

fn timestamp(value: &Value) -> i64 {
    DateTime::parse_from_rfc3339(value.as_str().unwrap())
        .unwrap()
        .timestamp_millis()
}

fn user(row: &Value) -> Value {
    json!({"name":row["name"], "email":row["email"], "role":row["role"]})
}

fn ban(row: &Value, issued_at: i64) -> Value {
    let mut value = user(row);
    value["banned"] = row["banned"].clone();
    value["banReason"] = row["banReason"].clone();
    value["lifetimeMillis"] = if row["banExpires"].is_null() {
        Value::Null
    } else {
        json!(timestamp(&row["banExpires"]) - issued_at)
    };
    value
}

fn session(row: &Value, issued_at: i64) -> Value {
    json!({"userId":row["userId"], "impersonatedBy":row["impersonatedBy"],
        "lifetimeMillis":timestamp(&row["expiresAt"]) - issued_at})
}

fn cookie(header: &str) -> Value {
    let mut parts = header.split(';').map(str::trim);
    let (name, value) = parts.next().unwrap().split_once('=').unwrap();
    let attributes: serde_json::Map<_, _> = parts
        .map(|attribute| match attribute.split_once('=') {
            Some((name, value)) => (
                name.to_lowercase(),
                json!(if name.eq_ignore_ascii_case("samesite") {
                    value.to_lowercase()
                } else {
                    value.to_owned()
                }),
            ),
            None => (attribute.to_lowercase(), true.into()),
        })
        .collect();
    json!({"name":name, "valuePresent":!value.is_empty(), "attributes":attributes})
}

#[tokio::test]
async fn admin_configuration_preserves_fractional_ban_and_impersonation_lifetimes() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/admin-duration-1.7.6.json")).unwrap();
    let valid_until: DateTime<Utc> = "2099-01-01T00:00:00Z".parse().unwrap();
    for expected in fixture["cases"].as_array().unwrap() {
        let name = expected["name"].as_str().unwrap();
        let operation = expected["operation"].as_str().unwrap();
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&db).await.unwrap();
        let mut config =
            AuthConfig::new("ordinary-admin-duration-secret-longer-than-32-characters")
                .base_url(ORIGIN);
        config.session.cookie_cache = Some(CookieCacheConfig {
            enabled: Some(false),
            ..Default::default()
        });
        let mut plugin = AdminPlugin::new();
        if let Some(seconds) = expected.get("configured").and_then(Value::as_f64) {
            plugin = if operation == "ban" {
                plugin.default_ban_expires_in(seconds)
            } else {
                plugin.impersonation_session_duration(seconds)
            };
        }
        let auth = AuthBuilder::new(config.clone())
            .store(SeaOrmStore::<BundledSchema>::new(config, db.clone()))
            .rate_limit(better_auth_core::middleware::RateLimitConfig {
                enabled: Some(false),
                ..Default::default()
            })
            .plugin(plugin)
            .build()
            .await
            .unwrap();
        let store = &auth.context().database;
        for (id, display_name, role) in [
            ("admin", "Ordinary Admin", "admin"),
            ("ordinary", "Ordinary User", "user"),
        ] {
            let _ = store
                .create_user(CreateUser {
                    id: Some(id.into()),
                    name: Some(display_name.into()).into(),
                    email: Some(format!("{id}@admin-duration.test")),
                    email_verified: Some(true),
                    role: Some(role.into()),
                    banned: Some(false),
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        let actor = store
            .create_session(CreateSession {
                user_id: "admin".into(),
                expires_at: valid_until,
                additional_fields: Default::default(),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await
            .unwrap();
        let signed_cookie = format!(
            "better-auth.session_token={}",
            sign_cookie_value(&actor.token, auth.config().signing_secret())
        );
        let mut body = json!({"userId":"ordinary"});
        if operation == "ban" {
            body["banReason"] = "Ordinary administrative update".into();
        }
        if let Some(seconds) = expected.get("requested") {
            body["banExpiresIn"] = seconds.clone();
        }
        let path = if operation == "ban" {
            "/admin/ban-user"
        } else {
            "/admin/impersonate-user"
        };
        let request = AuthRequest::from_parts(
            HttpMethod::Post,
            format!("/api/auth{path}"),
            [
                ("content-type".into(), "application/json".into()),
                ("origin".into(), ORIGIN.into()),
                ("cookie".into(), signed_cookie),
            ]
            .into(),
            Some(serde_json::to_vec(&body).unwrap()),
            None,
        )
        .with_url(format!("{ORIGIN}/api/auth{path}").parse().unwrap());
        let before = Utc::now().timestamp_millis();
        let response = auth.handle_request(request).await.unwrap();
        let after = Utc::now().timestamp_millis();
        assert_eq!(
            json!(response.status),
            expected["status"],
            "{operation}/{name}"
        );
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        let row = db
            .query_one_raw(Statement::from_string(DbBackend::Sqlite,
                "SELECT id, name, email, role, banned, ban_reason, ban_expires FROM users WHERE id = 'ordinary'".to_owned()))
            .await.unwrap().unwrap();
        let ban_expires: Option<DateTime<Utc>> = row.try_get("", "ban_expires").unwrap();
        let stored_user = json!({
            "id": row.try_get::<String>("", "id").unwrap(),
            "name": row.try_get::<String>("", "name").unwrap(),
            "email": row.try_get::<String>("", "email").unwrap(),
            "role": row.try_get::<Option<String>>("", "role").unwrap(),
            "banned": row.try_get::<bool>("", "banned").unwrap(),
            "banReason": row.try_get::<Option<String>>("", "ban_reason").unwrap(),
            "banExpires": ban_expires,
        });
        let rows = db
            .query_all_raw(Statement::from_string(DbBackend::Sqlite,
                "SELECT id, token, user_id, impersonated_by, expires_at FROM sessions WHERE user_id = 'ordinary'".to_owned()))
            .await.unwrap();
        let stored_sessions: Vec<_> = rows
            .into_iter()
            .map(|row| {
                json!({
                    "id": row.try_get::<String>("", "id").unwrap(),
                    "token": row.try_get::<String>("", "token").unwrap(),
                    "userId": row.try_get::<String>("", "user_id").unwrap(),
                    "impersonatedBy": row.try_get::<Option<String>>("", "impersonated_by").unwrap(),
                    "expiresAt": row.try_get::<DateTime<Utc>>("", "expires_at").unwrap(),
                })
            })
            .collect();
        assert_eq!(
            stored_sessions.len(),
            expected["issuedSessions"].as_array().unwrap().len(),
            "{operation}/{name}"
        );
        let (lifetime, expiry) = if operation == "ban" {
            (
                expected["storedUser"]["lifetimeMillis"].as_i64(),
                ban_expires.map(|date| date.timestamp_millis()),
            )
        } else {
            (
                expected["issuedSessions"][0]["lifetimeMillis"].as_i64(),
                Some(timestamp(&stored_sessions[0]["expiresAt"])),
            )
        };
        let issued_at = match (lifetime, expiry) {
            (Some(lifetime), Some(expiry)) => {
                assert!(
                    (before + lifetime..=after + lifetime).contains(&expiry),
                    "{operation}/{name}: expiry must equal the issuance clock plus {lifetime} milliseconds"
                );
                expiry - lifetime
            }
            (None, None) => before,
            _ => {
                panic!("{operation}/{name}: stored expiry presence differs from captured lifetime")
            }
        };
        let actual_body = if operation == "ban" {
            json!({"user":ban(&body["user"], issued_at)})
        } else {
            json!({"user":user(&body["user"]), "session":session(&body["session"], issued_at)})
        };
        assert_eq!(actual_body, expected["body"], "{operation}/{name}");
        let actual_user = if operation == "ban" {
            ban(&stored_user, issued_at)
        } else {
            user(&stored_user)
        };
        assert_eq!(actual_user, expected["storedUser"], "{operation}/{name}");
        let actual_sessions: Vec<_> = stored_sessions
            .iter()
            .map(|row| session(row, issued_at))
            .collect();
        assert_eq!(
            json!(actual_sessions),
            expected["issuedSessions"],
            "{operation}/{name}"
        );
        let matches = if operation == "ban" {
            body["user"]["id"] == stored_user["id"]
                && if body["user"]["banExpires"].is_null() {
                    ban_expires.is_none()
                } else {
                    Some(timestamp(&body["user"]["banExpires"])) == expiry
                }
        } else {
            body["session"]["id"] == stored_sessions[0]["id"]
                && body["session"]["token"] == stored_sessions[0]["token"]
                && Some(timestamp(&body["session"]["expiresAt"])) == expiry
        };
        assert_eq!(
            json!(matches),
            expected["responseMatchesStored"],
            "{operation}/{name}"
        );
        let cookies: Vec<_> = response
            .headers
            .get_all("set-cookie")
            .map(|header| cookie(header))
            .collect();
        assert_eq!(json!(cookies), expected["cookies"], "{operation}/{name}");
    }
}
