#![cfg(all(feature = "axum", feature = "seaorm2"))]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Integration fixtures fail immediately on invalid setup or changed persisted values."
)]

use async_trait::async_trait;
use better_auth::plugins::password_management::{PasswordManagementConfig, SendResetPassword};
use better_auth::plugins::{EmailPasswordPlugin, PasswordManagementPlugin};
use better_auth::{AuthBuilder, AuthConfig, server_api::EndpointInput};
use better_auth_core::{AuthResult, CreateUser, HttpMethod};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DbBackend, Statement},
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct Sender(Mutex<Vec<String>>);

#[async_trait]
impl SendResetPassword for Sender {
    async fn send(&self, _: &Value, _: &str, token: &str) -> AuthResult<()> {
        self.0.lock().unwrap().push(token.to_owned());
        Ok(())
    }
}

#[tokio::test]
async fn sqlite_reset_dates_preserve_pinned_fractional_lifetimes() {
    let fixture: BTreeMap<String, Value> =
        serde_json::from_str(include_str!("fixtures/duration-options-1.7.6.json")).unwrap();
    for (name, expected) in fixture {
        let configured = if name == "nan" {
            Some(f64::NAN)
        } else {
            expected.get("configured").and_then(Value::as_f64)
        };
        let config = AuthConfig::new("ordinary-duration-sqlite-secret-more-than-32-characters")
            .base_url("https://duration-options.test");
        let database = Database::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&database).await.unwrap();
        let sender = Arc::new(Sender::default());
        let reset = PasswordManagementPlugin::with_config(PasswordManagementConfig {
            reset_password_token_expires_in: configured,
            send_reset_password: Some(sender.clone()),
            ..Default::default()
        });
        let auth = AuthBuilder::<BundledSchema>::new(config.clone())
            .store(SeaOrmStore::<BundledSchema>::new(config, database.clone()))
            .plugin(EmailPasswordPlugin::new())
            .plugin(reset)
            .build()
            .await
            .unwrap();
        let _user = auth
            .context()
            .database
            .create_user(
                CreateUser::new()
                    .with_name("Duration User")
                    .with_email("duration@example.test"),
            )
            .await
            .unwrap();
        let before = chrono::Utc::now().timestamp_millis();
        let response = auth
            .call_endpoint(
                HttpMethod::Post,
                "/request-password-reset",
                EndpointInput {
                    body: Some(json!({"email":"duration@example.test"})),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let after = chrono::Utc::now().timestamp_millis();
        assert_eq!(response.status, 200, "{name}");
        assert_eq!(
            serde_json::from_slice::<Value>(&response.body).unwrap(),
            expected["response"],
            "{name}"
        );
        let tokens = sender.0.lock().unwrap().clone();
        assert_eq!(
            tokens.len(),
            expected["senderCalls"].as_u64().unwrap() as usize,
            "{name}"
        );
        let row = database
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT expires_at FROM verifications WHERE identifier = ?",
                [format!("reset-password:{}", tokens[0]).into()],
            ))
            .await
            .unwrap()
            .unwrap();
        let expires_at: chrono::DateTime<chrono::Utc> = row.try_get("", "expires_at").unwrap();
        let lifetime = expected["lifetimeMillis"].as_i64().unwrap();
        assert!(
            (before + lifetime..=after + lifetime).contains(&expires_at.timestamp_millis()),
            "{name}: persisted expiry {} must be within [{}, {}]",
            expires_at.timestamp_millis(),
            before + lifetime,
            after + lifetime,
        );
    }
}
