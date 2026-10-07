#![cfg(all(feature = "axum", feature = "seaorm2"))]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Captured fixture keys and local SQLite setup must exist; failures stop the contract."
)]

use better_auth::plugins::phone_number::{PhoneNumberCallbacks, PhoneNumberPlugin, PhoneOtp};
use better_auth::{AuthBuilder, AuthConfig};
use better_auth_core::{
    AuthRequest, CreateAccount, CreateUser, HttpMethod, utils::password::hash_password,
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DbBackend, Statement},
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

const PHONE: &str = "+15551230001";
const ORIGIN: &str = "http://phone-duration.test";

#[tokio::test]
async fn phone_issuance_preserves_pinned_fractional_lifetimes() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/phone-duration-1.7.6.json")).unwrap();
    let password = hash_password(None, "ordinary-password").await.unwrap();
    for expected in fixture["cases"].as_array().unwrap() {
        let operation = expected["operation"].as_str().unwrap();
        let name = expected["name"].as_str().unwrap();
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&db).await.unwrap();
        let config = AuthConfig::new("ordinary-phone-duration-secret-longer-than-32-characters")
            .base_url(ORIGIN);
        let sent = Arc::new(Mutex::new(Vec::<(&'static str, PhoneOtp)>::new()));
        let verification = sent.clone();
        let reset = sent.clone();
        let mut plugin = PhoneNumberPlugin::new().require_verification(true);
        if let Some(seconds) = expected.get("configured").and_then(Value::as_f64) {
            plugin = plugin.expires_in(seconds);
        }
        let auth = AuthBuilder::new(config.clone())
            .store(SeaOrmStore::<BundledSchema>::new(config, db.clone()))
            .rate_limit(better_auth_core::middleware::RateLimitConfig {
                enabled: Some(false),
                ..Default::default()
            })
            .plugin(
                plugin.callbacks(
                    PhoneNumberCallbacks::<BundledSchema>::default()
                        .send_otp(move |otp, _| {
                            verification
                                .lock()
                                .unwrap()
                                .push(("verification", otp.clone()));
                            Ok(None)
                        })
                        .send_password_reset_otp(move |otp, _| {
                            reset.lock().unwrap().push(("reset", otp.clone()));
                            Ok(None)
                        }),
                ),
            )
            .build()
            .await
            .unwrap();
        let _ = auth
            .context()
            .database
            .create_user(CreateUser {
                id: Some("ordinary-user".into()),
                name: Some("Phone Duration".into()).into(),
                email: Some("ordinary@phone-duration.test".into()),
                email_verified: Some(false),
                phone_number: Some(PHONE.into()),
                phone_number_verified: Some(false),
                ..Default::default()
            })
            .await
            .unwrap();
        let _ = auth
            .context()
            .database
            .create_account(CreateAccount {
                id: "ordinary-credential".into(),
                account_id: "ordinary-user".into(),
                user_id: "ordinary-user".into(),
                provider_id: "credential".into(),
                password: Some(password.clone()).into(),
                ..Default::default()
            })
            .await
            .unwrap();
        let (path, body) = match operation {
            "send" => Some(("/phone-number/send-otp", json!({"phoneNumber":PHONE}))),
            "signIn" => Some((
                "/sign-in/phone-number",
                json!({"phoneNumber":PHONE,"password":"ordinary-password"}),
            )),
            "reset" => Some((
                "/phone-number/request-password-reset",
                json!({"phoneNumber":PHONE}),
            )),
            _ => None,
        }
        .unwrap();
        let request = AuthRequest::from_parts(
            HttpMethod::Post,
            format!("/api/auth{path}"),
            [
                ("content-type".into(), "application/json".into()),
                ("origin".into(), ORIGIN.into()),
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
            "{name}/{operation}"
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&response.body.bytes().unwrap()).unwrap(),
            expected["body"],
            "{name}/{operation}"
        );
        let rows = db
            .query_all_raw(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT identifier, value, expires_at FROM verifications".to_owned(),
            ))
            .await
            .unwrap();
        let records = expected["records"].as_array().unwrap();
        assert_eq!(rows.len(), records.len(), "{name}/{operation}");
        let mut values = Vec::new();
        for (row, record) in rows.iter().zip(records) {
            let identifier: String = row.try_get("", "identifier").unwrap();
            let value: String = row.try_get("", "value").unwrap();
            let expires_at: DateTime<Utc> = row.try_get("", "expires_at").unwrap();
            let lifetime = record["lifetimeMillis"].as_i64().unwrap();
            assert_eq!(
                json!(identifier),
                record["identifier"],
                "{name}/{operation}"
            );
            assert_eq!(
                json!(value.ends_with(":0")),
                record["attemptSuffix"],
                "{name}/{operation}"
            );
            assert!(
                (before + lifetime..=after + lifetime).contains(&expires_at.timestamp_millis()),
                "{name}/{operation}: issued expiry must equal the issuance clock plus {lifetime} milliseconds"
            );
            values.push(value);
        }
        let actual_sender: Vec<_> = sent.lock().unwrap().iter().map(|(kind, otp)| {
            let stored_value = format!("{}{}", otp.code, if operation == "signIn" { "" } else { ":0" });
            json!({
                "kind": kind, "phone": otp.phone_number, "codeLength": otp.code.len(),
                "decimalCode": !otp.code.is_empty() && otp.code.bytes().all(|byte| byte.is_ascii_digit()),
                "matchesStored": values.contains(&stored_value),
            })
        }).collect();
        assert_eq!(
            json!(actual_sender),
            expected["sender"],
            "{name}/{operation}"
        );
    }
}
