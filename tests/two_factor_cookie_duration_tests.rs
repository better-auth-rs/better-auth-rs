#![cfg(all(feature = "axum", feature = "seaorm2"))]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Captured fixture keys and local SQLite setup must exist; failures stop the contract."
)]

use better_auth::plugins::two_factor::TwoFactorCallbacks;
use better_auth::plugins::{EmailPasswordPlugin, TwoFactorConfig, TwoFactorPlugin};
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use better_auth_core::{AuthRequest, AuthResponse, CreateAccount, CreateUser, HttpMethod};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DbBackend, Statement},
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use std::sync::{Arc, Mutex};

const ORIGIN: &str = "http://two-factor-duration.test";
const USER_ID: &str = "ordinary-user";
const EMAIL: &str = "ordinary@two-factor-duration.test";
const PASSWORD: &str = "ordinary-password";

async fn request(
    auth: &BetterAuth<BundledSchema>,
    path: &str,
    body: Value,
    cookie: Option<&str>,
) -> AuthResponse {
    let mut headers = std::collections::HashMap::from([
        ("content-type".to_owned(), "application/json".to_owned()),
        ("origin".to_owned(), ORIGIN.to_owned()),
    ]);
    if let Some(cookie) = cookie {
        let _ = headers.insert("cookie".to_owned(), cookie.to_owned());
    }
    let request = AuthRequest::from_parts(
        HttpMethod::Post,
        format!("/api/auth{path}"),
        headers,
        Some(serde_json::to_vec(&body).unwrap()),
        None,
    )
    .with_url(format!("{ORIGIN}/api/auth{path}").parse().unwrap());
    auth.handle_request(request).await.unwrap()
}

fn selected_cookie(response: &AuthResponse, suffix: &str) -> String {
    let prefix = format!("better-auth.{suffix}=");
    let cookies: Vec<_> = response
        .headers
        .get_all("set-cookie")
        .filter(|header| header.starts_with(&prefix))
        .collect();
    assert_eq!(cookies.len(), 1, "one {suffix} issuance cookie");
    cookies[0].clone()
}

fn cookie_shape(header: &str) -> Value {
    let mut parts = header.split("; ");
    let name = parts.next().unwrap().split_once('=').unwrap().0;
    let attributes: Map<_, _> = parts
        .map(|part| match part.split_once('=') {
            Some((name, value)) => (name.to_ascii_lowercase(), json!(value)),
            None => (part.to_ascii_lowercase(), json!(true)),
        })
        .collect();
    json!({"name":name,"attributes":attributes})
}

#[tokio::test]
async fn two_factor_cookie_issuance_preserves_pinned_fractional_lifetimes() {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/two-factor-cookie-duration-1.7.6.json"
    ))
    .unwrap();
    let password = better_auth_core::hash_password(None, PASSWORD)
        .await
        .unwrap();
    for expected in fixture["cases"].as_array().unwrap() {
        let name = expected["name"].as_str().unwrap();
        let operation = expected["operation"].as_str().unwrap();
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&db).await.unwrap();
        let config =
            AuthConfig::new("ordinary-two-factor-duration-secret-longer-than-32-characters")
                .base_url(ORIGIN);
        let mut factor_config = TwoFactorConfig {
            totp_disabled: true,
            ..Default::default()
        };
        if let Some(seconds) = expected.get("configured").and_then(Value::as_f64) {
            if operation == "challenge" {
                factor_config.two_factor_cookie_max_age = seconds;
            } else {
                factor_config.trust_device_max_age = seconds;
            }
        }
        let sent = Arc::new(Mutex::new(Vec::<(String, String, String)>::new()));
        let output = sent.clone();
        let auth = AuthBuilder::new(config.clone())
            .store(SeaOrmStore::<BundledSchema>::new(config, db.clone()))
            .rate_limit(better_auth_core::RateLimitConfig {
                enabled: Some(false),
                ..Default::default()
            })
            .plugin(EmailPasswordPlugin::new())
            .plugin(TwoFactorPlugin::with_config(factor_config).callbacks(
                TwoFactorCallbacks::<BundledSchema>::default().send(move |user, otp, _| {
                    output.lock().unwrap().push((
                        user.id.display_string()?,
                        user.email.clone().unwrap(),
                        otp.to_owned(),
                    ));
                    Ok(None)
                }),
            ))
            .build()
            .await
            .unwrap();
        let _ = auth
            .context()
            .database
            .create_user(CreateUser {
                id: Some(USER_ID.into()),
                name: Some("Two Factor Duration".into()).into(),
                email: Some(EMAIL.into()),
                email_verified: Some(true),
                ..Default::default()
            })
            .await
            .unwrap();
        let _ = auth
            .context()
            .database
            .create_account(CreateAccount {
                id: "ordinary-credential".into(),
                account_id: USER_ID.into(),
                user_id: USER_ID.into(),
                provider_id: "credential".into(),
                password: Some(password.clone()).into(),
                ..Default::default()
            })
            .await
            .unwrap();
        let _ = auth
            .context()
            .database
            .update_user(
                &USER_ID.to_owned(),
                better_auth_core::UpdateUser {
                    two_factor_enabled: Some(true),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let mut before = Utc::now().timestamp_millis();
        let sign_in = request(
            &auth,
            "/sign-in/email",
            json!({"email":EMAIL,"password":PASSWORD}),
            None,
        )
        .await;
        assert_eq!(sign_in.status, 200, "{name}/{operation}: ordinary sign-in");
        let response = if operation == "challenge" {
            sign_in
        } else {
            let pending_header = selected_cookie(&sign_in, "two_factor");
            let pending = pending_header.split(';').next().unwrap();
            let send = request(&auth, "/two-factor/send-otp", json!({}), Some(pending)).await;
            assert_eq!(send.status, 200, "{name}: ordinary OTP delivery");
            let otp = {
                let sent = sent.lock().unwrap();
                assert_eq!(sent.len(), 1);
                sent[0].2.clone()
            };
            before = Utc::now().timestamp_millis();
            request(
                &auth,
                "/two-factor/verify-otp",
                json!({"code":otp,"trustDevice":true}),
                Some(pending),
            )
            .await
        };
        let after = Utc::now().timestamp_millis();
        assert_eq!(
            json!(response.status),
            expected["status"],
            "{name}/{operation}"
        );
        let body: Value = serde_json::from_slice(&response.body.bytes().unwrap()).unwrap();
        let body = if operation == "challenge" {
            body
        } else {
            json!({
                "tokenPresent":body["token"].as_str().is_some_and(|token| !token.is_empty()),
                "user": {
                    "id":body["user"]["id"],"name":body["user"]["name"],
                    "email":body["user"]["email"],"emailVerified":body["user"]["emailVerified"],
                    "twoFactorEnabled":body["user"]["twoFactorEnabled"],
                },
            })
        };
        assert_eq!(body, expected["body"], "{name}/{operation}");
        let suffix = if operation == "challenge" {
            "two_factor"
        } else {
            "trust_device"
        };
        assert_eq!(
            cookie_shape(&selected_cookie(&response, suffix)),
            expected["cookie"],
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
        let mut actual_records = Vec::new();
        let mut challenge_dates = Vec::new();
        for row in &rows {
            let identifier: String = row.try_get("", "identifier").unwrap();
            let selected = if operation == "challenge" {
                identifier.starts_with("2fa-")
            } else {
                identifier.starts_with("trust-device-")
            };
            if !selected {
                continue;
            }
            let kind = if identifier.starts_with("2fa-attempts-") {
                "attempts"
            } else {
                operation
            };
            let record = records
                .iter()
                .find(|record| record["kind"] == kind)
                .unwrap();
            let lifetime = record["lifetimeMillis"].as_i64().unwrap();
            let expires_at: DateTime<Utc> = row.try_get("", "expires_at").unwrap();
            let expires_at = expires_at.timestamp_millis();
            assert!(
                (before + lifetime..=after + lifetime).contains(&expires_at),
                "{name}/{operation}/{kind}: stored expiry uses issuance time plus {lifetime} milliseconds"
            );
            let value: String = row.try_get("", "value").unwrap();
            actual_records.push(json!({"kind":kind,"value":value,"lifetimeMillis":lifetime}));
            challenge_dates.push(expires_at);
        }
        if operation == "challenge" {
            assert_eq!(challenge_dates.len(), 2);
            assert_eq!(
                challenge_dates[0], challenge_dates[1],
                "one challenge expiry"
            );
        }
        actual_records.sort_by(|a, b| a["kind"].as_str().cmp(&b["kind"].as_str()));
        assert_eq!(
            json!(actual_records),
            expected["records"],
            "{name}/{operation}"
        );
        let sender: Vec<_> = sent
            .lock()
            .unwrap()
            .iter()
            .map(|(user_id, email, otp)| {
                json!({
                    "userId":user_id,"email":email,"codeLength":otp.len(),
                    "decimalCode":!otp.is_empty() && otp.bytes().all(|byte| byte.is_ascii_digit()),
                })
            })
            .collect();
        assert_eq!(json!(sender), expected["sender"], "{name}/{operation}");
    }
}
