use std::sync::Arc;

use axum::{Json, Router, routing::post};
use better_auth::{AuthConfig, BetterAuth};
use better_auth_core::utils::{jwe, symmetric};
use better_auth_core::{AuthUser, CreateUser, CreateVerification, SecretKey, VersionedSecret};
use chrono::{Duration, Utc};
use serde_json::{Value, json};

use super::TestSchema;

pub(super) const CURRENT: &str = "current-rotation-key-with-32-characters-123";
pub(super) const PREVIOUS: &str = "previous-rotation-key-with-32-characters-456";

pub(super) fn configure(profile: &str, config: &mut AuthConfig) {
    if !profile.starts_with("crypto-") {
        return;
    }
    config.secrets = Some(vec![
        VersionedSecret::new(2, CURRENT),
        VersionedSecret::new(1, PREVIOUS),
    ]);
    config.account.encrypt_oauth_tokens = Some(true);
    config.account.store_account_cookie = Some(true);
    if profile == "crypto-cookie" {
        config.account.store_state_strategy = Some(better_auth::config::OAuthStateStrategy::Cookie);
    }
}

pub(super) fn router(auth: Arc<BetterAuth<TestSchema>>) -> Router {
    Router::new().route("/__test/crypto", post(move |Json(body): Json<Value>| {
        let auth = auth.clone();
        async move {
            let store = auth.store();
            let operation = body["operation"].as_str().unwrap();
            if operation == "state" {
                let state = body["state"].as_str().unwrap();
                if let Some(value) = body.get("value") {
                    store.delete_verification_by_identifier(state).await.unwrap();
                    store.create_verification(CreateVerification {
identifier: state.into(),
value: (value.as_str().map(str::to_owned).unwrap_or_else(|| value.to_string())).into(),
expires_at: (Utc::now() + Duration::minutes(10)).into(),
..Default::default()
}).await.unwrap();
                }
                let verification = store.get_verification_by_identifier(state).await.unwrap();
                return Json(json!({"value": verification.as_ref().map(|v| &v.value)}));
            }
            if operation == "user" {
                let user = store.create_user(CreateUser {
                    id: Some(body["id"].as_str().unwrap().into()),
                    email: Some(body["email"].as_str().unwrap().into()),
                    name: Some("Cookie transfer".into()).into(),
                    email_verified: Some(true),
                    ..Default::default()
                }).await.unwrap();
                return Json(json!({"id": user.id()}));
            }
            if operation == "accounts" {
                let user = store.get_user_by_email(body["email"].as_str().unwrap()).await.unwrap().unwrap();
                let accounts = store.get_user_accounts(user.id().typed().unwrap().as_ref()).await.unwrap();
                return Json(json!(accounts.iter().map(|a| json!({"id":a.id, "userId":a.user_id, "providerId":a.provider_id, "accountId":a.account_id, "accessToken":a.access_token, "refreshToken":a.refresh_token, "idToken":a.id_token})).collect::<Vec<_>>()));
            }
            let keys: Vec<_> = body["secrets"].as_array().map(|keys| keys.iter().map(|key| VersionedSecret::new(key["version"].as_u64().unwrap().into(), key["value"].as_str().unwrap())).collect()).unwrap_or_default();
            let key = if let Some(secret) = body["secret"].as_str() { SecretKey::Single(secret) }
                else if body.get("secrets").is_some() { SecretKey::Versioned { keys: &keys, legacy_secret: body["legacySecret"].as_str() } }
                else { auth.config().encryption_secret() };
            let salt = body["salt"].as_str().unwrap_or("better-auth-account");
            let result = match operation {
                "encrypt" => symmetric::encrypt(key, body["data"].as_str().unwrap()).map(Value::String),
                "decrypt" => symmetric::decrypt(key, body["data"].as_str().unwrap()).map(Value::String),
                "encode" => jwe::encode(body["data"].as_object().unwrap().clone(), key, salt, body["expiresIn"].as_f64().unwrap_or(3600.0)).map(Value::String),
                "decode" => Ok(jwe::decode(body["data"].as_str().unwrap(), key, salt).map(Value::Object).unwrap_or(Value::Null)),
                _ => panic!("Unknown crypto operation"),
            };
            Json(match result { Ok(value) => json!({"ok":true,"value":value}), Err(_) => json!({"ok":false}) })
        }
    }))
}
