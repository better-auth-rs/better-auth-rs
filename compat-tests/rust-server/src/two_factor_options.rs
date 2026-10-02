use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::Query,
    response::IntoResponse,
    routing::{get, post},
};
use better_auth::plugins::two_factor::{
    BackupCodeOptions, BackupCodeStorage, TwoFactorCipher, TwoFactorConfig, TwoFactorOtpStorage,
    TwoFactorPlugin,
};
use better_auth_core::{AuthError, AuthResult};
use better_auth_seaorm::{
    sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder},
    store::entities::{two_factor, verification},
};
use chrono::Duration;
use serde::Deserialize;
use serde_json::json;

struct FixtureCipher;

#[async_trait]
impl TwoFactorCipher for FixtureCipher {
    async fn encrypt(&self, plaintext: &str) -> AuthResult<String> {
        Ok(format!(
            "fixture-{}",
            plaintext.chars().rev().collect::<String>()
        ))
    }

    async fn decrypt(&self, ciphertext: &str) -> AuthResult<String> {
        ciphertext
            .strip_prefix("fixture-")
            .map(|value| value.chars().rev().collect())
            .ok_or_else(|| AuthError::internal("Invalid fixture ciphertext"))
    }
}

pub fn configure(profile: &str) -> TwoFactorConfig {
    if !profile.starts_with("two-factor-") {
        return TwoFactorConfig::default();
    }
    let mut config = TwoFactorConfig {
        allow_passwordless: true,
        skip_verification_on_enable: true,
        issuer: Some("Enrollment Issuer".into()),
        totp_digits: 8,
        totp_period: 60.0,
        otp_digits: 8,
        otp_period: Duration::minutes(2),
        otp_allowed_attempts: 2,
        backup_code_options: BackupCodeOptions {
            amount: 3,
            length: 6,
            ..Default::default()
        },
        ..Default::default()
    };
    match profile {
        "two-factor-plain" => config.backup_code_options.storage = BackupCodeStorage::Plain,
        "two-factor-hashed" => config.otp_storage = TwoFactorOtpStorage::Hashed,
        "two-factor-encrypted" => config.otp_storage = TwoFactorOtpStorage::Encrypted,
        "two-factor-custom" => {
            config.otp_storage = TwoFactorOtpStorage::CustomHash(Arc::new(|code| {
                Box::pin(async move {
                    if code == "codec-error" {
                        return Err(AuthError::Upstream {
                            status: 503,
                            code: "CODEC_UNAVAILABLE",
                            message: "Fixture codec unavailable",
                        });
                    }
                    Ok(format!("fixture-{code}"))
                })
            }));
            config.backup_code_options.storage = BackupCodeStorage::Custom(Arc::new(FixtureCipher));
            config.backup_code_options.generate = Some(Arc::new(|| {
                vec![
                    "duplicate-code".into(),
                    "duplicate-code".into(),
                    "last-code".into(),
                ]
            }));
        }
        "two-factor-custom-encrypted" => {
            config.otp_storage = TwoFactorOtpStorage::CustomEncryption(Arc::new(FixtureCipher))
        }
        "two-factor-disabled" => config.totp_disabled = true,
        "two-factor-password-policy" => {
            config.totp_allow_passwordless = Some(false);
            config.backup_code_options.allow_passwordless = Some(false);
        }
        _ => {}
    }
    config
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StateQuery {
    user_id: String,
}

#[derive(Deserialize)]
struct GenerateBody {
    secret: String,
}

pub fn router(database: DatabaseConnection, plugin: TwoFactorPlugin) -> Router {
    Router::new().route("/__test/two-factor-options", get(move |Query(query): Query<StateQuery>| {
        let database = database.clone();
        async move {
            let result = async {
                let factor = two_factor::Entity::find().filter(two_factor::Column::UserId.eq(query.user_id)).one(&database).await?;
                let otp = verification::Entity::find().filter(verification::Column::Identifier.starts_with("2fa-otp-")).order_by_desc(verification::Column::CreatedAt).one(&database).await?;
                Ok::<_, better_auth_seaorm::sea_orm::DbErr>(json!({
                    "factor": factor.map(|factor| json!({ "secret": factor.secret, "backupCodes": factor.backup_codes, "verified": factor.verified })),
                    "otp": otp.map(|otp| json!({ "value": otp.value, "expiresAt": otp.expires_at, "createdAt": otp.created_at }))
                }))
            }.await;
            match result {
                Ok(value) => Json(value).into_response(),
                Err(error) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
            }
        }
    })).route("/__test/generate-totp", post(move |Json(body): Json<GenerateBody>| {
        let plugin = plugin.clone();
        async move {
            match plugin.generate_totp(&body.secret) {
                Ok(code) => Json(json!({ "code": code })).into_response(),
                Err(error) => error.into_response(),
            }
        }
    }))
}
