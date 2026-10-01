#![cfg(feature = "seaorm2")]
#![expect(clippy::unwrap_used, reason = "contract setup fails immediately")]

use better_auth::plugins::{
    EmailPasswordPlugin, EmailVerificationPlugin,
    email_otp::{EmailOtpCallbacks, EmailOtpPlugin},
    email_verification::EmailVerificationCallbacks,
};
use better_auth::server_api::EndpointInput;
use better_auth::{AuthBuilder, AuthConfig};
use better_auth_core::HttpMethod;
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::Database,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use serde_json::json;
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn configured_typed_sender_precedes_otp_override_for_direct_and_automatic_delivery() {
    for custom in [false, true] {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let config = AuthConfig::new("priority-contract-secret-longer-than-thirty-two")
            .base_url("http://localhost:3000");
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&db).await.unwrap();
        let otp_calls = calls.clone();
        let mut builder = AuthBuilder::new(config.clone())
            .store(SeaOrmStore::<BundledSchema>::new(config, db))
            .plugin(EmailPasswordPlugin::new())
            .plugin(
                EmailOtpPlugin::new()
                    .override_default_email_verification(true)
                    .callbacks(
                        EmailOtpCallbacks::<BundledSchema>::default().send(move |_, _| {
                            otp_calls.lock().unwrap().push("otp");
                            Ok(None)
                        }),
                    ),
            );
        let plugin = EmailVerificationPlugin::new().send_on_sign_up(true);
        if custom {
            let configured_calls = calls.clone();
            builder = builder.plugin(plugin.callbacks(
                EmailVerificationCallbacks::<BundledSchema>::send(move |_, _| {
                    configured_calls.lock().unwrap().push("configured");
                    Ok(None)
                }),
            ));
        } else {
            builder = builder.plugin(plugin);
        }
        let auth = builder.build().await.unwrap();
        let response = auth.call_endpoint(HttpMethod::Post,"/sign-up/email",EndpointInput {
            body:Some(json!({"name":"Owner","email":"owner@example.com","password":"fixture-password"})),..Default::default()
        }).await.unwrap();
        assert_eq!(response.status, 200);
        let response = auth
            .call_endpoint(
                HttpMethod::Post,
                "/send-verification-email",
                EndpointInput {
                    body: Some(json!({"email":"owner@example.com"})),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(
            *calls.lock().unwrap(),
            vec![if custom { "configured" } else { "otp" }; 2]
        );
    }
}
