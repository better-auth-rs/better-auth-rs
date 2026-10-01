use better_auth::config::{IdGeneration, IdGenerator};
use better_auth::plugins::{EmailPasswordPlugin, SessionManagementPlugin};
use better_auth::{AuthConfig, BetterAuth};
use better_auth_core::store::{MemoryCacheAdapter, SecondaryStorage};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
#[path = "common/id_runtime.rs"]
mod support;
use support::{Hasher, request};

#[tokio::test]
async fn missing_ids_match_upstream_signup_signin_and_session_cache_boundaries() {
    for secondary in [false, true] {
        for mode in [
            "database",
            "callback-empty",
            "user-missing",
            "session-missing",
            "account-missing",
        ] {
            let mut config =
                AuthConfig::new("runtime-id-probe-secret-at-least-thirty-two-characters")
                    .base_url("http://localhost:3000");
            let calls = Arc::new(AtomicUsize::new(0));
            config.advanced.database.generate_id = if mode == "database" {
                IdGeneration::Database
            } else {
                IdGeneration::Custom(IdGenerator::new(move |request| {
                    let count = calls.fetch_add(1, Ordering::SeqCst) + 1;
                    Ok(Some(
                        if mode == "callback-empty" || mode == format!("{}-missing", request.model)
                        {
                            String::new()
                        } else {
                            format!("{}-{count}", request.model)
                        },
                    ))
                }))
            };
            let cache = Arc::new(MemoryCacheAdapter::new());
            let mut builder = BetterAuth::stateless(config)
                .plugin(EmailPasswordPlugin::new().password_hasher(Arc::new(Hasher)))
                .plugin(SessionManagementPlugin::new());
            if secondary {
                builder = builder.secondary_storage(cache.clone());
            }
            let auth = builder.build().await.unwrap();
            let credentials =
                json!({"email":"id@example.com", "name":"ID", "password":"long-enough-password"});
            let signup = request(&auth, "/sign-up/email", Some(credentials.clone()), "").await;
            assert_eq!(signup.0, 200, "{mode} secondary={secondary}: {}", signup.1);
            let missing_user = ["database", "callback-empty", "user-missing"].contains(&mode);
            assert_eq!(
                signup.1["user"].get("id").is_none(),
                missing_user,
                "{mode} secondary={secondary}"
            );
            let first = request(&auth, "/get-session", None, &signup.2).await;
            assert_eq!(first.0, 200, "{mode} secondary={secondary}: {}", first.1);
            assert_eq!(
                first.1.is_null(),
                missing_user && !secondary,
                "{mode} secondary={secondary}: {}",
                first.1
            );
            if !first.1.is_null() {
                let missing_session = mode == "callback-empty"
                    || mode == "session-missing"
                    || (!secondary && mode == "database");
                assert_eq!(
                    first.1["session"].get("id").is_none(),
                    missing_session,
                    "{mode} secondary={secondary}: {}",
                    first.1
                );
                assert_eq!(first.1["session"].get("userId").is_none(), missing_user);
            }
            let signin = request(&auth, "/sign-in/email", Some(credentials), "").await;
            assert_eq!(
                signin.0,
                if missing_user { 401 } else { 200 },
                "{mode} secondary={secondary}: {}",
                signin.1
            );
            if missing_user {
                assert_eq!(signin.1["code"], "INVALID_EMAIL_OR_PASSWORD");
            }
            let second = request(&auth, "/get-session", None, &signin.2).await;
            assert_eq!(second.0, 200);
            assert_eq!(
                second.1.is_null(),
                missing_user,
                "{mode} secondary={secondary}: {}",
                second.1
            );
            if secondary && missing_user {
                assert!(
                    cache
                        .get("active-sessions-undefined")
                        .await
                        .unwrap()
                        .is_some()
                );
            }
        }
    }
}
