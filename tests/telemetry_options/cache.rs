use super::*;
use better_auth::__private_core::store::{EphemeralStore, MemoryCacheAdapter};
use chrono::{Duration, Utc};

pub(super) fn oracle(name: &str) -> AuthResult<Value> {
    let data: Value =
        serde_json::from_str(include_str!("../fixtures/telemetry-cache-init-1.7.6.json"))?;
    data.get(name)
        .cloned()
        .ok_or_else(|| AuthError::internal(format!("missing cache initialization oracle: {name}")))
}

async fn initialize(storage: &str, config: AuthConfig) -> AuthResult<BetterAuth<S>> {
    let builder = if storage == "database" {
        BetterAuth::new(config.clone()).store(EphemeralStore::new(Arc::new(config)))
    } else {
        let builder = BetterAuth::stateless(config);
        if storage == "secondary" {
            builder.secondary_storage(Arc::new(MemoryCacheAdapter::new()))
        } else {
            builder
        }
    };
    builder.build().await
}

#[tokio::test]
async fn cache_metadata_matches_real_initialization_with_each_storage_mode() -> AuthResult<()> {
    for storage in ["stateless", "database", "secondary"] {
        for name in [
            "omitted",
            "empty",
            "disabled",
            "zeroLifetime",
            "customLifetime",
        ] {
            let case = format!("{storage}-{name}");
            let expected = oracle(&case)?;
            let (mut config, reports) = configuration();
            match name {
                "empty" => config.session.cookie_cache = Some(CookieCacheConfig::default()),
                "disabled" => {
                    config.session.cookie_cache = Some(CookieCacheConfig {
                        enabled: Some(false),
                        ..Default::default()
                    })
                }
                "zeroLifetime" => config.session.expires_in = Some(Duration::zero()),
                "customLifetime" => config.session.expires_in = Some(Duration::seconds(90)),
                _ => {}
            }
            let auth = initialize(storage, config).await?;
            assert_eq!(
                reports.config()?.get("session"),
                expected.get("session"),
                "{case}"
            );
            assert_eq!(
                Some(auth.context().config.session.expires_in().num_seconds()),
                expected.get("expiresIn").and_then(Value::as_i64),
                "{case}"
            );
            assert_eq!(
                auth.context().config.session.cookie_cache.is_some(),
                expected.get("cache").is_some(),
                "{case}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn explicit_zero_session_lifetime_creates_a_persisted_seven_day_session() -> AuthResult<()> {
    for storage in ["stateless", "database", "secondary"] {
        let (mut config, reports) = configuration();
        config.session.expires_in = Some(Duration::zero());
        let auth = initialize(storage, config).await?;
        let user = auth
            .store()
            .create_user(super::core::CreateUser::new().with_email("zero-lifetime@example.test"))
            .await?;
        let before = Utc::now() + Duration::days(7);
        let session = auth
            .session_manager()
            .create_session(&user, None, None)
            .await?;
        let after = Utc::now() + Duration::days(7);
        assert!(
            (before.timestamp_millis()..=after.timestamp_millis())
                .contains(&session.expires_at.timestamp_millis()),
            "{storage}: created expiry {}",
            session.expires_at
        );
        let persisted = auth
            .store()
            .get_session(&session.token)
            .await?
            .ok_or_else(|| AuthError::internal("created session missing"))?;
        assert_eq!(
            persisted.expires_at.timestamp_millis(),
            session.expires_at.timestamp_millis()
        );
        assert_eq!(
            reports.config()?.pointer("/session/expiresIn"),
            Some(&serde_json::json!(0))
        );
    }
    Ok(())
}
