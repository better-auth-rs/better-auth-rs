#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    clippy::panic,
    reason = "The shared cache contract fails on missing cache observations or malformed case definitions"
)]

use better_auth_core::{
    AuthRequest, AuthResult, CookieCacheConfig, CookieCacheStrategy, FieldMap, FieldValue,
    FromFieldMap, HttpMethod, SessionView, UserView,
    session::{SessionData, SessionManager, SessionRead},
    store::{
        EphemeralStore, MemoryCacheAdapter, SecondaryStorage, SessionStore, StatelessSchema,
        secondary::SecondaryStore,
    },
};
use std::sync::Arc;

#[path = "support/user_runtime_output_contract.rs"]
#[expect(
    dead_code,
    reason = "The shared contract also supplies adapter output configuration and seeding"
)]
mod contract;

fn session() -> FieldMap {
    let date: chrono::DateTime<chrono::Utc> = contract::DATE.parse().unwrap();
    FieldMap::from([
        ("id".into(), "runtime-session".into()),
        ("userId".into(), contract::OWNER.into()),
        ("token".into(), "runtime-token".into()),
        ("createdAt".into(), date.into()),
        ("updatedAt".into(), date.into()),
        (
            "expiresAt".into(),
            "2100-01-01T00:00:00.000Z"
                .parse::<chrono::DateTime<chrono::Utc>>()
                .unwrap()
                .into(),
        ),
    ])
}

#[tokio::test]
async fn secondary_user_cache_keeps_native_values_and_applies_only_user_date_constructors()
-> AuthResult<()> {
    let config = Arc::new(contract::config()?);
    let cache = Arc::new(MemoryCacheAdapter::new());
    let raw = Arc::new(EphemeralStore::new(config.clone()));
    let store =
        SecondaryStore::<StatelessSchema>::new(raw, cache.clone(), config, Default::default())?;
    for case in contract::cases()?["cache"].as_array().unwrap() {
        let name = case["field"].as_str().unwrap();
        let mut user = contract::native_user();
        let _ = user.insert(name.into(), contract::revive(&case["value"])?);
        let envelope = FieldValue::from(FieldMap::from([
            ("session".into(), session().into()),
            ("user".into(), user.into()),
        ]));
        let encoded = envelope.stringify()?.unwrap();
        cache.set("runtime-token", &encoded, None).await?;
        let (_, snapshot) = store.get_session_snapshot("runtime-token").await?.unwrap();
        let snapshot = snapshot.unwrap().into_typed()?.unwrap();
        let fields = FieldMap::from(snapshot.user);
        let expected = case.get("secondaryValue").unwrap_or(&case["value"]);
        assert_eq!(
            contract::observe(fields.get(name).unwrap_or(&FieldValue::Undefined))?,
            *expected,
            "{}",
            case["name"]
        );
        assert_eq!(cache.get("runtime-token").await?, Some(encoded.into()));
    }
    Ok(())
}

#[tokio::test]
async fn signed_user_cookie_cache_uses_the_upstream_schema_for_every_encoding_strategy()
-> AuthResult<()> {
    let cases = contract::cases()?;
    for strategy in [
        CookieCacheStrategy::Compact,
        CookieCacheStrategy::Jwt,
        CookieCacheStrategy::Jwe,
    ] {
        for case in cases["cache"].as_array().unwrap() {
            let mut config = contract::config()?;
            config.session.cookie_cache = Some(CookieCacheConfig {
                enabled: Some(true),
                strategy: Some(strategy),
                ..Default::default()
            });
            let config = Arc::new(config);
            let raw = Arc::new(EphemeralStore::new(config.clone()));
            let manager = SessionManager::new(config, raw);
            let name = case["field"].as_str().unwrap();
            let mut user = contract::native_user();
            let _ = user.insert(name.into(), contract::revive(&case["value"])?);
            let data = SessionData {
                user: UserView::from_field_values(user)?,
                session: SessionView::from_field_values(session())?,
            };
            let write = AuthRequest::new(HttpMethod::Get, "/issue-cookie");
            manager
                .set_session_cookie(&write, data, Some(false))
                .await?;
            let headers = write.take_response_headers()?;
            assert!(
                headers
                    .get_all("set-cookie")
                    .any(|value| value.starts_with("better-auth.session_data="))
            );
            let cookie = headers
                .get_all("set-cookie")
                .map(|value| value.split(';').next().unwrap())
                .collect::<Vec<_>>()
                .join("; ");
            let mut read = AuthRequest::new(HttpMethod::Get, "/get-session");
            let _ = read.headers.insert("cookie".into(), cookie);
            let before = chrono::Utc::now().timestamp_millis();
            let result = manager.resolve(&read, SessionRead::Cached).await?.data;
            let after = chrono::Utc::now().timestamp_millis();
            let accepted = if strategy == CookieCacheStrategy::Compact {
                case.get("compact").unwrap_or(&case["cookie"])
            } else {
                &case["cookie"]
            };
            assert_eq!(
                result.is_some(),
                accepted.as_bool().unwrap(),
                "{strategy:?} / {}",
                case["name"]
            );
            if let Some(data) = result {
                let fields = FieldMap::from(data.user);
                let observed = fields.get(name).unwrap();
                if case
                    .get("cookieDefaultDate")
                    .and_then(serde_json::Value::as_bool)
                    == Some(true)
                {
                    let FieldValue::Date(date) = observed else {
                        panic!("Default cache timestamp must be a Date");
                    };
                    assert!((before as f64..=after as f64).contains(&date.milliseconds()));
                } else {
                    assert_eq!(
                        contract::observe(observed)?,
                        case["cookieValue"],
                        "{strategy:?} / {}",
                        case["name"]
                    );
                }
            }
        }
    }
    Ok(())
}
