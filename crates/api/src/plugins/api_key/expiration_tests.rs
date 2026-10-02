use super::*;
use better_auth_core::CreateUser;
use chrono::Utc;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExpirationConfig {
    default_expires_in: Option<f64>,
    min_expires_in: Option<f64>,
    max_expires_in: Option<f64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Expected {
    name: String,
    lifetime_millis: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    name: String,
    key_expiration: ExpirationConfig,
    create_expires_in: Option<f64>,
    update_expires_in: Option<f64>,
    created: Expected,
    stored_created: Expected,
    updated: Expected,
    stored_updated: Expected,
}

fn check_date(value: Option<&str>, expected: &Expected, before: i64, after: i64) {
    match (value, expected.lifetime_millis) {
        (None, None) => {}
        (Some(date), Some(lifetime)) => {
            let origin = chrono::DateTime::parse_from_rfc3339(date)
                .unwrap()
                .timestamp_millis()
                - lifetime;
            assert!(
                (before..=after).contains(&origin),
                "{before} <= {origin} <= {after}"
            );
        }
        pair => panic!("unexpected expiration presence: {pair:?}"),
    }
}

#[tokio::test]
async fn expiration_config_preserves_fractional_defaults_and_day_bounds_in_sqlite() -> AuthResult<()>
{
    let cases: Vec<Case> = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/api-key-expiration-1.7.6.json"
    ))?;
    for case in cases {
        let ctx = crate::plugins::test_helpers::create_test_context().await;
        let user = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_name("Expiration Owner")
                    .with_email("owner@key-expiration.test"),
            )
            .await?;
        let user_id = user.id.typed()?.clone();
        let defaults = KeyExpirationConfig::default();
        let plugin = ApiKeyPlugin::builder()
            .key_expiration(KeyExpirationConfig {
                default_expires_in: case.key_expiration.default_expires_in,
                min_expires_in: case
                    .key_expiration
                    .min_expires_in
                    .unwrap_or(defaults.min_expires_in),
                max_expires_in: case
                    .key_expiration
                    .max_expires_in
                    .unwrap_or(defaults.max_expires_in),
                ..defaults
            })
            .build();
        let before_create = Utc::now().timestamp_millis();
        let created = plugin
            .create_key(
                &ctx,
                &CreateKeyRequest {
                    user_id: Some(user_id.clone()),
                    name: Some("Desk".into()),
                    expires_in: case.create_expires_in,
                    ..Default::default()
                },
            )
            .await?
            .api_key;
        let after_create = Utc::now().timestamp_millis();
        assert_eq!(
            created.name.typed()?.as_deref(),
            Some(case.created.name.as_str()),
            "{}",
            case.name
        );
        check_date(
            created.expires_at.as_deref(),
            &case.created,
            before_create,
            after_create,
        );
        let stored = ctx
            .database
            .get_api_key_by_id(created.id.typed()?)
            .await?
            .unwrap();
        assert_eq!(
            stored.name.typed()?.as_deref(),
            Some(case.stored_created.name.as_str())
        );
        assert_eq!(stored.expires_at, created.expires_at);
        check_date(
            stored.expires_at.as_deref(),
            &case.stored_created,
            before_create,
            after_create,
        );

        let before_update = Utc::now().timestamp_millis();
        let updated = plugin
            .update_key(
                &ctx,
                &UpdateKeyRequest {
                    user_id: Some(user_id),
                    key_id: created.id.typed()?.clone(),
                    name: Some("Mobile".into()),
                    expires_in: case.update_expires_in.map(Some),
                    ..Default::default()
                },
            )
            .await?;
        let after_update = Utc::now().timestamp_millis();
        let (before, after) = if case.update_expires_in.is_some() {
            (before_update, after_update)
        } else {
            assert_eq!(updated.expires_at, created.expires_at);
            (before_create, after_create)
        };
        assert_eq!(
            updated.name.typed()?.as_deref(),
            Some(case.updated.name.as_str())
        );
        check_date(updated.expires_at.as_deref(), &case.updated, before, after);
        let stored_updated = ctx
            .database
            .get_api_key_by_id(created.id.typed()?)
            .await?
            .unwrap();
        assert_eq!(
            stored_updated.name.typed()?.as_deref(),
            Some(case.stored_updated.name.as_str())
        );
        assert_eq!(stored_updated.expires_at, updated.expires_at);
        check_date(
            stored_updated.expires_at.as_deref(),
            &case.stored_updated,
            before,
            after,
        );
        assert_eq!(stored_updated.id, stored.id);
        assert_eq!(stored_updated.reference_id, stored.reference_id);
        assert_eq!(stored_updated.config_id, stored.config_id);
        assert_eq!(stored_updated.key_hash, stored.key_hash);
    }
    Ok(())
}
