#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "Session query regressions compare exact selected rows and output callback traces"
)]

use std::sync::{Arc, Mutex};

use better_auth_core::{
    AuthConfig, AuthContext, AuthResult, AuthSchema, CreateSession, CreateUser, FieldMap,
    FieldValue, SchemaValue,
    store::{
        AuthStore, EphemeralStore, MemoryCacheAdapter, SecondaryStorage, secondary::SecondaryStore,
    },
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
    wire::SessionView,
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::Database,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use chrono::{Duration, Utc};
use serde_json::json;

async fn seed<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    owner: FieldValue,
    token: &str,
    expires: chrono::DateTime<Utc>,
) -> AuthResult<SessionView> {
    store
        .create_session(CreateSession {
            user_id: SchemaValue::from_field(owner),
            expires_at: expires.into(),
            additional_fields: [("token".into(), token.into())].into(),
            inherited_fields: Default::default(),
            ip_address: Some(token.into()),
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await
}

async fn active_query<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    mut config: AuthConfig,
) -> AuthResult<()> {
    let owner = raw
        .create_user(
            CreateUser::new()
                .with_email("list-filter@example.test")
                .with_name("Session owner"),
        )
        .await?;
    let expired = seed(
        raw.as_ref(),
        owner.id.field_value(),
        "expired",
        Utc::now() - Duration::hours(1),
    )
    .await?;
    let active = seed(
        raw.as_ref(),
        owner.id.field_value(),
        "active",
        Utc::now() + Duration::hours(1),
    )
    .await?;
    let trace = Arc::new(Mutex::new(Vec::new()));
    let observed = trace.clone();
    config.advanced.database.default_find_many_limit = Some(1.0);
    let _ = config.session.fields_mut().insert(
        "ipAddress".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                input: None,
                output: Some(UserFieldTransform::new(move |value| {
                    observed.lock().unwrap().push(value.clone());
                    Ok(value)
                })),
            }),
            ..Default::default()
        },
    );
    let config = Arc::new(config);
    let store = raw.with_runtime(config.clone(), Vec::new(), Default::default())?;
    let context = AuthContext::new(config, store);
    let listed = super::list_sessions_core(&owner.id.field_value(), &context).await?;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].token, active.token);
    assert_eq!(*trace.lock().unwrap(), [FieldValue::from("active")]);
    trace.lock().unwrap().clear();
    let unfiltered = context
        .database
        .get_user_session_snapshots_value(&owner.id.field_value(), false)
        .await?;
    assert_eq!(unfiltered.len(), 1);
    assert_eq!(unfiltered[0].0.token, expired.token);
    assert_eq!(*trace.lock().unwrap(), [FieldValue::from("expired")]);
    assert_eq!(raw.get_session("expired").await?, Some(expired));
    assert_eq!(raw.get_session("active").await?, Some(active));
    Ok(())
}

#[tokio::test]
async fn memory_and_sql_filter_expired_rows_before_limit_and_output_callbacks() -> AuthResult<()> {
    for renamed in [false, true] {
        let mut config = AuthConfig::default();
        if renamed {
            for (name, column) in [("expiresAt", "createdAt"), ("createdAt", "expiresAt")] {
                let _ = config.session.fields_mut().insert(
                    name.into(),
                    UserFieldConfig {
                        field_name: Some(column.into()),
                        field_type: better_auth_core::user_fields::UserFieldType::Date,
                        ..Default::default()
                    },
                );
            }
        }
        active_query(
            Arc::new(EphemeralStore::new(Arc::new(config.clone()))),
            config.clone(),
        )
        .await?;
        let connection = Database::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&connection).await.unwrap();
        active_query(
            Arc::new(SeaOrmStore::<BundledSchema>::new(
                config.clone(),
                connection,
            )),
            config,
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn session_lists_preserve_native_owner_selectors_without_string_coercion() -> AuthResult<()> {
    for renamed in [false, true] {
        let mut config = AuthConfig::default();
        if renamed {
            let _ = config.session.fields_mut().insert(
                "userId".into(),
                UserFieldConfig {
                    field_name: Some("ownerKey".into()),
                    ..Default::default()
                },
            );
        }
        let config = Arc::new(config);
        let store = Arc::new(EphemeralStore::new(config.clone()));
        let expiry = Utc::now() + Duration::hours(1);
        let numeric = seed(store.as_ref(), 7.0.into(), "numeric-owner", expiry).await?;
        let text = seed(store.as_ref(), "7".into(), "string-owner", expiry).await?;
        let missing = seed(
            store.as_ref(),
            FieldValue::Undefined,
            "missing-owner",
            expiry,
        )
        .await?;
        let context = AuthContext::new(config, store);
        // Replacing the declaration removes the native userId reference output conversion.
        let numeric_output = if renamed { 7.0.into() } else { "7".into() };
        for (owner, expected, output_owner) in [
            (7.0.into(), numeric, numeric_output),
            ("7".into(), text, "7".into()),
            (FieldValue::Undefined, missing, FieldValue::Undefined),
        ] {
            let listed = super::list_sessions_core(&owner, &context).await?;
            assert_eq!(listed.len(), 1);
            assert_eq!(listed[0].token, expected.token);
            assert_eq!(listed[0].user_id.field_value(), output_owner);
        }
    }
    Ok(())
}

#[tokio::test]
async fn secondary_lists_keep_cache_field_presence_and_native_owner_keys() -> AuthResult<()> {
    let expiry = Utc::now() + Duration::hours(1);
    let mut config = AuthConfig::default();
    let _ = config.session.fields_mut().insert(
        "hidden".into(),
        UserFieldConfig {
            returned: Some(false),
            ..Default::default()
        },
    );
    let config = Arc::new(config);
    let inner = Arc::new(EphemeralStore::new(config.clone()));
    let cache = Arc::new(MemoryCacheAdapter::new());
    let cached = json!({"session": {
        "id": "cached-session", "userId": 7, "token": "cached-token",
        "expiresAt": expiry.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "createdAt": "original-text", "note": null, "hidden": "private"
    }});
    cache.set("cached-token", &cached.to_string(), None).await?;
    cache
        .set(
            "active-sessions-7",
            &json!([{
                "token": "cached-token", "expiresAt": expiry.timestamp_millis()
            }])
            .to_string(),
            None,
        )
        .await?;
    let store = Arc::new(SecondaryStore::new(
        inner,
        cache.clone(),
        config.clone(),
        Default::default(),
    )?);
    let context = AuthContext::new(config, store);
    let listed = super::list_sessions_core(&7.0.into(), &context).await?;
    assert_eq!(listed.len(), 1);
    assert_eq!(
        FieldMap::from(listed[0].clone()),
        FieldMap::from([
            ("id".into(), "cached-session".into()),
            ("userId".into(), 7.0.into()),
            ("token".into(), "cached-token".into()),
            ("expiresAt".into(), expiry.into()),
            ("createdAt".into(), "original-text".into()),
            ("note".into(), FieldValue::Null),
        ])
    );
    assert_eq!(
        cache.get("cached-token").await?,
        Some(serde_json::Value::String(cached.to_string()))
    );
    Ok(())
}
