use crate::store::secondary::SecondaryStore;
use crate::store::{
    EphemeralStore, MemoryCacheAdapter, SecondaryStorage, SessionStore, StatelessSchema, UserStore,
    VerificationStore,
};
use crate::types::{CreateSession, CreateUser, CreateVerification, UpdateUser};
use crate::user_fields::{UserFieldConfig, UserFieldType};
use crate::{AuthConfig, AuthResult, FieldDate, FieldMap, FieldValue, SchemaValue};
use std::sync::Arc;

const NOW: i64 = 4_102_444_800_000;
const EXPIRY: i64 = NOW + 3_600_000;
const DATE_TEXT: &str = "2100-01-01T00:00:00.000Z";

fn payload(number: f64) -> FieldValue {
    FieldMap::from([
        ("10".into(), 10.0.into()),
        ("2".into(), number.into()),
        (
            "text".into(),
            crate::Utf16String::from_units(vec![0xdc00]).into(),
        ),
    ])
    .into()
}

fn storage() -> AuthResult<(SecondaryStore<StatelessSchema>, Arc<MemoryCacheAdapter>)> {
    let mut config = AuthConfig::default();
    for (name, field_type) in [
        ("payload", UserFieldType::Json),
        ("dateText", UserFieldType::String),
    ] {
        let _ = config.session.fields_mut().insert(
            name.into(),
            UserFieldConfig {
                field_type,
                ..Default::default()
            },
        );
    }
    let config = Arc::new(config);
    let inner = Arc::new(EphemeralStore::new(config.clone()));
    let cache = Arc::new(MemoryCacheAdapter::new());
    let store = SecondaryStore::new(inner, cache.clone(), config, Default::default())?
        .with_clock(|| chrono::DateTime::from_timestamp_millis(NOW).unwrap());
    Ok((store, cache))
}

fn session_input(user_id: SchemaValue<String>, token: FieldValue) -> CreateSession {
    CreateSession {
        inherited_fields: FieldMap::new(),
        additional_fields: FieldMap::from([
            ("token".into(), token),
            ("payload".into(), payload(1e-7)),
            ("dateText".into(), DATE_TEXT.into()),
            (
                "createdAt".into(),
                FieldDate::from_milliseconds(NOW as f64).into(),
            ),
            (
                "updatedAt".into(),
                FieldDate::from_milliseconds(NOW as f64).into(),
            ),
        ]),
        user_id,
        expires_at: FieldDate::from_milliseconds(EXPIRY as f64),
        ip_address: None,
        user_agent: None,
        impersonated_by: None,
        active_organization_id: None,
    }
}

async fn encoded(cache: &MemoryCacheAdapter, key: &FieldValue) -> AuthResult<String> {
    let value = cache
        .get_native(key)
        .await?
        .expect("Cache entry must exist");
    Ok(value
        .as_str()
        .expect("Cache entry must contain JSON text")
        .to_owned())
}

fn assert_payload(fields: &FieldMap, number: f64) {
    assert_eq!(fields.get("payload"), Some(&payload(number)));
}

#[tokio::test]
async fn session_cache_preserves_native_values_through_index_update_and_user_refresh()
-> AuthResult<()> {
    let (store, cache) = storage()?;
    let user = store
        .create_user(
            CreateUser::new()
                .with_email("native-cache@example.com")
                .with_name("Before"),
        )
        .await?;
    let id = user.id.typed()?.clone();
    let token: FieldValue = crate::Utf16String::from_units(vec![0xd800]).into();
    let created = store
        .create_session(session_input(user.id, token.clone()))
        .await?;
    assert_eq!(created.token.field_value(), token);
    let index = format!("active-sessions-{id}");
    assert_eq!(
        encoded(&cache, &index.into()).await?,
        format!(r#"[{{"token":"\ud800","expiresAt":{EXPIRY}}}]"#),
    );
    assert!(
        encoded(&cache, &token)
            .await?
            .contains(r#""payload":{"2":1e-7,"10":10,"text":"\udc00"}"#)
    );
    let found = store.get_session_by_token_value(&token).await?.unwrap();
    assert_payload(&found.additional_fields, 1e-7);
    assert!(matches!(
        found.additional_fields.get("dateText"),
        Some(FieldValue::Date(_))
    ));
    let listed = store.get_user_sessions(&id).await?;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].token.field_value(), token);
    assert_payload(&listed[0].additional_fields, 1e-7);
    assert_eq!(
        listed[0].additional_fields.get("dateText"),
        Some(&DATE_TEXT.into())
    );

    let updated = store
        .update_session_fields_by_token_value(
            &token,
            FieldMap::from([("payload".into(), payload(1e-8))]),
        )
        .await?
        .unwrap();
    assert_payload(&updated.additional_fields, 1e-8);
    assert!(
        encoded(&cache, &token)
            .await?
            .contains(r#""payload":{"2":1e-8,"10":10,"text":"\udc00"}"#)
    );
    let before_refresh =
        crate::utils::json::parse_native_json(&encoded(&cache, &token).await?.into())?;
    store
        .update_user(
            &id,
            UpdateUser {
                name: Some("After".to_owned()).into(),
                ..Default::default()
            },
        )
        .await?;
    let refreshed = crate::utils::json::parse_native_json(&encoded(&cache, &token).await?.into())?;
    let before = before_refresh.as_object().unwrap().snapshot_fields()?;
    let after = refreshed.as_object().unwrap().snapshot_fields()?;
    assert_eq!(after.get("session"), before.get("session"));
    assert_eq!(
        after
            .get("user")
            .unwrap()
            .as_object()
            .unwrap()
            .get("name")?,
        Some("After".into()),
    );
    assert_payload(
        &store
            .get_session_by_token_value(&token)
            .await?
            .unwrap()
            .additional_fields,
        1e-8,
    );
    Ok(())
}

#[tokio::test]
async fn session_single_and_batch_reads_keep_their_parsing_and_malformed_record_policies()
-> AuthResult<()> {
    let (store, cache) = storage()?;
    let user = store
        .create_user(CreateUser::new().with_email("batch-cache@example.com"))
        .await?;
    let id = user.id.typed()?.clone();
    store
        .create_session(session_input(user.id, "valid".into()))
        .await?;
    let (_, single) = store.get_session_snapshot("valid").await?.unwrap();
    assert!(matches!(
        single.unwrap().session.additional_fields.get("dateText"),
        Some(FieldValue::Date(_))
    ));
    for (key, value) in [
        ("broken-json", "{"),
        ("broken-record", r#"{"session":null,"user":null}"#),
        ("falsy", "false"),
    ] {
        cache.set(key, value, None).await?;
    }
    assert!(store.get_session_snapshot("broken-json").await?.is_none());
    assert!(store.get_session_snapshot("falsy").await?.is_none());
    assert!(store.get_session_snapshot("broken-record").await.is_err());
    let tokens = ["broken-json", "broken-record", "falsy", "absent", "valid"].map(str::to_owned);
    let batch = store.get_session_snapshots(&tokens, true).await?;
    assert_eq!(batch.len(), 1);
    assert_payload(&batch[0].0.additional_fields, 1e-7);
    assert_eq!(
        batch[0].0.additional_fields.get("dateText"),
        Some(&DATE_TEXT.into())
    );
    cache.set(
        &format!("active-sessions-{id}"),
        &format!(r#"[{{"token":"broken-json","expiresAt":{EXPIRY}}},{{"token":"broken-record","expiresAt":{EXPIRY}}},{{"token":"valid","expiresAt":{EXPIRY}}}]"#),
        None,
    ).await?;
    let listed = store.get_user_sessions(&id).await?;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].token, "valid");
    Ok(())
}

#[tokio::test]
async fn verification_cache_preserves_native_fields_through_update_and_atomic_consumption()
-> AuthResult<()> {
    let (store, cache) = storage()?;
    let native = FieldValue::from(crate::Utf16String::from_units(vec![0xd800]));
    let input = CreateVerification {
        identifier: "native".into(),
        value: SchemaValue::from_field(native.clone()),
        expires_at: FieldDate::from_milliseconds(EXPIRY as f64).into(),
        additional_fields: FieldMap::from([("payload".into(), payload(1e-7))]),
        ..Default::default()
    };
    store.create_verification(input).await?;
    let initial = encoded(&cache, &"verification:native".into()).await?;
    assert!(initial.contains(r#""value":"\ud800""#));
    assert!(initial.contains(r#""payload":{"2":1e-7,"10":10,"text":"\udc00"}"#));
    let found = store
        .get_verification_by_identifier("native")
        .await?
        .unwrap();
    assert_eq!(found.value.field_value(), native);
    assert_payload(&found.additional_fields, 1e-7);
    let updated = store
        .update_verification(
            "native",
            crate::store::database_hooks::VerificationUpdate {
                additional_fields: FieldMap::from([("payload".into(), payload(1e-8))]),
                ..Default::default()
            },
        )
        .await?
        .unwrap();
    assert_eq!(updated.value.field_value(), native);
    assert!(
        encoded(&cache, &"verification:native".into())
            .await?
            .contains(r#""payload":{"2":1e-8,"10":10,"text":"\udc00"}"#)
    );
    let consumed = store
        .consume_verification_by_identifier("native")
        .await?
        .unwrap();
    assert_eq!(consumed.value.field_value(), native);
    assert_payload(&consumed.additional_fields, 1e-8);
    assert!(
        store
            .consume_verification_by_identifier("native")
            .await?
            .is_none()
    );
    assert!(
        cache
            .get_native(&"verification:native".into())
            .await?
            .is_none()
    );
    for value in ["{", "false", "null"] {
        cache.set("verification:malformed", value, None).await?;
        assert!(
            store
                .get_verification_including_expired("malformed")
                .await?
                .is_none()
        );
        assert!(
            store
                .consume_verification_including_expired("malformed")
                .await?
                .is_none()
        );
    }
    Ok(())
}
