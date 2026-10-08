use super::*;
use crate::store::database_hooks::SessionUpdate;

fn session(user_id: &str) -> CreateSession {
    CreateSession {
        inherited_fields: Default::default(),
        user_id: user_id.into(),
        expires_at: (Utc::now() + chrono::Duration::hours(1)).into(),
        additional_fields: Default::default(),
        ip_address: None,
        user_agent: None,
        impersonated_by: None,
        active_organization_id: None,
    }
}

async fn access(
    store: &EphemeralStore,
    user_id: &str,
    account_id: &str,
) -> AuthResult<SessionView> {
    let account = store
        .create_account(CreateAccount {
            user_id: user_id.into(),
            provider_id: "fixture".into(),
            account_id: account_id.into(),
            ..Default::default()
        })
        .await?;
    assert!(matches!(account.user_id.field_value(), Value::String(_)));
    store.create_session(session(user_id)).await
}

fn raw_owners(store: &EphemeralStore) -> AuthResult<(Vec<Value>, Vec<Value>)> {
    let state = store.lock()?;
    let sessions = state
        .sessions
        .snapshot()?
        .into_iter()
        .map(|session| session.user_id.field_value())
        .collect();
    let accounts = state
        .accounts
        .snapshot()?
        .into_iter()
        .map(|account| Ok(required(account.get("userId"))?.clone()))
        .collect::<AuthResult<_>>()?;
    Ok((sessions, accounts))
}

#[tokio::test]
async fn serial_user_deletion_cleans_owned_access_for_canonical_and_aliased_ids() -> AuthResult<()>
{
    for id in ["1", "01", "0x1"] {
        let store = serial_store(false);
        for name in ["owner", "other"] {
            let _ = store.create_user(user(name)).await?;
        }
        let first = access(&store, "1", "first").await?;
        let second = access(&store, "01", "second").await?;
        let other = access(&store, "02", "other").await?;
        assert_eq!(first.user_id, "1");
        assert_eq!(second.user_id, "1");
        assert_eq!(other.user_id, "2");
        assert_eq!(
            raw_owners(&store)?,
            (
                vec![Value::Number(1.0), Value::Number(1.0), Value::Number(2.0)],
                vec![Value::Number(1.0), Value::Number(1.0), Value::Number(2.0)]
            )
        );
        store.delete_user(id).await?;
        assert!(store.get_user_by_id("1").await?.is_none());
        assert_eq!(required(store.get_user_by_id("2").await?)?.id, "2");
        assert!(
            store
                .get_session(first.token.typed().unwrap())
                .await?
                .is_none()
        );
        assert!(
            store
                .get_session(second.token.typed().unwrap())
                .await?
                .is_none()
        );
        assert_eq!(
            required(store.get_session(other.token.typed().unwrap()).await?)?.user_id,
            "2"
        );
        assert_eq!(
            store
                .get_user_accounts("02")
                .await?
                .into_iter()
                .map(|account| account.account_id)
                .collect::<Vec<_>>(),
            [crate::SchemaValue::from("other")]
        );
        assert_eq!(
            raw_owners(&store)?,
            (vec![Value::Number(2.0)], vec![Value::Number(2.0)])
        );
    }
    Ok(())
}

#[tokio::test]
async fn serial_session_owner_update_rebinds_aliases_for_list_and_delete() -> AuthResult<()> {
    let store = serial_store(false);
    for name in ["first", "second"] {
        let _ = store.create_user(user(name)).await?;
    }
    let moved = store.create_session(session("01")).await?;
    let retained = store.create_session(session("1")).await?;
    assert_eq!(moved.user_id, "1");
    let updated = required(
        SessionStore::update_session_with_writer(
            &store,
            moved.token.typed().unwrap(),
            SessionUpdate {
                user_id: Some("0x2".into()),
                ..Default::default()
            },
            None,
        )
        .await?,
    )?;
    assert_eq!(updated.user_id, "2");
    assert_eq!(
        raw_owners(&store)?,
        (vec![Value::Number(2.0), Value::Number(1.0)], Vec::new())
    );
    for (id, token, owner) in [
        ("01", retained.token.typed().unwrap(), "1"),
        ("02", moved.token.typed().unwrap(), "2"),
    ] {
        let sessions = store.get_user_sessions(id).await?;
        assert_eq!(sessions.len(), 1);
        let session = required(sessions.first())?;
        assert_eq!(session.token.typed().unwrap(), token);
        assert_eq!(session.user_id, owner);
    }
    assert_eq!(
        store.delete_user_sessions_optional("0x2", false).await?,
        Some(1)
    );
    assert!(
        store
            .get_session(moved.token.typed().unwrap())
            .await?
            .is_none()
    );
    assert_eq!(
        required(store.get_session(retained.token.typed().unwrap()).await?)?.user_id,
        "1"
    );
    assert_eq!(raw_owners(&store)?, (vec![Value::Number(1.0)], Vec::new()));
    Ok(())
}

#[tokio::test]
async fn serial_unproven_user_verification_cleans_access_once_through_aliases() -> AuthResult<()> {
    let store = serial_store(false);
    for name in ["unproven", "other"] {
        let _ = store.create_user(user(name)).await?;
    }
    let revoked = access(&store, "01", "unproven").await?;
    let retained = access(&store, "2", "other").await?;
    let verified = required(store.verify_user_and_revoke_unproven_access("0x1").await?)?;
    assert_eq!(verified.id, "1");
    assert!(*verified.email_verified.typed()?);
    assert!(
        !*required(store.get_user_by_id("2").await?)?
            .email_verified
            .typed()?
    );
    assert!(
        store
            .get_session(revoked.token.typed().unwrap())
            .await?
            .is_none()
    );
    assert_eq!(
        required(store.get_session(retained.token.typed().unwrap()).await?)?.user_id,
        "2"
    );
    assert_eq!(
        raw_owners(&store)?,
        (vec![Value::Number(2.0)], vec![Value::Number(2.0)])
    );
    let proven = access(&store, "1", "proven").await?;
    assert!(
        *required(store.verify_user_and_revoke_unproven_access("01").await?)?
            .email_verified
            .typed()?
    );
    assert_eq!(
        required(store.get_session(proven.token.typed().unwrap()).await?)?.user_id,
        "1"
    );
    assert_eq!(
        raw_owners(&store)?,
        (
            vec![Value::Number(2.0), Value::Number(1.0)],
            vec![Value::Number(2.0), Value::Number(1.0)]
        )
    );
    Ok(())
}

#[tokio::test]
async fn configured_serial_session_owner_has_one_storage_and_output_value() -> AuthResult<()> {
    use crate::user_fields::{
        FieldTransforms, UserFieldConfig, UserFieldReference, UserFieldTransform,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    let input_calls = Arc::new(AtomicUsize::new(0));
    let output_calls = Arc::new(AtomicUsize::new(0));
    let input_count = input_calls.clone();
    let output_count = output_calls.clone();
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(crate::id::IdGeneration::Serial);
    config.session.additional_fields = Some(
        [(
            "userId".into(),
            UserFieldConfig {
                field_name: Some("stored_owner".into()),
                references: Some(UserFieldReference {
                    model: "user".into(),
                    field: "id".into(),
                    ..Default::default()
                }),
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |value| {
                        let _ = input_count.fetch_add(1, Ordering::Relaxed);
                        assert_eq!(value, Value::from("01"));
                        Ok(Value::Number(2.0))
                    })),
                    output: Some(UserFieldTransform::new(move |value| {
                        let _ = output_count.fetch_add(1, Ordering::Relaxed);
                        assert_eq!(value, Value::Number(2.0));
                        Ok(Value::from("1"))
                    })),
                }),
                ..Default::default()
            },
        )]
        .into(),
    );
    let store = EphemeralStore::new(Arc::new(config));
    let created = store.create_session(session("01")).await?;
    assert_eq!(
        (
            input_calls.load(Ordering::Relaxed),
            output_calls.load(Ordering::Relaxed)
        ),
        (1, 1)
    );
    assert_eq!(raw_owners(&store)?, (vec![Value::Number(2.0)], Vec::new()));
    let read = required(store.get_session(created.token.typed().unwrap()).await?)?;
    assert_eq!(
        (
            input_calls.load(Ordering::Relaxed),
            output_calls.load(Ordering::Relaxed)
        ),
        (1, 2)
    );
    let updated = required(
        SessionStore::update_session_with_writer(
            &store,
            created.token.typed().unwrap(),
            SessionUpdate {
                user_id: Some("01".into()),
                additional_fields: [("userId".into(), Value::from("99"))].into(),
                ..Default::default()
            },
            None,
        )
        .await?,
    )?;
    assert_eq!(
        (
            input_calls.load(Ordering::Relaxed),
            output_calls.load(Ordering::Relaxed)
        ),
        (2, 3)
    );
    assert_eq!(raw_owners(&store)?, (vec![Value::Number(2.0)], Vec::new()));
    for projected in [created, read, updated] {
        assert_eq!(projected.user_id, "1");
        assert_eq!(
            serde_json::to_value(&projected)?.get("userId"),
            Some(&serde_json::Value::String("1".into()))
        );
        assert!(!projected.additional_fields.contains_key("userId"));
        assert!(!projected.additional_fields.contains_key("stored_owner"));
    }
    Ok(())
}

#[tokio::test]
async fn preserved_serial_sessions_apply_owner_on_update_once_per_batch() -> AuthResult<()> {
    use crate::user_fields::{UserFieldConfig, UserFieldReference};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let calls = Arc::new(AtomicUsize::new(0));
    let callback_calls = calls.clone();
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(crate::id::IdGeneration::Serial);
    config.session.additional_fields = Some(
        [(
            "userId".into(),
            UserFieldConfig {
                field_name: Some("stored_owner".into()),
                references: Some(UserFieldReference {
                    model: "user".into(),
                    field: "id".into(),
                    ..Default::default()
                }),
                on_update: Some(Arc::new(move || {
                    let _ = callback_calls.fetch_add(1, Ordering::Relaxed);
                    Ok(Value::Number(2.0))
                })),
                ..Default::default()
            },
        )]
        .into(),
    );
    let store = EphemeralStore::new(Arc::new(config));
    for name in ["old-owner", "new-owner"] {
        let _ = store.create_user(user(name)).await?;
    }
    let first = store.create_session(session("1")).await?;
    let second = store.create_session(session("01")).await?;
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert_eq!(
        raw_owners(&store)?,
        (vec![Value::Number(1.0), Value::Number(1.0)], Vec::new())
    );
    assert_eq!(
        store.delete_user_sessions_optional("01", true).await?,
        Some(2)
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(
        raw_owners(&store)?,
        (vec![Value::Number(2.0), Value::Number(2.0)], Vec::new())
    );
    assert!(store.get_user_sessions("1").await?.is_empty());
    let preserved = store.get_user_sessions("2").await?;
    assert_eq!(
        preserved
            .iter()
            .map(|session| session.token.typed().unwrap())
            .collect::<Vec<_>>(),
        [first.token.typed().unwrap(), second.token.typed().unwrap()]
    );
    let now = Utc::now().timestamp_millis() as f64;
    for session in preserved {
        assert_eq!(session.user_id, "2");
        assert!(session.expires_at.date_milliseconds().unwrap() <= now);
    }
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    Ok(())
}

#[tokio::test]
async fn serial_session_creation_defaults_override_core_before_explicit_fields() -> AuthResult<()> {
    use crate::user_fields::{UserFieldConfig, UserFieldReference};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let calls = Arc::new(AtomicUsize::new(0));
    let callback_calls = calls.clone();
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(crate::id::IdGeneration::Serial);
    config.session.additional_fields = Some(
        [(
            "userId".into(),
            UserFieldConfig {
                references: Some(UserFieldReference {
                    model: "user".into(),
                    field: "id".into(),
                    ..Default::default()
                }),
                default_value_fn: Some(Arc::new(move || {
                    let _ = callback_calls.fetch_add(1, Ordering::Relaxed);
                    Ok(Value::from("2"))
                })),
                ..Default::default()
            },
        )]
        .into(),
    );
    let store = EphemeralStore::new(Arc::new(config));
    let defaulted = store.create_session(session("1")).await?;
    assert_eq!(defaulted.user_id, "2");
    assert_eq!(raw_owners(&store)?, (vec![Value::Number(2.0)], Vec::new()));
    assert_eq!(calls.load(Ordering::Relaxed), 1);

    let mut explicit = session("1");
    let _ = explicit
        .additional_fields
        .insert("userId".into(), "3".into());
    let supplied = store.create_session(explicit).await?;
    assert_eq!(supplied.user_id, "3");
    assert_eq!(
        raw_owners(&store)?,
        (vec![Value::Number(2.0), Value::Number(3.0)], Vec::new())
    );
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    Ok(())
}
