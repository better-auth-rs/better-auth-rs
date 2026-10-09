use super::*;
use crate::user_fields::{UserFieldConfig, UserFieldReference, UserFieldType};

fn mapped(column: &str) -> UserFieldConfig {
    UserFieldConfig {
        field_name: Some(column.into()),
        ..Default::default()
    }
}

fn input(token: &str, owner: &str, additional: FieldMap) -> CreateSession {
    let mut fields = FieldMap::from([("token".into(), token.into())]);
    fields.extend(additional);
    CreateSession {
        inherited_fields: FieldMap::new(),
        user_id: owner.into(),
        expires_at: (Utc::now() + chrono::Duration::days(1)).into(),
        ip_address: Some("original-address".into()),
        user_agent: Some("original-agent".into()),
        impersonated_by: None,
        active_organization_id: None,
        additional_fields: fields,
    }
}

fn stored(store: &EphemeralStore) -> AuthResult<FieldMap> {
    store
        .lock()?
        .sessions
        .snapshot()?
        .pop()
        .ok_or_else(|| AuthError::internal("Physical Session fixture row is missing"))
}

#[tokio::test]
async fn replacement_declarations_preserve_raw_strings_and_shared_object_identity() -> AuthResult<()>
{
    let identity = Value::from(FieldMap::from([("value".into(), 7.into())]));
    let output_identity = identity.clone();
    let mut config = (*test_config()).clone();
    for name in ["expiresAt", "createdAt", "updatedAt"] {
        let _ = config
            .session
            .fields_mut()
            .insert(name.into(), mapped(&format!("physical_{name}")));
    }
    let _ = config.session.fields_mut().insert(
        "jsonAlias".into(),
        UserFieldConfig {
            field_type: UserFieldType::Json,
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    assert!(value.strict_equals(&output_identity));
                    Ok(value)
                })),
                ..Default::default()
            }),
            ..mapped("shared")
        },
    );
    let _ = config
        .session
        .fields_mut()
        .insert("objectWriter".into(), mapped("shared"));
    let store = EphemeralStore::new(Arc::new(config));
    let fields = FieldMap::from([
        ("expiresAt".into(), "2100-01-02T03:04:05.000Z".into()),
        ("createdAt".into(), "2030-01-02T03:04:05.000Z".into()),
        ("updatedAt".into(), "not-a-date".into()),
        ("objectWriter".into(), identity.clone()),
    ]);
    let created = FieldMap::from(
        store
            .create_session(input("raw", "owner", fields.clone()))
            .await?,
    );
    let physical = stored(&store)?;
    for name in ["expiresAt", "createdAt", "updatedAt"] {
        assert_eq!(created[name], fields[name]);
        assert_eq!(physical[&format!("physical_{name}")], fields[name]);
        assert!(!physical.contains_key(name));
    }
    assert!(physical["shared"].strict_equals(&identity));
    assert!(created["jsonAlias"].strict_equals(&identity));
    assert!(created["objectWriter"].strict_equals(&identity));
    assert!(!physical.contains_key("jsonAlias"));
    assert!(!physical.contains_key("objectWriter"));
    let read = FieldMap::from(
        store
            .get_session("raw")
            .await?
            .ok_or(AuthError::SessionNotFound)?,
    );
    assert!(read["jsonAlias"].strict_equals(&identity));
    assert_eq!(stored(&store)?, physical);
    Ok(())
}

#[tokio::test]
async fn mapped_undefined_and_null_remain_distinct_without_private_storage_fields() -> AuthResult<()>
{
    let mut config = (*test_config()).clone();
    let _ = config.session.fields_mut().insert(
        "ipAddress".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(|_| Ok(Value::Undefined))),
                ..Default::default()
            }),
            ..mapped("address")
        },
    );
    let _ = config
        .session
        .fields_mut()
        .insert("userAgent".into(), mapped("agent"));
    let _ = config
        .session
        .fields_mut()
        .insert("active".into(), UserFieldConfig::default());
    let store = EphemeralStore::new(Arc::new(config));
    let session = store
        .create_session(input(
            "nullish",
            "owner",
            [
                ("userAgent".into(), Value::Null),
                ("active".into(), "extension".into()),
            ]
            .into(),
        ))
        .await?;
    assert!(session.active);
    let output = FieldMap::from(session);
    assert_eq!(output.get("ipAddress"), Some(&Value::Undefined));
    assert_eq!(output.get("userAgent"), Some(&Value::Null));
    assert_eq!(output.get("active"), Some(&Value::from("extension")));
    let physical = stored(&store)?;
    assert!(!physical.contains_key("ipAddress"));
    assert!(!physical.contains_key("address"));
    assert!(!physical.contains_key("userAgent"));
    assert_eq!(physical.get("agent"), Some(&Value::Null));
    assert_eq!(physical.get("active"), Some(&Value::from("extension")));
    Ok(())
}

#[tokio::test]
async fn reconfigured_columns_read_physical_values_without_logical_fallbacks() -> AuthResult<()> {
    let writer = EphemeralStore::new(test_config());
    let _ = writer
        .create_session(input("reconfigure", "owner", FieldMap::new()))
        .await?;
    let before = stored(&writer)?;
    let mut reader = writer.clone();
    let _ = reader
        .session_config
        .fields_mut()
        .insert("ipAddress".into(), mapped("userAgent"));
    let _ = reader
        .session_config
        .fields_mut()
        .insert("original".into(), mapped("ipAddress"));
    let selected = FieldMap::from(
        reader
            .get_session("reconfigure")
            .await?
            .ok_or(AuthError::SessionNotFound)?,
    );
    assert_eq!(selected["ipAddress"], Value::from("original-agent"));
    assert_eq!(selected["original"], Value::from("original-address"));
    assert_eq!(stored(&writer)?, before);
    let changed = reader
        .update_session_fields(
            "reconfigure",
            [("ipAddress".into(), "changed".into())].into(),
        )
        .await?
        .ok_or(AuthError::SessionNotFound)?;
    assert_eq!(changed.ip_address.field_value(), "changed".into());
    let physical = stored(&writer)?;
    assert_eq!(physical["ipAddress"], Value::from("original-address"));
    assert_eq!(physical["userAgent"], Value::from("changed"));
    assert!(!physical.contains_key("original"));

    let _ = reader
        .session_config
        .fields_mut()
        .insert("userId".into(), mapped("absentOwner"));
    assert!(reader.get_user_sessions("owner").await?.is_empty());
    let selected = FieldMap::from(
        reader
            .get_session("reconfigure")
            .await?
            .ok_or(AuthError::SessionNotFound)?,
    );
    assert_eq!(selected.get("userId"), Some(&Value::Undefined));
    let _ = reader
        .session_config
        .fields_mut()
        .insert("token".into(), mapped("absentToken"));
    assert!(reader.get_session("reconfigure").await?.is_none());
    reader.delete_sessions(&["reconfigure".into()]).await?;
    assert_eq!(stored(&writer)?, physical);
    Ok(())
}

#[tokio::test]
async fn mapped_session_selectors_and_expiry_work_for_both_join_paths() -> AuthResult<()> {
    for native in [false, true] {
        let mut config = (*test_config()).clone();
        config.advanced.database.joins = Some(native);
        let _ = config
            .session
            .fields_mut()
            .insert("token".into(), mapped("credential"));
        let _ = config.session.fields_mut().insert(
            "userId".into(),
            UserFieldConfig {
                references: Some(UserFieldReference {
                    model: "user".into(),
                    field: "id".into(),
                    ..Default::default()
                }),
                ..mapped("owner")
            },
        );
        let _ = config
            .session
            .fields_mut()
            .insert("updatedAt".into(), UserFieldConfig::default());
        let _ = config.session.fields_mut().insert(
            "expiresAt".into(),
            UserFieldConfig {
                field_type: UserFieldType::Date,
                ..mapped("deadline")
            },
        );
        let store = EphemeralStore::new(Arc::new(config));
        let user = store
            .create_user(CreateUser {
                email: Some("physical-session@example.com".into()),
                ..Default::default()
            })
            .await?;
        let owner = user.id.typed()?;
        let _ = store
            .create_session(input(
                "mapped",
                owner,
                [("updatedAt".into(), "preserved-marker".into())].into(),
            ))
            .await?;
        let physical = stored(&store)?;
        for logical in ["token", "userId", "expiresAt", "active"] {
            assert!(!physical.contains_key(logical));
        }
        assert_eq!(physical["credential"], Value::from("mapped"));
        assert_eq!(physical["owner"], Value::from(owner.as_str()));
        let (_, joined) = store
            .get_session_snapshot("mapped")
            .await?
            .ok_or(AuthError::SessionNotFound)?;
        let joined = joined
            .ok_or(AuthError::UserNotFound)?
            .into_typed()?
            .ok_or(AuthError::UserNotFound)?;
        assert_eq!(joined.user.id, user.id);
        assert_eq!(joined.session.token, "mapped");
        assert_eq!(
            store
                .get_user_session_snapshots_value(&owner.as_str().into(), true)
                .await?
                .len(),
            1
        );
        store.end_sessions(&["mapped".into()]).await?;
        assert_eq!(
            stored(&store)?["updatedAt"],
            Value::from("preserved-marker")
        );
        assert!(
            store
                .get_user_session_snapshots_value(&owner.as_str().into(), true)
                .await?
                .is_empty()
        );
        assert!(
            store
                .get_session_snapshots(&["mapped".into()], true)
                .await?
                .is_empty()
        );
        assert_eq!(store.delete_expired_sessions().await?, 1);
        assert_eq!(store.lock()?.sessions.len(), 0);
        let _ = store
            .create_session(input("delete", owner, FieldMap::new()))
            .await?;
        store.delete_user_sessions(owner).await?;
        assert_eq!(store.lock()?.sessions.len(), 0);
    }
    Ok(())
}

#[tokio::test]
async fn plugin_named_physical_columns_do_not_add_undeclared_output_fields() -> AuthResult<()> {
    for column in ["impersonatedBy", "activeOrganizationId", "activeTeamId"] {
        let mut config = (*test_config()).clone();
        let _ = config
            .session
            .fields_mut()
            .insert("alias".into(), mapped(column));
        let store = EphemeralStore::new(Arc::new(config));
        let session = store
            .create_session(input(
                "alias",
                "owner",
                [("alias".into(), "stored-value".into())].into(),
            ))
            .await?;
        let output = FieldMap::from(session);
        assert_eq!(output["alias"], Value::from("stored-value"));
        assert!(!output.contains_key(column));
        let physical = stored(&store)?;
        assert_eq!(physical[column], Value::from("stored-value"));
        assert!(!physical.contains_key("alias"));
        let output = FieldMap::from(
            store
                .get_session("alias")
                .await?
                .ok_or(AuthError::SessionNotFound)?,
        );
        assert!(!output.contains_key(column));
        assert_eq!(stored(&store)?, physical);
    }
    Ok(())
}

#[tokio::test]
async fn mapped_session_transactions_commit_and_rollback_physical_rows() -> AuthResult<()> {
    let mut config = (*test_config()).clone();
    let _ = config
        .session
        .fields_mut()
        .insert("ipAddress".into(), mapped("address"));
    let store = EphemeralStore::new(Arc::new(config));
    let _ = store
        .create_session(input("transaction", "owner", FieldMap::new()))
        .await?;
    let before = stored(&store)?;
    let (_base, discarded, _pending) = store.begin_adapter_transaction()?;
    let _ = discarded
        .update_session_fields(
            "transaction",
            [("ipAddress".into(), "discarded".into())].into(),
        )
        .await?;
    assert_eq!(stored(&discarded)?["address"], Value::from("discarded"));
    drop(discarded);
    assert_eq!(stored(&store)?, before);
    let (base, committed, pending) = store.begin_adapter_transaction()?;
    let _ = committed
        .update_session_fields(
            "transaction",
            [("ipAddress".into(), "committed".into())].into(),
        )
        .await?;
    store.commit_transaction(base, committed, pending).await?;
    let physical = stored(&store)?;
    assert_eq!(physical["address"], Value::from("committed"));
    assert_eq!(physical["token"], before["token"]);
    assert!(!physical.contains_key("ipAddress"));
    Ok(())
}

#[tokio::test]
async fn batch_token_queries_convert_the_array_once_before_matching() -> AuthResult<()> {
    let mut config = (*test_config()).clone();
    let _ = config.session.fields_mut().insert(
        "token".into(),
        UserFieldConfig {
            field_type: UserFieldType::Number,
            ..mapped("credential")
        },
    );
    let store = EphemeralStore::new(Arc::new(config));
    let _ = store
        .create_session(input(
            "ignored",
            "owner",
            [("token".into(), 7.into())].into(),
        ))
        .await?;
    let before = stored(&store)?;
    assert!(store.get_session("7").await?.is_some());
    let mixed = ["7".into(), "not-a-number".into()];
    assert!(store.get_session_snapshots(&mixed, false).await?.is_empty());
    store.end_sessions(&mixed).await?;
    store.delete_sessions(&mixed).await?;
    assert_eq!(stored(&store)?, before);
    assert_eq!(
        store
            .get_session_snapshots(&["7".into()], false)
            .await?
            .len(),
        1
    );
    store.delete_sessions(&["7".into()]).await?;
    assert_eq!(store.lock()?.sessions.len(), 0);
    Ok(())
}

#[tokio::test]
async fn json_batch_token_conversion_is_validated_only_when_a_row_is_evaluated() -> AuthResult<()> {
    let mut config = (*test_config()).clone();
    let _ = config.session.fields_mut().insert(
        "token".into(),
        UserFieldConfig {
            field_type: UserFieldType::Json,
            ..mapped("credential")
        },
    );
    let store = EphemeralStore::new(Arc::new(config));
    assert!(store.get_session_snapshots(&[], false).await?.is_empty());
    store.delete_sessions(&[]).await?;
    let _ = store
        .create_session(input(
            "ignored",
            "owner",
            [(
                "token".into(),
                FieldMap::from([("key".into(), 1.into())]).into(),
            )]
            .into(),
        ))
        .await?;
    let before = stored(&store)?;
    assert!(
        matches!(store.get_session_snapshots(&[], false).await, Err(AuthError::Internal(message)) if message == "Value must be an array")
    );
    assert!(
        matches!(store.delete_sessions(&[]).await, Err(AuthError::Internal(message)) if message == "Value must be an array")
    );
    assert_eq!(stored(&store)?, before);
    Ok(())
}
