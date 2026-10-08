use super::*;
use crate::store::{OrganizationDetailsQuery, OrganizationKey, transaction};

mod create_order;
mod join_projection;
mod session_cleanup;

fn required<T>(value: Option<T>) -> AuthResult<T> {
    value.ok_or_else(|| AuthError::internal("Expected a stored Serial fixture row"))
}

fn serial_store(joins: bool) -> EphemeralStore {
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(crate::id::IdGeneration::Serial);
    config.advanced.database.joins = Some(joins);
    EphemeralStore::new(Arc::new(config))
}

fn user(name: &str) -> CreateUser {
    CreateUser::new()
        .with_name(name)
        .with_email(format!("{name}@serial-user.test"))
}

fn stored_ids(store: &EphemeralStore) -> AuthResult<Vec<Value>> {
    Ok(store
        .lock()?
        .users
        .snapshot()?
        .into_iter()
        .map(|user| user.id.field_value())
        .collect())
}

#[tokio::test]
async fn serial_user_queries_bind_numbers_and_project_strings() -> AuthResult<()> {
    let store = serial_store(false);
    for index in 1..=10 {
        let created = store.create_user(user(&format!("user-{index}"))).await?;
        assert_eq!(created.id, index.to_string());
    }
    assert_eq!(
        stored_ids(&store)?,
        (1..=10)
            .map(|id| Value::Number(f64::from(id)))
            .collect::<Vec<_>>()
    );
    assert_eq!(required(store.get_user_by_id("01").await?)?.id, "1");
    assert_eq!(
        required(store.get_user_by_id_field(&"01".into()).await?)?.id,
        "1"
    );
    assert_eq!(
        required(store.get_user_by_id_value(&Value::Number(1.0)).await?)?.id,
        "1"
    );
    assert!(
        store
            .get_user_by_id_value(&vec![Value::Number(1.0)].into())
            .await?
            .is_none()
    );
    let selected = store
        .list_users_by_ids(&["01".into(), "10".into()], 10.0)
        .await?;
    assert_eq!(
        selected.into_iter().map(|user| user.id).collect::<Vec<_>>(),
        [
            crate::SchemaValue::from("1"),
            crate::SchemaValue::from("10")
        ]
    );
    let (selected, total) = store
        .list_users(ListUsersParams {
            filter_field: Some("id".into()),
            filter_operator: Some("in".into()),
            filter_value: Some(vec![Value::from("02"), Value::Number(10.0)].into()),
            sort_by: Some("id".into()),
            ..Default::default()
        })
        .await?;
    assert_eq!(total, 2);
    assert_eq!(
        selected.into_iter().map(|user| user.id).collect::<Vec<_>>(),
        [
            crate::SchemaValue::from("2"),
            crate::SchemaValue::from("10")
        ]
    );
    let (selected, total) = store
        .list_users(ListUsersParams {
            search_field: Some("_id".into()),
            search_operator: Some("eq".into()),
            search_value: Some("01".into()),
            ..Default::default()
        })
        .await?;
    assert_eq!(total, 1);
    assert_eq!(required(selected.first())?.id, "1");
    let updated = store
        .update_user(
            "01",
            UpdateUser {
                name: Some("changed".into()).into(),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(updated.id, "1");
    assert_eq!(updated.name.typed()?.as_deref(), Some("changed"));
    let deleted = required(store.delete_user_optional("02", false).await?)?;
    assert_eq!(deleted.id, "2");
    assert!(store.get_user_by_id("2").await?.is_none());
    assert_eq!(store.create_user(user("replacement")).await?.id, "10");
    store.delete_user("10").await?;
    assert_eq!(
        required(store.get_user_by_id("10").await?)?
            .email
            .as_deref(),
        Some("replacement@serial-user.test")
    );
    assert!(
        stored_ids(&store)?
            .iter()
            .all(|id| matches!(id, Value::Number(_)))
    );
    Ok(())
}

#[tokio::test]
async fn serial_user_joins_keep_numeric_bindings_in_both_modes() -> AuthResult<()> {
    for joins in [false, true] {
        let store = serial_store(joins);
        let owner = store.create_user(user("owner")).await?;
        let _ = store
            .create_account(CreateAccount {
                user_id: owner.id.clone(),
                provider_id: "fixture".into(),
                account_id: "serial-account".into(),
                ..Default::default()
            })
            .await?;
        let accounts = required(
            store
                .get_user_with_accounts("owner@serial-user.test")
                .await?,
        )?;
        assert_eq!(accounts.user.id, "1");
        let crate::store::JoinValue::Many(accounts) = accounts.accounts else {
            return Err(AuthError::internal(
                "Expected the Account relationship page",
            ));
        };
        assert_eq!(accounts.len(), 1);
        assert_eq!(required(accounts.first())?.user_id, "1");
        let account = required(store.get_account_owner("fixture", "serial-account").await?)?;
        let crate::store::JoinValue::One(user) = account.user else {
            return Err(AuthError::internal("Expected a single Account owner"));
        };
        assert_eq!(required(user)?.id, "1");
        let session = store
            .create_session(CreateSession {
                inherited_fields: Default::default(),
                user_id: owner.id,
                expires_at: (Utc::now() + chrono::Duration::hours(1)).into(),
                additional_fields: Default::default(),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await?;
        let (_, snapshot) = required(store.get_session_snapshot(&session.token).await?)?;
        assert_eq!(required(required(snapshot)?.into_typed()?)?.user.id, "1");
        let snapshots = store
            .get_session_snapshots(std::slice::from_ref(&session.token), true)
            .await?;
        assert_eq!(snapshots.len(), 1);
        assert_eq!(
            required(required(required(snapshots.first())?.1.clone())?.into_typed()?)?
                .user
                .id,
            "1"
        );
        let organization = store
            .create_organization(CreateOrganization::new("Serial", "serial"))
            .await?;
        let member = store
            .create_member(CreateMember::new(
                organization.id.typed()?.clone(),
                "1",
                "member",
            ))
            .await?;
        assert_eq!(
            required(store.get_member_by_id_with_user(member.id.typed()?).await?)?
                .user
                .id,
            "1"
        );
        assert_eq!(
            required(
                store
                    .get_member_with_user(organization.id.typed()?, "01")
                    .await?
            )?
            .user
            .id,
            "1"
        );
        let details = required(
            store
                .get_organization_details(OrganizationDetailsQuery {
                    organization: OrganizationKey::Id(organization.id.typed()?),
                    members_limit: None,
                    users_limit: 10.0,
                    include_teams: false,
                })
                .await?,
        )?;
        assert_eq!(details.members.len(), 1);
        assert_eq!(required(details.members.first())?.user.id, "1");
        assert_eq!(stored_ids(&store)?, [Value::Number(1.0)]);
    }
    Ok(())
}

#[tokio::test]
async fn serial_user_transactions_keep_distinct_rows_and_rollback() -> AuthResult<()> {
    let store = Arc::new(serial_store(false));
    for name in ["first", "second"] {
        let _ = store.create_user(user(name)).await?;
    }
    let live = store.clone();
    transaction(store.as_ref(), move |tx| {
        Box::pin(async move {
            let _ = tx
                .update_user(
                    "1",
                    UpdateUser {
                        name: Some("committed".into()).into(),
                        ..Default::default()
                    },
                )
                .await?;
            let _ = live
                .update_user(
                    "2",
                    UpdateUser {
                        name: Some("concurrent".into()).into(),
                        ..Default::default()
                    },
                )
                .await?;
            assert_eq!(tx.create_user(user("third")).await?.id, "3");
            Ok(())
        })
    })
    .await?;
    assert_eq!(
        required(store.get_user_by_id("1").await?)?
            .name
            .typed()?
            .as_deref(),
        Some("committed")
    );
    assert_eq!(
        required(store.get_user_by_id("2").await?)?
            .name
            .typed()?
            .as_deref(),
        Some("concurrent")
    );
    assert_eq!(
        stored_ids(&store)?,
        [Value::Number(1.0), Value::Number(2.0), Value::Number(3.0)]
    );
    let result: AuthResult<()> = transaction(store.as_ref(), |tx| {
        Box::pin(async move {
            tx.delete_user("1").await?;
            let _ = tx.create_user(user("discarded")).await?;
            Err(AuthError::bad_request("rollback Serial changes"))
        })
    })
    .await;
    assert!(matches!(result, Err(AuthError::BadRequest(_))));
    assert_eq!(
        stored_ids(&store)?,
        [Value::Number(1.0), Value::Number(2.0), Value::Number(3.0)]
    );
    assert!(
        store
            .get_user_by_email("discarded@serial-user.test")
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn non_serial_session_owner_projection_preserves_lone_utf16() -> AuthResult<()> {
    let store = EphemeralStore::default();
    let owner = Value::Utf16String(crate::Utf16String::from_units(vec![0xd800]));
    let session = store
        .create_session(CreateSession {
            inherited_fields: Default::default(),
            user_id: crate::SchemaValue::from_field(owner.clone()),
            expires_at: (Utc::now() + chrono::Duration::hours(1)).into(),
            additional_fields: Default::default(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?;
    assert_eq!(session.user_id.field_value(), owner);
    assert_eq!(
        required(store.get_session(&session.token).await?)?
            .user_id
            .field_value(),
        owner
    );
    Ok(())
}

#[tokio::test]
async fn native_user_update_preserves_undefined_null_and_string_selectors() -> AuthResult<()> {
    let store = EphemeralStore::default();
    for name in ["first", "second", "null", "string"] {
        let _ = store.create_user(user(name)).await?;
    }
    store.lock()?.users.update_each(|user| {
        user.id = crate::SchemaValue::from_field(match user.name.typed()?.as_deref() {
            Some("first" | "second") => Value::Undefined,
            Some("null") => Value::Null,
            _ => Value::from("undefined"),
        });
        Ok(())
    })?;
    for (id, name, expected_names) in [
        (
            Value::Undefined,
            "undefined match",
            ["undefined match", "undefined match", "null", "string"],
        ),
        (
            Value::Null,
            "null match",
            ["null match", "null match", "null match", "string"],
        ),
        (
            Value::from("undefined"),
            "string match",
            ["null match", "null match", "null match", "string match"],
        ),
    ] {
        let updated = required(
            store
                .update_user_by_id_value(
                    &id,
                    UpdateUser {
                        name: Some(name.into()).into(),
                        ..Default::default()
                    },
                )
                .await?,
        )?;
        assert_eq!(
            updated.email.as_deref(),
            Some(if id.is_string() {
                "string@serial-user.test"
            } else {
                "first@serial-user.test"
            })
        );
        let rows = store.lock()?.users.snapshot()?;
        assert_eq!(
            rows.iter()
                .map(|user| user.name.typed().map(|value| value.as_deref()))
                .collect::<AuthResult<Vec<_>>>()?,
            expected_names.map(Some)
        );
        assert_eq!(rows[0].updated_at, rows[1].updated_at);
    }
    Ok(())
}
