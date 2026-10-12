//! Native parent grouping is exercised through the Account, User, and Session stores.
#![expect(
    clippy::panic_in_result_fn,
    reason = "The regression checks complete selected records, native errors, and persistent rows."
)]

use super::*;
use crate::store::JoinValue;
use crate::user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform};
use crate::{FieldDate, FieldFunction};

mod contract;

const EMAIL: &str = "owner@memory-native-join-grouping.test";
const TABLES: [&str; 3] = ["user", "account", "session"];

fn required<T>(value: Option<T>) -> AuthResult<T> {
    value
        .ok_or_else(|| AuthError::internal("The grouping fixture must contain its selected record"))
}

fn lock<T>(value: &Mutex<T>) -> AuthResult<std::sync::MutexGuard<'_, T>> {
    value
        .lock()
        .map_err(|_| AuthError::internal("The native grouping fixture lock is poisoned"))
}

fn date() -> Value {
    FieldDate::from_milliseconds(1_893_553_445_000.0).into()
}

fn user(id: Value, name: &str) -> FieldMap {
    FieldMap::from([
        ("id".into(), id),
        ("name".into(), name.into()),
        ("email".into(), EMAIL.into()),
        ("emailVerified".into(), true.into()),
        ("image".into(), Value::Null),
        ("createdAt".into(), date()),
        ("updatedAt".into(), date()),
    ])
}

fn account(id: Value, owner: &str, token: &str) -> FieldMap {
    FieldMap::from([
        ("id".into(), id),
        ("accountId".into(), "external-owner".into()),
        ("providerId".into(), "provider".into()),
        ("userId".into(), owner.into()),
        ("accessToken".into(), token.into()),
        ("refreshToken".into(), Value::Null),
        ("idToken".into(), Value::Null),
        ("accessTokenExpiresAt".into(), Value::Null),
        ("refreshTokenExpiresAt".into(), Value::Null),
        ("scope".into(), Value::Null),
        ("password".into(), Value::Null),
        ("createdAt".into(), date()),
        ("updatedAt".into(), date()),
    ])
}

fn session(id: Value, owner: &str, agent: &str) -> FieldMap {
    FieldMap::from([
        ("id".into(), id),
        ("token".into(), "shared-token".into()),
        ("userId".into(), owner.into()),
        (
            "expiresAt".into(),
            FieldDate::from_milliseconds(4_071_006_245_000.0).into(),
        ),
        ("createdAt".into(), date()),
        ("updatedAt".into(), date()),
        ("ipAddress".into(), Value::Null),
        ("userAgent".into(), agent.into()),
    ])
}

fn config() -> AuthConfig {
    let mut config = AuthConfig::default();
    config.advanced.database.joins = Some(true);
    config.advanced.database.default_find_many_limit = Some(1.0);
    config
}

fn seed(store: &EphemeralStore, model: &str, rows: &[FieldMap]) -> AuthResult<()> {
    store.operation(|op| {
        let state = op.capture_state()?;
        let table = state.table(model)?;
        for row in rows {
            let _ = table.push(row.clone())?;
        }
        Ok(())
    })
}

fn stored(store: &EphemeralStore) -> AuthResult<Vec<Vec<FieldMap>>> {
    store.operation(|op| {
        let state = op.capture_state()?;
        TABLES
            .iter()
            .map(|model| state.table(model)?.snapshot())
            .collect()
    })
}

fn one_user(value: JoinValue<UserView>) -> AuthResult<UserView> {
    match value {
        JoinValue::One(Some(user)) => Ok(user),
        _ => Err(AuthError::internal(
            "The native grouping fixture must select one User",
        )),
    }
}

#[tokio::test]
async fn native_account_and_session_owners_use_last_duplicate_relationship() -> AuthResult<()> {
    for ids in [
        [Value::from("shared"), Value::from("shared")],
        [Value::from(1), Value::from("1")],
    ] {
        let store = EphemeralStore::new(Arc::new(config()));
        let users = [
            user("user-a".into(), "User 0"),
            user("user-b".into(), "User 1"),
        ];
        let accounts = [
            account(ids[0].clone(), "user-a", "parent-0"),
            account(ids[1].clone(), "user-b", "parent-1"),
        ];
        let sessions = [
            session(ids[0].clone(), "user-a", "parent-0"),
            session(ids[1].clone(), "user-b", "parent-1"),
        ];
        seed(&store, "user", &users)?;
        seed(&store, "account", &accounts)?;
        seed(&store, "session", &sessions)?;
        let before = stored(&store)?;

        let owner = required(
            store
                .get_account_owner("provider", "external-owner")
                .await?,
        )?;
        let mut expected = accounts[0].clone();
        let _ = expected.insert("id".into(), ids[0].display_utf16()?.into());
        assert_eq!(owner.account.internal_fields()?, expected);
        assert_eq!(one_user(owner.user)?.field_values()?, users[1]);

        let (selected, data) = required(store.get_session_snapshot("shared-token").await?)?;
        let mut expected = sessions[0].clone();
        let _ = expected.insert("id".into(), ids[0].display_utf16()?.into());
        assert_eq!(FieldMap::from(selected), expected);
        let data = required(data)?;
        assert_eq!(FieldMap::from(data.session), expected);
        assert_eq!(one_user(data.user)?.field_values()?, users[1]);
        assert_eq!(stored(&store)?, before);
    }
    Ok(())
}

#[tokio::test]
async fn native_user_accounts_accumulate_each_duplicate_parents_child_limit() -> AuthResult<()> {
    let store = EphemeralStore::new(Arc::new(config()));
    let users = [
        user("user-a".into(), "User 0"),
        user("user-a".into(), "User 1"),
    ];
    let accounts = [
        account("account-a".into(), "user-a", "parent-0"),
        account("account-a".into(), "user-a", "parent-1"),
        account("account-b".into(), "user-a", "parent-2"),
    ];
    seed(&store, "user", &users)?;
    seed(&store, "account", &accounts)?;
    let before = stored(&store)?;
    let selected = required(store.get_user_with_accounts(EMAIL).await?)?;
    assert_eq!(selected.user.field_values()?, users[0]);
    let children = selected.accounts.into_required_page("accounts")?;
    assert_eq!(
        children
            .iter()
            .map(AccountView::internal_fields)
            .collect::<AuthResult<Vec<_>>>()?,
        [accounts[0].clone(), accounts[2].clone()]
    );
    assert_eq!(stored(&store)?, before);
    Ok(())
}

#[tokio::test]
async fn native_session_pagination_follows_complete_parent_grouping() -> AuthResult<()> {
    let store = EphemeralStore::new(Arc::new(config()));
    let users = [
        user("user-a".into(), "User 0"),
        user("user-b".into(), "User 1"),
        user("user-c".into(), "User 2"),
    ];
    let sessions = [
        session("shared".into(), "user-a", "parent-0"),
        session("other".into(), "user-c", "parent-1"),
        session("shared".into(), "user-b", "parent-2"),
    ];
    seed(&store, "user", &users)?;
    seed(&store, "session", &sessions)?;
    let before = stored(&store)?;
    let one = required(store.get_session_snapshot("shared-token").await?)?;
    let many = store
        .get_session_snapshots(&["shared-token".into()], false)
        .await?;
    assert_eq!(many.len(), 1);
    for (parent, data) in std::iter::once(one).chain(many) {
        assert_eq!(FieldMap::from(parent), sessions[0]);
        let data = required(data)?;
        assert_eq!(FieldMap::from(data.session), sessions[0]);
        assert_eq!(one_user(data.user)?.field_values()?, users[1]);
    }
    assert_eq!(stored(&store)?, before);
    Ok(())
}

#[tokio::test]
async fn native_grouping_retains_first_parent_snapshot_and_live_child() -> AuthResult<()> {
    let store = EphemeralStore::new(Arc::new(config()));
    let users = [
        user("user-a".into(), "User 0"),
        user("user-b".into(), "User 1"),
    ];
    let first = account("shared".into(), "user-a", "parent-0");
    seed(&store, "user", &users)?;
    seed(&store, "account", std::slice::from_ref(&first))?;
    let (parent, child) = store.operation(|op| {
        let state = op.capture_state()?;
        Ok((
            required(state.table("account")?.row_at(0)?)?,
            required(state.table("user")?.row_at(1)?)?,
        ))
    })?;
    let calls = Arc::new(Mutex::new(0));
    let observed = calls.clone();
    let id: Value = FieldMap::from([(
        "toString".into(),
        FieldFunction::contextual(move |_, _| {
            *lock(&observed)? += 1;
            parent.set_field("accessToken".into(), "parent-0-after".into())?;
            child.set_field("name".into(), "Live User".into())?;
            Ok("shared".into())
        })
        .into(),
    )])
    .into();
    let second = account(id, "user-b", "parent-1");
    seed(&store, "account", &[second])?;
    let mut expected_storage = stored(&store)?;
    let selected = required(
        store
            .get_account_owner("provider", "external-owner")
            .await?,
    )?;
    assert_eq!(*lock(&calls)?, 1);
    assert_eq!(selected.account.internal_fields()?, first);
    let mut expected_user = users[1].clone();
    let _ = expected_user.insert("name".into(), "Live User".into());
    assert_eq!(one_user(selected.user)?.field_values()?, expected_user);
    let _ = required(required(expected_storage.get_mut(0))?.get_mut(1))?
        .insert("name".into(), "Live User".into());
    let _ = required(required(expected_storage.get_mut(1))?.get_mut(0))?
        .insert("accessToken".into(), "parent-0-after".into());
    assert_eq!(stored(&store)?, expected_storage);
    Ok(())
}

#[tokio::test]
async fn native_grouping_reads_late_ids_before_limits_and_preserves_original_errors()
-> AuthResult<()> {
    for model in TABLES {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut config = config();
        let observed = events.clone();
        let field = UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    lock(&observed)?.push("output");
                    Ok(value)
                })),
                ..Default::default()
            }),
            ..Default::default()
        };
        let _ = config
            .user
            .fields_mut()
            .insert("name".into(), field.clone());
        let _ = config
            .account
            .additional_fields
            .insert("accessToken".into(), field.clone());
        let _ = config
            .session
            .fields_mut()
            .insert("userAgent".into(), field);
        let store = EphemeralStore::new(Arc::new(config));
        let thrown: Value = FieldMap::from([(
            "message".into(),
            "Native parent ID conversion failed".into(),
        )])
        .into();
        let original = thrown.clone();
        let observed = events.clone();
        let id: Value = FieldMap::from([(
            "toString".into(),
            FieldFunction::contextual(move |_, _| {
                lock(&observed)?.push("toString");
                Err(AuthError::from_thrown(original.clone()))
            })
            .into(),
        )])
        .into();
        if model != "user" {
            seed(
                &store,
                "user",
                &[
                    user("user-a".into(), "User 0"),
                    user("user-b".into(), "User 1"),
                ],
            )?;
        }
        let parents = ["first".into(), "second".into(), id]
            .into_iter()
            .map(|id| match model {
                "user" => user(id, "User"),
                "account" => account(id, "user-a", "parent"),
                _ => session(id, "user-a", "parent"),
            })
            .collect::<Vec<_>>();
        seed(&store, model, &parents)?;
        let before = stored(&store)?;
        let result = match model {
            "user" => store.get_user_with_accounts(EMAIL).await.map(|_| ()),
            "account" => store
                .get_account_owner("provider", "external-owner")
                .await
                .map(|_| ()),
            _ => store.get_session_snapshot("shared-token").await.map(|_| ()),
        };
        let error = result
            .err()
            .ok_or_else(|| AuthError::internal("The late parent ID must abort grouping"))?;
        assert!(required(error.raw_value())?.strict_equals(&thrown));
        assert_eq!(*lock(&events)?, ["toString"]);
        assert_eq!(stored(&store)?, before);
    }
    Ok(())
}
