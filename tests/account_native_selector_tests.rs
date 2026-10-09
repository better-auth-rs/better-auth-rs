#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Fixture setup and hook observations must fail immediately on unexpected errors"
)]

use std::sync::{Arc, Mutex};

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthStore, CreateAccount, CreateUser,
    FieldValue, Utf16String,
    id::IdGeneration,
    store::{
        AccountStore, EphemeralStore, MemoryCacheAdapter,
        database_hooks::{DatabaseHookContext, DatabaseHookControl, DatabaseHooks},
        secondary::SecondaryStore,
    },
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType},
    wire::AccountView,
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::Database,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};

type Events = Arc<Mutex<Vec<String>>>;

struct ObserveDelete(Events);

#[better_auth::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for ObserveDelete {
    async fn before_delete_account(
        &self,
        account: &AccountView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        let subject = account.account_id.typed()?;
        self.0.lock().unwrap().push(format!("before:{subject}"));
        Ok(if subject == "cancelled" {
            DatabaseHookControl::Cancel
        } else {
            DatabaseHookControl::Continue
        })
    }

    async fn after_delete_account(
        &self,
        account: &AccountView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        let subject = account.account_id.typed()?;
        self.0.lock().unwrap().push(format!("after:{subject}"));
        if subject == "failed" {
            return Err(AuthError::internal("account after hook failed"));
        }
        Ok(())
    }
}

async fn check<S: AuthSchema>(
    inner: Arc<dyn AuthStore<S>>,
    mut config: AuthConfig,
    secondary: bool,
) -> AuthResult<()> {
    let owner = inner
        .create_user(
            CreateUser::new()
                .with_email("native-account@example.test")
                .with_name("Native account"),
        )
        .await?;
    for (id, subject) in [("1", "deleted"), ("2", "cancelled"), ("3", "failed")] {
        let created = inner
            .create_account(CreateAccount {
                id: id.into(),
                account_id: subject.into(),
                provider_id: "fixture".into(),
                user_id: owner.id.clone(),
                scope: Some(r#"{"owner":7}"#.to_owned()).into(),
                ..Default::default()
            })
            .await?;
        assert_eq!(created.id, id);
    }
    let _ = config.account.additional_fields.insert(
        "userId".into(),
        UserFieldConfig {
            field_type: UserFieldType::Json,
            field_name: Some("scope".into()),
            ..Default::default()
        },
    );
    let config = Arc::new(config);
    let events = Events::default();
    let inner = inner.with_runtime(
        config.clone(),
        vec![Arc::new(ObserveDelete(events.clone()))],
        Default::default(),
    )?;
    let store: Arc<dyn AuthStore<S>> = if secondary {
        Arc::new(SecondaryStore::new(
            inner,
            Arc::new(MemoryCacheAdapter::new()),
            config,
            Default::default(),
        )?)
    } else {
        inner
    };
    let selector = FieldValue::from_json(serde_json::json!({"owner":7}))?;
    assert_eq!(store.get_user_accounts_value(&selector).await?.len(), 3);
    assert!(
        store
            .get_user_accounts_value(&FieldValue::from_json(serde_json::json!({"owner":8}))?)
            .await?
            .is_empty()
    );
    for (id, fails) in [("1", false), ("2", false), ("3", true)] {
        let selector =
            FieldValue::Utf16String(Utf16String::from_units(id.encode_utf16().collect()));
        let result = store.delete_account_value(&selector).await;
        if fails {
            assert!(
                matches!(result, Err(AuthError::Internal(message)) if message == "account after hook failed")
            );
        } else {
            result?;
        }
    }
    assert_eq!(
        *events.lock().unwrap(),
        [
            "before:deleted",
            "after:deleted",
            "before:cancelled",
            "before:failed",
            "after:failed"
        ]
    );
    let remaining = store.get_user_accounts_value(&selector).await?;
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining.first().unwrap().account_id, "cancelled");
    assert!(store.get_account("fixture", "deleted").await?.is_none());
    assert!(store.get_account("fixture", "failed").await?.is_none());
    Ok(())
}

#[tokio::test]
async fn native_account_selectors_preserve_aliases_and_single_delete_lifecycles() -> AuthResult<()>
{
    for secondary in [false, true] {
        let config = AuthConfig::default();
        check(
            Arc::new(EphemeralStore::new(Arc::new(config.clone()))),
            config.clone(),
            secondary,
        )
        .await?;
        let database = Database::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&database).await.unwrap();
        check(
            Arc::new(SeaOrmStore::<BundledSchema>::new(config.clone(), database)),
            config,
            secondary,
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn serial_account_selectors_convert_native_values_before_matching() -> AuthResult<()> {
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(IdGeneration::Serial);
    let store = EphemeralStore::new(Arc::new(config));
    let created = store
        .create_account(CreateAccount {
            account_id: "native-serial".into(),
            provider_id: "fixture".into(),
            user_id: "001".into(),
            ..Default::default()
        })
        .await?;
    assert_eq!(created.id, "1");
    assert_eq!(store.get_user_accounts_value(&true.into()).await?.len(), 1);
    store.delete_account_value(&true.into()).await?;
    assert!(store.get_user_accounts_value(&1.into()).await?.is_empty());
    Ok(())
}

async fn check_user_batches<S: AuthSchema>(
    inner: Arc<dyn AuthStore<S>>,
    mut config: AuthConfig,
    secondary: bool,
    sqlite: bool,
) -> AuthResult<()> {
    for (id, name) in [("0", "zero"), ("1", "one"), ("2", "failed")] {
        let _ = inner
            .create_user(CreateUser {
                id: Some(id.into()),
                name: Some(name.into()).into(),
                email: Some(format!("{name}@native-batch.test")),
                ..Default::default()
            })
            .await?;
    }
    let events = Events::default();
    let observed = events.clone();
    let _ = config.user.fields_mut().insert(
        "name".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    let name = value.as_str().unwrap();
                    observed.lock().unwrap().push(name.to_owned());
                    if name == "failed" {
                        return Err(AuthError::internal("batch output failed"));
                    }
                    Ok(format!("projected:{name}").into())
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let config = Arc::new(config);
    let inner = inner.with_runtime(config.clone(), vec![], Default::default())?;
    let store: Arc<dyn AuthStore<S>> = if secondary {
        Arc::new(SecondaryStore::new(
            inner,
            Arc::new(MemoryCacheAdapter::new()),
            config,
            Default::default(),
        )?)
    } else {
        inner
    };
    let take = || std::mem::take(&mut *events.lock().unwrap());
    let rows = store
        .list_users_by_id_values(&["1".into(), "0".into(), "1".into()], 10.0)
        .await?;
    let mut ids = rows
        .iter()
        .map(|row| row.id.typed().cloned())
        .collect::<AuthResult<Vec<_>>>()?;
    ids.sort();
    assert_eq!(ids, ["0", "1"]);
    let mut projected = take();
    projected.sort();
    assert_eq!(projected, ["one", "zero"]);

    let rows = store
        .list_users_by_id_values(&["1".into(), "0".into()], 1.0)
        .await?;
    assert_eq!(rows.len(), 1);
    let projected = take();
    assert_eq!(projected.len(), 1);
    assert_eq!(
        rows.first().unwrap().name.typed()?.as_deref(),
        Some(format!("projected:{}", projected.first().unwrap()).as_str())
    );
    for id in [1.into(), true.into(), 0.into(), false.into()] {
        let rows = store.list_users_by_id_values(&[id], 10.0).await?;
        assert_eq!(rows.len(), usize::from(sqlite));
        assert_eq!(take().len(), usize::from(sqlite));
    }
    for ids in [vec![], vec![FieldValue::Null, FieldValue::Undefined]] {
        assert!(store.list_users_by_id_values(&ids, 10.0).await?.is_empty());
        assert!(take().is_empty());
    }
    assert!(
        store
            .list_users_by_id_values(&["2".into()], 0.0)
            .await?
            .is_empty()
    );
    assert!(take().is_empty());
    assert!(matches!(
        store.list_users_by_id_values(&["2".into()], 1.0).await,
        Err(AuthError::Internal(message)) if message == "batch output failed"
    ));
    assert_eq!(take(), ["failed"]);
    Ok(())
}

#[tokio::test]
async fn native_user_batches_keep_adapter_matching_limits_and_output_failures() -> AuthResult<()> {
    for secondary in [false, true] {
        let config = AuthConfig::default();
        check_user_batches(
            Arc::new(EphemeralStore::new(Arc::new(config.clone()))),
            config.clone(),
            secondary,
            false,
        )
        .await?;
        let database = Database::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&database).await.unwrap();
        check_user_batches(
            Arc::new(SeaOrmStore::<BundledSchema>::new(config.clone(), database)),
            config,
            secondary,
            true,
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn account_owner_number_selectors_match_ordinary_reads_with_native_joins() -> AuthResult<()> {
    let store: Arc<dyn AuthStore<better_auth_core::store::StatelessSchema>> =
        Arc::new(EphemeralStore::default());
    let date = better_auth_core::FieldDate::from_milliseconds(1_893_456_000_000.0);
    let _ = store
        .create_user(CreateUser {
            id: Some("selector-owner".into()),
            name: Some("Selector owner".into()).into(),
            email: Some("selector-owner@example.test".into()),
            email_verified: Some(true),
            image: None::<String>.into(),
            created_at: Some(date.clone()),
            updated_at: Some(date.clone()),
            ..Default::default()
        })
        .await?;
    for (id, provider) in [
        ("numeric-provider", FieldValue::from(1)),
        ("string-decoy", FieldValue::from("01")),
    ] {
        let _ = store
            .create_account(CreateAccount {
                id: id.into(),
                account_id: "shared-subject".into(),
                provider_id: better_auth_core::SchemaValue::from_field(provider),
                user_id: "selector-owner".into(),
                access_token: None::<String>.into(),
                refresh_token: None::<String>.into(),
                id_token: None::<String>.into(),
                access_token_expires_at: None::<better_auth_core::FieldDate>.into(),
                refresh_token_expires_at: None::<better_auth_core::FieldDate>.into(),
                scope: None::<String>.into(),
                password: None::<String>.into(),
                created_at: date.clone().into(),
                updated_at: date.clone().into(),
                ..Default::default()
            })
            .await?;
    }
    let before = store
        .get_user_accounts("selector-owner")
        .await?
        .iter()
        .map(AccountView::internal_fields)
        .collect::<AuthResult<Vec<_>>>()?;
    let before_user = store.get_user_by_id("selector-owner").await?;
    assert_eq!(before.len(), 2);
    let expected_account = serde_json::json!({
        "id": "numeric-provider", "accountId": "shared-subject", "providerId": 1,
        "userId": "selector-owner", "accessToken": null, "refreshToken": null,
        "idToken": null, "accessTokenExpiresAt": null, "refreshTokenExpiresAt": null,
        "scope": null, "password": null,
        "createdAt": "2030-01-01T00:00:00.000Z", "updatedAt": "2030-01-01T00:00:00.000Z",
    });
    for joins in [false, true] {
        let events = Events::default();
        let input_events = events.clone();
        let mut config = AuthConfig::default();
        config.advanced.database.joins = Some(joins);
        let _ = config.account.additional_fields.insert(
            "providerId".into(),
            UserFieldConfig {
                field_type: UserFieldType::Number,
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |value| {
                        input_events.lock().unwrap().push("provider-input".into());
                        Ok(value)
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let reader = store.with_runtime(Arc::new(config), vec![], Default::default())?;
        let account = reader
            .get_account("01", "shared-subject")
            .await?
            .ok_or_else(|| {
                AuthError::internal("Number selector must match the numeric provider")
            })?;
        let owner = reader
            .get_account_owner("01", "shared-subject")
            .await?
            .ok_or_else(|| AuthError::internal("Number selector must retain its account owner"))?;
        let better_auth_core::store::JoinValue::One(Some(user)) = owner.user else {
            return Err(AuthError::internal("Number selector must join one owner"));
        };
        assert_eq!(
            serde_json::Value::Object(account.internal_fields()?.json()?),
            expected_account
        );
        assert_eq!(
            serde_json::json!({
                "kind": "owned", "account": owner.account.internal_fields()?.json()?, "user": user,
            }),
            serde_json::json!({
                "kind": "owned", "account": expected_account,
                "user": {
                    "id": "selector-owner", "name": "Selector owner",
                    "email": "selector-owner@example.test", "emailVerified": true, "image": null,
                    "createdAt": "2030-01-01T00:00:00.000Z", "updatedAt": "2030-01-01T00:00:00.000Z",
                },
            }),
            "joins={joins}"
        );
        assert!(events.lock().unwrap().is_empty());
        assert_eq!(
            store
                .get_user_accounts("selector-owner")
                .await?
                .iter()
                .map(AccountView::internal_fields)
                .collect::<AuthResult<Vec<_>>>()?,
            before
        );
        assert_eq!(store.get_user_by_id("selector-owner").await?, before_user);
    }
    Ok(())
}
