use super::*;
use crate::store::database_hooks::{
    DatabaseHookContext, DatabaseHookControl, DatabaseHookUpdate, DatabaseHooks, SessionUpdate,
    VerificationUpdate,
};
use std::sync::atomic::{AtomicUsize, Ordering};

struct UpdateHooks {
    first: bool,
    observed: Arc<Mutex<Vec<String>>>,
}

#[crate::database_hooks()]
impl DatabaseHooks<StatelessSchema> for UpdateHooks {
    async fn before_update_account(
        &self,
        data: &UpdateAccount,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<UpdateAccount>> {
        self.observed
            .lock()
            .unwrap()
            .push(if data.password.is_undefined() {
                String::new()
            } else {
                data.password.typed()?.clone().unwrap_or_default()
            });
        if data.scope == Some("cancel".to_owned()) {
            return Ok(DatabaseHookUpdate::Cancel);
        }
        Ok(DatabaseHookUpdate::Patch(if self.first {
            UpdateAccount {
                password: (Some("first-patch".into())).into(),
                ..Default::default()
            }
        } else {
            UpdateAccount {
                scope: (Some("second-patch".into())).into(),
                ..Default::default()
            }
        }))
    }
    async fn after_update_account(
        &self,
        row: Option<&AccountView>,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        self.observed.lock().unwrap().push(
            if row.is_some() {
                "after-row"
            } else {
                "after-null"
            }
            .into(),
        );
        Ok(())
    }
}

#[tokio::test]
async fn account_update_hooks_receive_original_input_and_merge_independent_patches() {
    let observed = Arc::new(Mutex::new(Vec::new()));
    let store = EphemeralStore::default().with_hooks(vec![
        Arc::new(UpdateHooks {
            first: true,
            observed: observed.clone(),
        }),
        Arc::new(UpdateHooks {
            first: false,
            observed: observed.clone(),
        }),
    ]);
    let account = store
        .create_account(CreateAccount {
            user_id: "owner".into(),
            account_id: "owner".into(),
            provider_id: "credential".into(),
            access_token: Default::default(),
            refresh_token: Default::default(),
            id_token: Default::default(),
            access_token_expires_at: Default::default(),
            refresh_token_expires_at: Default::default(),
            scope: Default::default(),
            password: Default::default(),
            ..Default::default()
        })
        .await
        .unwrap();
    let updated = store
        .update_account(
            account.id.typed().unwrap(),
            UpdateAccount {
                password: (Some("original".into())).into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        updated.password.typed().unwrap().as_deref(),
        Some("first-patch")
    );
    assert_eq!(
        updated.scope.typed().unwrap().as_deref(),
        Some("second-patch")
    );
    assert_eq!(
        *observed.lock().unwrap(),
        ["original", "original", "after-row", "after-row"]
    );

    observed.lock().unwrap().clear();
    assert!(
        store
            .update_account_optional("missing", UpdateAccount::default())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        *observed.lock().unwrap(),
        ["", "", "after-null", "after-null"]
    );
    observed.lock().unwrap().clear();
    assert!(
        store
            .update_account_optional(
                account.id.typed().unwrap(),
                UpdateAccount {
                    scope: (Some("cancel".into())).into(),
                    ..Default::default()
                }
            )
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(*observed.lock().unwrap(), [""]);
    assert_eq!(
        store
            .get_account("credential", "owner")
            .await
            .unwrap()
            .unwrap(),
        updated
    );
}

#[tokio::test]
async fn native_credential_selectors_bind_all_fields_before_account_projection() -> AuthResult<()> {
    use crate::user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform};

    let events = Arc::new(Mutex::new(Vec::new()));
    let mut config = AuthConfig::default();
    for (name, physical) in [
        ("userId", "storedOwner"),
        ("providerId", "storedProvider"),
        ("accountId", "storedAccount"),
    ] {
        let events = events.clone();
        let _ = config.account.additional_fields.insert(
            name.into(),
            UserFieldConfig {
                field_name: Some(physical.into()),
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |value| {
                        events.lock().unwrap().push((name, value.clone()));
                        Ok(value)
                    })),
                    output: (name == "userId").then(|| UserFieldTransform::new(|_| Ok(99.into()))),
                }),
                ..Default::default()
            },
        );
    }
    let store = EphemeralStore::new(Arc::new(config));
    let mut created = Vec::new();
    for (owner, account_id, provider) in [
        (Value::from(7), Value::from(7), "social"),
        (Value::from(7), Value::from("7"), "credential"),
        (Value::from("7"), Value::from("7"), "credential"),
        (Value::from(7), Value::from(7), "credential"),
    ] {
        created.push(
            store
                .create_account(CreateAccount {
                    user_id: crate::SchemaValue::from_field(owner),
                    account_id: crate::SchemaValue::from_field(account_id),
                    provider_id: provider.into(),
                    ..Default::default()
                })
                .await?,
        );
    }
    events.lock().unwrap().clear();
    let selected = store.get_credential_account_value(&7.into()).await?;
    assert_eq!(selected, created.get(3).cloned());
    assert!(
        events.lock().unwrap().is_empty(),
        "where binding must not call field input transforms"
    );
    assert_eq!(
        store.get_credential_account("7").await?,
        created.get(2).cloned()
    );
    store.delete_user_accounts_value(&7.into()).await?;
    let remaining = store.lock()?.accounts.snapshot()?;
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].get("id"), Some(&created[2].id.field_value()));
    assert_eq!(remaining[0].get("storedOwner"), Some(&"7".into()));
    Ok(())
}

#[tokio::test]
async fn native_account_update_keeps_numeric_ids_and_original_hook_lifecycle() -> AuthResult<()> {
    let observed = Arc::new(Mutex::new(Vec::new()));
    let store = EphemeralStore::default().with_hooks(vec![Arc::new(UpdateHooks {
        first: true,
        observed: observed.clone(),
    })]);
    let created = store
        .create_account(CreateAccount {
            user_id: "owner".into(),
            account_id: "owner".into(),
            provider_id: "credential".into(),
            ..Default::default()
        })
        .await?;
    let _ = store
        .update_account_optional(
            created.id.typed()?,
            UpdateAccount {
                id: crate::SchemaValue::from_field(7.into()),
                ..Default::default()
            },
        )
        .await?;
    observed.lock().unwrap().clear();
    assert!(
        store
            .update_account_by_id_value(&"7".into(), UpdateAccount::default())
            .await?
            .is_none()
    );
    assert_eq!(*observed.lock().unwrap(), ["", "after-null"]);
    observed.lock().unwrap().clear();
    assert!(
        store
            .update_account_by_id_value(
                &7.into(),
                UpdateAccount {
                    scope: Some("cancel".into()).into(),
                    ..Default::default()
                }
            )
            .await?
            .is_none()
    );
    assert_eq!(*observed.lock().unwrap(), [""]);
    observed.lock().unwrap().clear();
    let updated = store
        .update_account_by_id_value(
            &7.into(),
            UpdateAccount {
                password: Some("original".into()).into(),
                ..Default::default()
            },
        )
        .await?
        .ok_or_else(|| AuthError::internal("Expected updated native Account"))?;
    assert_eq!(updated.password.typed()?.as_deref(), Some("first-patch"));
    assert_eq!(*observed.lock().unwrap(), ["original", "after-row"]);
    assert_eq!(store.get_credential_account("owner").await?, Some(updated));
    assert_eq!(
        store.lock()?.accounts.snapshot()?[0].get("id"),
        Some(&7.into())
    );
    Ok(())
}

struct ConsumeHooks {
    before: Arc<AtomicUsize>,
    after: Arc<AtomicUsize>,
}

#[crate::database_hooks()]
impl DatabaseHooks<StatelessSchema> for ConsumeHooks {
    async fn before_delete_verification(
        &self,
        value: &VerificationView,
        context: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookControl> {
        assert_eq!(value.value, "latest");
        assert!(context.transaction.is_some());
        let _ = self.before.fetch_add(1, Ordering::SeqCst);
        tokio::task::yield_now().await;
        Ok(DatabaseHookControl::Continue)
    }
    async fn after_delete_verification(
        &self,
        value: &VerificationView,
        context: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        assert_eq!(value.value, "latest");
        assert!(context.transaction.is_none());
        let _ = self.after.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn concurrent_consume_runs_hooks_once_and_invalidates_older_rows() {
    let before = Arc::new(AtomicUsize::new(0));
    let after = Arc::new(AtomicUsize::new(0));
    let store = EphemeralStore::default().with_hooks(vec![Arc::new(ConsumeHooks {
        before: before.clone(),
        after: after.clone(),
    })]);
    let old = store
        .create_verification(CreateVerification {
            identifier: "once".into(),
            value: "old".into(),
            expires_at: (Utc::now() + chrono::Duration::minutes(1)).into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let _ = store
        .lock()
        .unwrap()
        .verifications
        .find_mut(|row| {
            row.get("id")
                .unwrap_or(&Value::Undefined)
                .strict_equals(&old.id.field_value())
        })
        .unwrap()
        .unwrap()
        .insert(
            "createdAt".into(),
            crate::FieldDate::from_milliseconds(
                old.created_at.typed().unwrap().milliseconds() - 1000.0,
            )
            .into(),
        );
    let _ = store
        .create_verification(CreateVerification {
            identifier: "once".into(),
            value: "latest".into(),
            expires_at: (Utc::now() + chrono::Duration::minutes(1)).into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let (first, second) = tokio::join!(
        store.consume_verification_by_identifier("once"),
        store.consume_verification_by_identifier("once")
    );
    assert_eq!(
        [first.unwrap(), second.unwrap()]
            .into_iter()
            .flatten()
            .count(),
        1
    );
    assert_eq!(before.load(Ordering::SeqCst), 1);
    assert_eq!(after.load(Ordering::SeqCst), 1);
    assert!(
        store
            .get_verification_including_expired("once")
            .await
            .unwrap()
            .is_none()
    );
}

#[derive(Default)]
struct MissingUpdates(Mutex<Vec<&'static str>>);

#[crate::database_hooks()]
impl DatabaseHooks<StatelessSchema> for MissingUpdates {
    async fn after_update_user(
        &self,
        row: Option<&UserView>,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        assert!(row.is_none());
        self.0.lock().unwrap().push("user");
        Ok(())
    }
    async fn before_update_session(
        &self,
        _: &SessionUpdate,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<SessionUpdate>> {
        Ok(DatabaseHookUpdate::Continue)
    }
    async fn after_update_session(
        &self,
        row: Option<&SessionView>,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        assert!(row.is_none());
        self.0.lock().unwrap().push("session");
        Ok(())
    }
    async fn before_update_verification(
        &self,
        _: &VerificationUpdate,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<VerificationUpdate>> {
        Ok(DatabaseHookUpdate::Continue)
    }
    async fn after_update_verification(
        &self,
        row: Option<&VerificationView>,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        assert!(row.is_none());
        self.0.lock().unwrap().push("verification");
        Ok(())
    }
}

#[tokio::test]
async fn missing_update_results_reach_hooks_before_strict_store_errors() {
    let hooks = Arc::new(MissingUpdates::default());
    let store = EphemeralStore::default().with_hooks(vec![hooks.clone()]);
    assert!(matches!(
        store.update_user("missing", UpdateUser::default()).await,
        Err(AuthError::UserNotFound)
    ));
    assert!(
        store
            .update_session_fields("missing", Default::default())
            .await
            .unwrap()
            .is_none()
    );
    store
        .update_verification_by_identifier("missing", Some("value".into()), None)
        .await
        .unwrap();
    assert_eq!(
        *hooks.0.lock().unwrap(),
        ["user", "session", "verification"]
    );
}

#[tokio::test]
async fn optional_runtime_fields_preserve_absence_then_explicit_null() {
    use crate::user_fields::{UserFieldConfig, UserFieldType};

    let mut config = AuthConfig::default();
    for (name, field_type) in [
        ("banReason", UserFieldType::String),
        ("banExpires", UserFieldType::Date),
    ] {
        let _ = config.user.fields_mut().insert(
            name.into(),
            UserFieldConfig {
                field_type,
                required: Some(false),
                ..Default::default()
            },
        );
    }
    for name in ["impersonatedBy", "activeOrganizationId", "activeTeamId"] {
        let _ = config.session.fields_mut().insert(
            name.into(),
            UserFieldConfig {
                required: Some(false),
                ..Default::default()
            },
        );
    }
    let store = EphemeralStore::new(Arc::new(config));
    let user = store.create_user(CreateUser::new()).await.unwrap();
    let raw = serde_json::to_value(&user).unwrap();
    for field in ["image", "banReason", "banExpires"] {
        assert!(raw.get(field).is_none());
    }
    let member = crate::entity::MemberUserView::from_user(&user);
    assert!(
        serde_json::to_value(&member)
            .unwrap()
            .get("image")
            .is_none()
    );
    let decoded: crate::entity::MemberUserView =
        serde_json::from_value(serde_json::to_value(member).unwrap()).unwrap();
    assert!(
        serde_json::to_value(decoded)
            .unwrap()
            .get("image")
            .is_none()
    );

    store
        .update_user(
            user.id.typed().unwrap(),
            UpdateUser {
                image: Some("https://example.test/avatar".into()).into(),
                ban_reason: Some(Some("temporary".into())),
                ban_expires: Some(Some(Utc::now().into())),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    store
        .update_user(
            user.id.typed().unwrap(),
            UpdateUser {
                image: None.into(),
                ban_reason: Some(None),
                ban_expires: Some(None),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let user = store
        .update_user(
            user.id.typed().unwrap(),
            UpdateUser {
                name: Some("renamed".into()).into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let raw = serde_json::to_value(&user).unwrap();
    for field in ["image", "banReason", "banExpires"] {
        assert_eq!(raw.get(field), Some(&serde_json::Value::Null));
    }
    let member = crate::entity::MemberUserView::from_user(&user);
    assert_eq!(
        serde_json::to_value(member).unwrap().get("image"),
        Some(&serde_json::Value::Null)
    );

    let session = store
        .create_session(CreateSession {
            inherited_fields: Default::default(),
            additional_fields: Default::default(),
            user_id: user.id,
            expires_at: (Utc::now() + chrono::Duration::days(1)).into(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await
        .unwrap();
    let raw = serde_json::to_value(SessionView::from(&session)).unwrap();
    for field in ["impersonatedBy", "activeOrganizationId", "activeTeamId"] {
        assert!(raw.get(field).is_none());
    }
    store
        .update_session_with_writer(
            session.token.typed().unwrap(),
            SessionUpdate {
                impersonated_by: Some(Some("administrator".into())),
                active_organization_id: Some(Some("organization".into())),
                active_team_id: Some(Some("team".into())),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap()
        .unwrap();
    store
        .update_session_with_writer(
            session.token.typed().unwrap(),
            SessionUpdate {
                impersonated_by: Some(None),
                active_organization_id: Some(None),
                active_team_id: Some(None),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap()
        .unwrap();
    let session = store
        .get_session(session.token.typed().unwrap())
        .await
        .unwrap()
        .unwrap();
    let raw = serde_json::to_value(SessionView::from(&session)).unwrap();
    for field in ["impersonatedBy", "activeOrganizationId", "activeTeamId"] {
        assert_eq!(raw.get(field), Some(&serde_json::Value::Null));
    }
}

struct VerificationCreateHooks {
    cancel: bool,
    after: Arc<AtomicUsize>,
}

#[crate::database_hooks()]
impl DatabaseHooks<StatelessSchema> for VerificationCreateHooks {
    async fn before_create_verification(
        &self,
        input: &mut CreateVerification,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookControl> {
        assert_eq!(
            input
                .fields()?
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["createdAt", "updatedAt", "identifier", "value", "expiresAt"]
        );
        Ok(if self.cancel {
            DatabaseHookControl::Cancel
        } else {
            DatabaseHookControl::Continue
        })
    }

    async fn after_create_verification(
        &self,
        verification: Option<&VerificationView>,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        assert!(verification.is_some());
        let _ = self.after.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn verification_creation_cancellation_skips_writer_storage_and_after_hooks() -> AuthResult<()>
{
    for cancel in [false, true] {
        let after = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let store = EphemeralStore::default().with_hooks(vec![Arc::new(VerificationCreateHooks {
            cancel,
            after: after.clone(),
        })]);
        let writer_calls = writes.clone();
        let created = store
            .create_verification_with_writer(
                CreateVerification {
                    identifier: "nullable-create".into(),
                    value: "proof".into(),
                    expires_at: (Utc::now() + chrono::Duration::minutes(1)).into(),
                    ..Default::default()
                },
                Some(Box::new(move |fields| {
                    Box::pin(async move {
                        assert_eq!(fields.get("value"), Some(&"proof".into()));
                        let _ = writer_calls.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    })
                })),
            )
            .await?;
        assert_eq!(created.is_none(), cancel);
        assert_eq!(store.lock()?.verifications.len(), usize::from(!cancel));
        assert_eq!(writes.load(Ordering::SeqCst), usize::from(!cancel));
        assert_eq!(after.load(Ordering::SeqCst), usize::from(!cancel));
    }
    Ok(())
}

#[tokio::test]
async fn native_session_updates_transform_values_before_matching_and_projection() -> AuthResult<()>
{
    use crate::user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType};
    let mut config = AuthConfig::default();
    let _ = config.session.fields_mut().insert(
        "token".into(),
        UserFieldConfig {
            field_type: UserFieldType::Number,
            ..Default::default()
        },
    );
    let _ = config.session.fields_mut().insert(
        "activeTeamId".into(),
        UserFieldConfig {
            field_type: UserFieldType::Number,
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(|value| {
                    Ok((crate::query::field_number(&value)? + 1.0).into())
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let store = EphemeralStore::new(Arc::new(config));
    let session = store
        .create_session(CreateSession {
            user_id: "owner".into(),
            expires_at: (Utc::now() + chrono::Duration::hours(1)).into(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            inherited_fields: Default::default(),
            additional_fields: [("token".into(), 7.into())].into(),
        })
        .await?;
    assert_eq!(session.token.field_value(), 7.into());
    let updated = store
        .update_session_active_team_by_token_value(&7.into(), Some(&3.into()))
        .await?;
    assert_eq!(updated.active_team_id.field_value(), 4.into());
    let fetched = store
        .get_session_by_token_value(&7.into())
        .await?
        .ok_or(AuthError::SessionNotFound)?;
    assert_eq!(fetched.active_team_id.field_value(), 4.into());
    assert!(
        store
            .update_session_fields_by_token_value(
                &8.into(),
                [("activeTeamId".into(), 5.into())].into()
            )
            .await?
            .is_none()
    );
    assert_eq!(store.lock()?.sessions.len(), 1);
    Ok(())
}
