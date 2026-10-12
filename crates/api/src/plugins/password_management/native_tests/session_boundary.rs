#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]

use super::*;
use better_auth_core::{
    FieldDate, SchemaValue,
    session::NativeSessionData,
    store::{
        StoreCapabilities,
        database_hooks::{
            DatabaseHookContext, DatabaseHookControl, DatabaseHookUpdate, DatabaseHooks,
        },
    },
    user_fields::{UserFieldFactory, UserFieldType},
    wire::{AccountView, SessionView, UserView},
};

const NOW: f64 = 2_000_000_000_000.0;

struct Hooks {
    state: Arc<State>,
    deletion_error: bool,
    original: FieldValue,
}

#[better_auth_core::database_hooks()]
impl DatabaseHooks<StatelessSchema> for Hooks {
    async fn before_delete_session(
        &self,
        _: &SessionView,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookControl> {
        self.state.events.lock().unwrap().push("delete-before");
        Ok(DatabaseHookControl::Continue)
    }

    async fn after_delete_session(
        &self,
        _: &SessionView,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        self.state.events.lock().unwrap().push("delete-after");
        if self.deletion_error {
            return Err(AuthError::from_thrown(self.original.clone()));
        }
        Ok(())
    }

    async fn before_create_session(
        &self,
        fields: &mut FieldMap,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        assert_eq!(fields.get("userId"), Some(&7.into()));
        self.state.events.lock().unwrap().push("create-cancel");
        Ok(DatabaseHookUpdate::Cancel)
    }
}

fn session(id: &str, owner: FieldValue) -> FieldMap {
    FieldMap::from([
        ("id".into(), id.into()),
        ("token".into(), id.into()),
        ("userId".into(), owner),
        (
            "expiresAt".into(),
            FieldDate::from_milliseconds(NOW + 3_600_000.0).into(),
        ),
        ("createdAt".into(), FieldDate::from_milliseconds(NOW).into()),
        ("updatedAt".into(), FieldDate::from_milliseconds(NOW).into()),
        ("ipAddress".into(), FieldValue::Null),
        ("userAgent".into(), FieldValue::Null),
    ])
}

#[tokio::test]
async fn native_session_owner_reaches_revocation_and_preserves_committed_failure_state()
-> AuthResult<()> {
    for deletion_error in [false, true] {
        let state = Arc::new(State::default());
        *state.projected.lock().unwrap() = native_hash();
        *state.result.lock().unwrap() = true.into();
        let original: FieldValue =
            FieldMap::from([("failure".into(), "after-delete".into())]).into();
        let hooks = Arc::new(Hooks {
            state: state.clone(),
            deletion_error,
            original: original.clone(),
        });
        let mut config = test_helpers::create_test_config().disable_session_refresh(true);
        let _ = config
            .account
            .additional_fields
            .insert("userId".into(), UserFieldConfig::default());
        let _ = config
            .session
            .fields_mut()
            .insert("userId".into(), UserFieldConfig::default());
        let _ = config.account.additional_fields.insert(
            "updatedAt".into(),
            UserFieldConfig {
                field_type: UserFieldType::Date,
                on_update: Some(UserFieldFactory::new(|| {
                    Ok(FieldDate::from_milliseconds(NOW).into())
                })),
                ..Default::default()
            },
        );
        let raw = Arc::new(
            EphemeralStore::from_storage(
                Arc::new(config.clone()),
                [
                    ("user".into(), vec![]),
                    (
                        "account".into(),
                        vec![FieldMap::from([
                            ("id".into(), "credential".into()),
                            ("userId".into(), 7.into()),
                            ("accountId".into(), 7.into()),
                            ("providerId".into(), "credential".into()),
                            ("password".into(), "stored-hash".into()),
                            ("createdAt".into(), FieldDate::from_milliseconds(NOW).into()),
                            ("updatedAt".into(), FieldDate::from_milliseconds(NOW).into()),
                        ])],
                    ),
                    (
                        "session".into(),
                        vec![session("target", 7.into()), session("foreign", "7".into())],
                    ),
                    ("verification".into(), vec![]),
                ],
            )?
            .with_hooks(vec![hooks]),
        );
        let raw_context =
            test_helpers::initialize_test_context(Arc::new(config.clone()), raw.clone(), &[])
                .await?;
        let initial_accounts = raw_context
            .database
            .get_user_accounts_value(&7.into())
            .await?;
        let foreign = raw_context.database.get_session("foreign").await?.unwrap();
        let selected = raw_context.database.get_session("target").await?.unwrap();
        let output_state = state.clone();
        let _ = config.account.additional_fields.insert(
            "password".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    input: None,
                    output: Some(UserFieldTransform::new(move |value| {
                        output_state.events.lock().unwrap().push(
                            if value == "stored-hash".into() {
                                "projection"
                            } else {
                                assert_eq!(value, "new-hash".into());
                                "projection-updated"
                            },
                        );
                        Ok(output_state.projected.lock().unwrap().clone())
                    })),
                }),
                ..Default::default()
            },
        );
        let email = EmailPasswordPlugin::new().password_hasher(state.clone());
        let plugin = PasswordManagementPlugin::new();
        let mut context =
            test_helpers::initialize_test_context(Arc::new(config), raw, &[&email, &plugin])
                .await?;
        context.extensions.insert(StoreCapabilities {
            database: false,
            secondary: false,
        });
        let request = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/change-password",
            None,
            Some(
                json!({"currentPassword":PASSWORD,"newPassword":PASSWORD,"revokeOtherSessions":true}),
            ),
        );
        super::authoritative_session::inject_session(
            &mut context,
            &plugin,
            NativeSessionData::new(
                selected,
                FieldMap::from([
                    ("id".into(), 7.into()),
                    ("name".into(), "Native owner".into()),
                ])
                .into(),
            ),
        );
        let error = test_helpers::native_session::dispatch_plugin(&request, &context, &plugin)
            .await
            .err()
            .unwrap();
        if deletion_error {
            assert!(error.raw_value().unwrap().strict_equals(&original));
        } else {
            assert_eq!(
                error.body_value()?.json()?,
                Some(json!({"code":"FAILED_TO_GET_SESSION","message":"Failed to get session"}))
            );
            assert_eq!(error.status_code()?, 500);
        }
        assert_eq!(
            *state.events.lock().unwrap(),
            if deletion_error {
                vec![
                    "projection",
                    "hash",
                    "verify",
                    "projection-updated",
                    "delete-before",
                    "delete-after",
                ]
            } else {
                vec![
                    "projection",
                    "hash",
                    "verify",
                    "projection-updated",
                    "delete-before",
                    "delete-after",
                    "create-cancel",
                ]
            }
        );
        let mut expected = initial_accounts
            .into_iter()
            .next()
            .unwrap()
            .field_values()?;
        let _ = expected.insert("password".into(), "new-hash".into());
        assert_eq!(
            raw_context
                .database
                .get_user_accounts_value(&7.into())
                .await?
                .into_iter()
                .map(|account| account.field_values())
                .collect::<AuthResult<Vec<_>>>()?,
            vec![expected]
        );
        assert!(raw_context.database.get_session("target").await?.is_none());
        assert_eq!(
            FieldMap::from(raw_context.database.get_session("foreign").await?.unwrap()),
            FieldMap::from(foreign)
        );
        assert!(
            raw_context
                .database
                .get_user_sessions_value(&7.into())
                .await?
                .is_empty()
        );
        assert!(request.new_session()?.is_none());
        assert!(!request.take_response_headers()?.contains_key("Set-Cookie"));
    }
    Ok(())
}

#[test]
fn included_credential_selection_uses_native_identity_instead_of_structural_equality()
-> AuthResult<()> {
    for value in [
        FieldValue::from(FieldMap::from([("id".into(), 7.into())])),
        FieldValue::from(vec![FieldValue::from(7)]),
        FieldValue::from(FieldDate::from_milliseconds(NOW)),
    ] {
        for same in [false, true] {
            let account_id = if same {
                value.clone()
            } else {
                better_auth_core::StructuredCloneContext::new().clone_value(&value)?
            };
            let hash = native_hash();
            let record = better_auth_core::store::UserAccounts {
                user: UserView::try_from(FieldMap::from([("id".into(), value.clone())]))?,
                accounts: better_auth_core::store::JoinValue::Many(vec![AccountView {
                    account_id: SchemaValue::from_field(account_id),
                    provider_id: "credential".into(),
                    password: SchemaValue::from_field(hash.clone()),
                    ..Default::default()
                }]),
            };
            let actual =
                crate::plugins::email_password::credential_password_from_accounts(&record)?;
            assert_eq!(actual.is_some(), same);
            if let Some(actual) = actual {
                assert!(actual.strict_equals(&hash));
            }
        }
    }
    Ok(())
}
