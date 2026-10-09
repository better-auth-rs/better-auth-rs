#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "The shared update contract must fail on invalid setup, lost fields, or changed hook observations"
)]

use better_auth_core::{
    AuthConfig, AuthResult, AuthSchema, AuthStore, CreateAccount, CreateSession, CreateUser,
    CreateVerification, FieldDate, FieldMap, FieldValue, UpdateAccount,
    store::{
        EphemeralStore,
        database_hooks::{
            DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks, DatabaseUpdateResult,
            SessionUpdate, VerificationUpdate,
        },
    },
    wire::{AccountView, SessionView, VerificationView},
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::Database,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use std::sync::{Arc, Mutex};

#[path = "account_verification_update_fields_tests/session_secondary.rs"]
mod session_secondary;

#[path = "account_verification_update_fields_tests/server.rs"]
mod server;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Patch {
    Values,
    Empty,
    Continue,
}

#[derive(Clone, Copy, Debug)]
enum Model {
    Account,
    AccountMany,
    Verification,
    Session,
}

impl Model {
    fn keys(self) -> [&'static str; 3] {
        match self {
            Self::Account | Self::AccountMany => ["accessToken", "scope", "accountId"],
            Self::Verification => ["identifier", "value", "expiresAt"],
            Self::Session => ["ipAddress", "userAgent", "token"],
        }
    }

    fn mutation(self, late: bool) -> FieldValue {
        match self {
            Self::Account | Self::AccountMany | Self::Session => {
                if late { "late" } else { "in-place" }.into()
            }
            Self::Verification => FieldValue::Date(date(if late { 3 } else { 2 })),
        }
    }
}

// Keep the shared date within the MySQL TIMESTAMP range.
fn date(offset: u32) -> FieldDate {
    FieldDate::from_milliseconds(1_893_456_000_000.0 + f64::from(offset) * 1_000.0)
}

struct Hooks {
    first: bool,
    model: Model,
    patch: Patch,
    original_date: FieldValue,
    observed: Arc<Mutex<Vec<FieldMap>>>,
    after: Arc<Mutex<Vec<FieldValue>>>,
}

impl Hooks {
    fn before(&self, original: &mut FieldMap) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        let [target, replacement, mutation] = self.model.keys();
        assert!(
            original
                .get("updatedAt")
                .unwrap()
                .strict_equals(&self.original_date)
        );
        self.observed.lock().unwrap().push(original.clone());
        if self.first {
            let _ = original.insert(mutation.into(), self.model.mutation(false));
            Ok(match self.patch {
                Patch::Values => DatabaseHookUpdate::Patch(
                    [
                        (target.into(), FieldValue::Undefined),
                        (replacement.into(), FieldValue::Number(7.0)),
                    ]
                    .into(),
                ),
                Patch::Empty => DatabaseHookUpdate::Patch(FieldMap::new()),
                Patch::Continue => DatabaseHookUpdate::Continue,
            })
        } else {
            assert_eq!(original.get(target), Some(&FieldValue::from("requested")));
            assert_eq!(
                original.get(replacement),
                Some(&FieldValue::from("requested"))
            );
            let _ = original.insert(mutation.into(), self.model.mutation(true));
            let _ = original.insert(target.into(), "late".into());
            let _ = original.insert(replacement.into(), "late".into());
            let _ = original.insert("updatedAt".into(), FieldValue::Date(date(3)));
            Ok(DatabaseHookUpdate::Continue)
        }
    }
}

#[better_auth::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for Hooks {
    async fn before_update_session(
        &self,
        data: &mut FieldMap,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.before(data)
    }
    async fn before_update_account(
        &self,
        data: &mut FieldMap,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.before(data)
    }
    async fn before_update_verification(
        &self,
        data: &mut FieldMap,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.before(data)
    }
    async fn after_update_account(
        &self,
        data: DatabaseUpdateResult<&AccountView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.after.lock().unwrap().push(match data {
            DatabaseUpdateResult::One(row) => row.unwrap().internal_fields()?.into(),
            DatabaseUpdateResult::Many(count) => FieldValue::Number(count as f64),
        });
        Ok(())
    }
    async fn after_update_verification(
        &self,
        data: Option<&VerificationView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.after
            .lock()
            .unwrap()
            .push(data.unwrap().fields()?.into());
        Ok(())
    }
    async fn after_update_session(
        &self,
        data: Option<&SessionView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.after
            .lock()
            .unwrap()
            .push(FieldMap::from(data.unwrap().clone()).into());
        Ok(())
    }
}

async fn check<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    sql: bool,
    model: Model,
    patch: Patch,
) -> AuthResult<()> {
    let owner = raw
        .create_user(
            CreateUser::new()
                .with_name("Owner")
                .with_email("owner@update-fields.test"),
        )
        .await?;
    let original_date = FieldValue::Date(date(1));
    let (id, before) = match model {
        Model::Account | Model::AccountMany => {
            let row = raw
                .create_account(CreateAccount {
                    id: "record".into(),
                    account_id: "original".into(),
                    provider_id: "credential".into(),
                    user_id: owner.id,
                    access_token: Some("stored".into()).into(),
                    scope: Some("stored".into()).into(),
                    created_at: date(0).into(),
                    updated_at: date(0).into(),
                    ..Default::default()
                })
                .await?;
            (row.id.typed()?.clone(), row.internal_fields()?)
        }
        Model::Verification => {
            let row = raw
                .create_verification(CreateVerification {
                    id: "record".into(),
                    identifier: "original".into(),
                    value: "stored".into(),
                    expires_at: date(0).into(),
                    created_at: date(0).into(),
                    updated_at: date(0).into(),
                    ..Default::default()
                })
                .await?;
            (row.id.typed()?.clone(), row.fields()?)
        }
        Model::Session => {
            let row = raw
                .create_session(CreateSession {
                    user_id: owner.id,
                    expires_at: date(100),
                    ip_address: Some("stored".into()),
                    user_agent: Some("stored".into()),
                    inherited_fields: Default::default(),
                    additional_fields: Default::default(),
                    impersonated_by: None,
                    active_organization_id: None,
                })
                .await?;
            (row.token.typed()?.clone(), row.into())
        }
    };
    let observed = Arc::new(Mutex::new(Vec::new()));
    let after = Arc::new(Mutex::new(Vec::new()));
    let hooks = [true, false]
        .into_iter()
        .map(|first| {
            Arc::new(Hooks {
                first,
                model,
                patch,
                original_date: original_date.clone(),
                observed: observed.clone(),
                after: after.clone(),
            }) as Arc<dyn DatabaseHooks<S>>
        })
        .collect();
    let store = raw.with_runtime(Arc::new(AuthConfig::default()), hooks, Default::default())?;
    let result = match model {
        Model::Account | Model::AccountMany => {
            let input = UpdateAccount {
                access_token: Some("requested".into()).into(),
                scope: Some("requested".into()).into(),
                updated_at: better_auth_core::SchemaValue::from_field(original_date.clone()),
                ..Default::default()
            };
            if matches!(model, Model::AccountMany) {
                assert_eq!(
                    store
                        .update_accounts(&[("id".into(), id.as_str().into())].into(), input)
                        .await?,
                    Some(1)
                );
                None
            } else {
                Some(
                    store
                        .update_account_optional(&id, input)
                        .await?
                        .unwrap()
                        .internal_fields()?,
                )
            }
        }
        Model::Verification => Some(
            store
                .update_verification(
                    "original",
                    VerificationUpdate {
                        value: "requested".into(),
                        identifier: "requested".into(),
                        updated_at: better_auth_core::SchemaValue::from_field(original_date),
                        ..Default::default()
                    },
                )
                .await?
                .unwrap()
                .fields()?,
        ),
        Model::Session => Some(
            store
                .update_session_with_writer(
                    &id,
                    SessionUpdate {
                        ip_address: Some(Some("requested".into())),
                        user_agent: Some(Some("requested".into())),
                        updated_at: Some(original_date.as_date().unwrap().clone()),
                        ..Default::default()
                    },
                    None,
                )
                .await?
                .unwrap()
                .into(),
        ),
    };
    let [target, replacement, mutation] = model.keys();
    let mut expected = before;
    let _ = expected.insert(mutation.into(), model.mutation(patch == Patch::Continue));
    let _ = expected.insert(
        "updatedAt".into(),
        FieldValue::Date(date(if patch == Patch::Continue { 3 } else { 1 })),
    );
    match patch {
        Patch::Values => {
            let _ = expected.insert(replacement.into(), if sql { "7".into() } else { 7.into() });
        }
        Patch::Empty | Patch::Continue => {
            let value = if patch == Patch::Empty {
                "requested"
            } else {
                "late"
            };
            let _ = expected.insert(target.into(), value.into());
            let _ = expected.insert(replacement.into(), value.into());
        }
    }
    let stored = match model {
        Model::Account | Model::AccountMany => raw
            .get_account(
                "credential",
                expected.get("accountId").unwrap().as_str().unwrap(),
            )
            .await?
            .unwrap()
            .internal_fields()?,
        Model::Verification => raw
            .get_verification_including_expired(if patch == Patch::Values {
                "original"
            } else if patch == Patch::Empty {
                "requested"
            } else {
                "late"
            })
            .await?
            .unwrap()
            .fields()?,
        Model::Session => raw
            .get_session(expected.get("token").unwrap().as_str().unwrap())
            .await?
            .unwrap()
            .into(),
    };
    assert_eq!(stored, expected, "{model:?} {patch:?} sql={sql}");
    if let Some(result) = result {
        assert_eq!(result, expected);
    }
    let expected_after = if matches!(model, Model::AccountMany) {
        FieldValue::Number(1.0)
    } else {
        expected.into()
    };
    assert_eq!(
        *after.lock().unwrap(),
        vec![expected_after.clone(), expected_after]
    );
    let observations = observed.lock().unwrap();
    let first: FieldMap = [
        (target.into(), "requested".into()),
        (replacement.into(), "requested".into()),
        ("updatedAt".into(), FieldValue::Date(date(1))),
    ]
    .into();
    let mut second = first.clone();
    let _ = second.insert(mutation.into(), model.mutation(false));
    assert_eq!(*observations, vec![first, second]);
    Ok(())
}

#[tokio::test]
async fn native_record_updates_preserve_shallow_hook_fields_and_own_undefined() -> AuthResult<()> {
    for model in [
        Model::Account,
        Model::AccountMany,
        Model::Verification,
        Model::Session,
    ] {
        for patch in [Patch::Values, Patch::Empty, Patch::Continue] {
            check(
                Arc::new(EphemeralStore::new(Arc::new(AuthConfig::default()))),
                false,
                model,
                patch,
            )
            .await?;
            let db = Database::connect("sqlite::memory:").await.unwrap();
            migrator::run_migrations(&db).await.unwrap();
            check(
                Arc::new(SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), db)),
                true,
                model,
                patch,
            )
            .await?;
        }
    }
    Ok(())
}
