#![cfg(feature = "seaorm2")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "The paired contract asserts native records, callback order, and durable writes"
)]

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthStore, CreateAccount, CreateUser, FieldDate,
    FieldMap, FieldValue, SchemaValue, UpdateAccount,
    error::DatabaseError,
    id::{IdGeneration, IdGenerator},
    store::{
        EphemeralStore, StatelessSchema,
        database_hooks::{DatabaseHookContext, DatabaseHooks, DatabaseUpdateResult},
        schema::EntityRole,
    },
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
    wire::AccountView,
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{
        ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement,
    },
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use std::sync::{Arc, Mutex, OnceLock, Weak};

#[path = "account_id_input_tests/create.rs"]
mod create;
#[path = "account_id_input_tests/reentrant.rs"]
mod reentrant;
#[path = "account_id_input_tests/update.rs"]
mod update;

type Events = Arc<Mutex<Vec<FieldValue>>>;

enum Storage {
    Memory(EphemeralStore),
    Sqlite(DatabaseConnection),
}

impl Storage {
    fn is_memory(&self) -> bool {
        matches!(self, Self::Memory(_))
    }

    async fn read(&self) -> AuthResult<Vec<FieldMap>> {
        match self {
            Self::Memory(store) => store.storage_rows(EntityRole::Account),
            Self::Sqlite(database) => database
                .query_all_raw(Statement::from_string(
                    DbBackend::Sqlite,
                    "SELECT * FROM accounts ORDER BY rowid".to_owned(),
                ))
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?
                .into_iter()
                .map(|row| {
                    [
                        ("id", "id"),
                        ("accountId", "account_id"),
                        ("providerId", "provider_id"),
                        ("userId", "user_id"),
                        ("accessToken", "access_token"),
                        ("refreshToken", "refresh_token"),
                        ("idToken", "id_token"),
                        ("accessTokenExpiresAt", "access_token_expires_at"),
                        ("refreshTokenExpiresAt", "refresh_token_expires_at"),
                        ("scope", "scope"),
                        ("password", "password"),
                        ("createdAt", "created_at"),
                        ("updatedAt", "updated_at"),
                    ]
                    .into_iter()
                    .map(|(name, column)| {
                        let value = row
                            .try_get::<Option<String>>("", column)
                            .map_err(|error| AuthError::internal(error.to_string()))?;
                        Ok((
                            name.into(),
                            value.map_or(FieldValue::Null, FieldValue::from),
                        ))
                    })
                    .collect()
                })
                .collect(),
        }
    }

    fn expected(&self, mut fields: FieldMap) -> AuthResult<FieldMap> {
        if !self.is_memory() {
            for name in [
                "accessTokenExpiresAt",
                "refreshTokenExpiresAt",
                "createdAt",
                "updatedAt",
            ] {
                let date = fields
                    .get(name)
                    .and_then(FieldValue::as_date)
                    .ok_or_else(|| AuthError::internal(format!("Expected Account date {name}")))?;
                let value = date
                    .to_datetime()?
                    .ok_or_else(|| AuthError::internal("Expected valid date"))?
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                let _ = fields.insert(name.into(), value.into());
            }
            if let Some(FieldValue::Number(value)) = fields.get("id") {
                let value = value.to_string();
                let _ = fields.insert("id".into(), value.into());
            }
        }
        Ok(fields)
    }
}

fn date(offset: u32) -> FieldDate {
    FieldDate::from_milliseconds(1_893_456_000_000.0 + f64::from(offset) * 1_000.0)
}

fn input(id: FieldValue, account_id: &str, token: &str) -> CreateAccount {
    CreateAccount {
        id: SchemaValue::from_field(id),
        account_id: account_id.into(),
        provider_id: "provider".into(),
        user_id: "owner".into(),
        access_token: Some(token.to_owned()).into(),
        refresh_token: Some("refresh".into()).into(),
        id_token: Some("id-token".into()).into(),
        access_token_expires_at: Some(date(10)).into(),
        refresh_token_expires_at: Some(date(20)).into(),
        scope: Some("read".into()).into(),
        password: Some("password".into()).into(),
        created_at: date(0).into(),
        updated_at: date(0).into(),
        ..Default::default()
    }
}

fn target(id: FieldValue) -> AuthResult<FieldMap> {
    input(id, "subject", "before").fields()
}

fn retained() -> CreateAccount {
    input("retained".into(), "retained-subject", "retained")
}

fn trace(name: &str, value: FieldValue) -> FieldValue {
    vec![name.into(), value].into()
}

fn event(events: &Events, name: &str, value: FieldValue) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Account ID trace lock poisoned"))?
        .push(trace(name, value));
    Ok(())
}

fn observed(events: &Events) -> AuthResult<Vec<FieldValue>> {
    Ok(events
        .lock()
        .map_err(|_| AuthError::internal("Account ID trace lock poisoned"))?
        .clone())
}

fn visible(row: Option<&AccountView>) -> AuthResult<FieldValue> {
    row.map_or(Ok(FieldValue::Null), |row| {
        row.internal_fields().map(Into::into)
    })
}

struct Hooks(Events);

#[better_auth::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for Hooks {
    async fn after_create_account(
        &self,
        row: Option<&AccountView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        event(&self.0, "after-create", visible(row)?)
    }

    async fn after_update_account(
        &self,
        result: DatabaseUpdateResult<&AccountView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        let value = match result {
            DatabaseUpdateResult::One(row) => visible(row)?,
            DatabaseUpdateResult::Many(count) => {
                assert_eq!(count, 1);
                FieldValue::Number(1.0)
            }
        };
        event(&self.0, "after-update", value)
    }
}

fn reader<S: AuthSchema>(
    base: &dyn AuthStore<S>,
    config: AuthConfig,
    events: &Events,
) -> AuthResult<Arc<dyn AuthStore<S>>> {
    base.with_runtime(
        Arc::new(config),
        vec![Arc::new(Hooks(events.clone()))],
        Default::default(),
    )
}

fn id_sentinel() -> UserFieldConfig {
    UserFieldConfig {
        field_name: Some("ignored_id".into()),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(|_| {
                Err(AuthError::type_error(
                    "application ID input must be replaced",
                ))
            })),
            output: Some(UserFieldTransform::new(|_| {
                Err(AuthError::type_error(
                    "application ID output must be replaced",
                ))
            })),
        }),
        ..Default::default()
    }
}

fn generator(events: &Events, reject: bool) -> IdGeneration {
    let events = events.clone();
    IdGeneration::Custom(IdGenerator::new(move |context| {
        event(&events, "generate", context.model.into())?;
        if reject {
            return Err(AuthError::type_error("account-id-generator-rejected"));
        }
        Ok(Some("generated".into()))
    }))
}

fn assert_created(
    result: AuthResult<Option<AccountView>>,
    expected: Option<&FieldMap>,
) -> AuthResult<()> {
    if let Some(expected) = expected {
        let actual = result?.ok_or_else(|| AuthError::internal("Expected created Account"))?;
        assert_eq!(actual.internal_fields()?, *expected);
    } else {
        let Err(AuthError::Database(DatabaseError::Query(message))) = result else {
            return Err(AuthError::internal(format!(
                "Expected SQLite missing-ID error: {result:?}"
            )));
        };
        assert_eq!(
            message,
            "Query Error: error returned from database: (code: 1299) NOT NULL constraint failed: accounts.id"
        );
    }
    Ok(())
}

async fn seed<S: AuthSchema>(base: &dyn AuthStore<S>) -> AuthResult<()> {
    let _ = base
        .create_user(CreateUser {
            id: Some("owner".into()),
            ..CreateUser::new()
                .with_email("owner@account-id-input.test")
                .with_name("Owner")
        })
        .await?;
    let _ = base.create_account(retained()).await?;
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum Case {
    Slot(create::Slot, create::Mode),
    Native(create::Native),
    Update(update::Id, bool),
    Reentrant(reentrant::Read, bool),
}

fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for slot in [
        create::Slot::Implicit,
        create::Slot::BeforeAlias,
        create::Slot::AfterAlias,
    ] {
        for mode in [
            create::Mode::Generated,
            create::Mode::Supplied,
            create::Mode::GeneratorError,
            create::Mode::FieldError,
        ] {
            cases.push(Case::Slot(slot, mode));
        }
    }
    cases.extend(
        [
            create::Native::Seven,
            create::Native::False,
            create::Native::Zero,
        ]
        .map(Case::Native),
    );
    for id in [
        update::Id::False,
        update::Id::Zero,
        update::Id::Empty,
        update::Id::Serial,
    ] {
        for many in [false, true] {
            cases.push(Case::Update(id, many));
        }
    }
    for read in [reentrant::Read::Found, reentrant::Read::Missing] {
        for id_first in [false, true] {
            cases.push(Case::Reentrant(read, id_first));
        }
    }
    assert_eq!(cases.len(), 27);
    cases
}

async fn check<S: AuthSchema>(
    base: Arc<dyn AuthStore<S>>,
    storage: Storage,
    case: Case,
) -> AuthResult<()> {
    seed(base.as_ref()).await?;
    match case {
        Case::Slot(slot, mode) => create::slot(base, storage, slot, mode).await,
        Case::Native(id) => create::native(base, storage, id).await,
        Case::Update(id, many) => update::check(base, storage, id, many).await,
        Case::Reentrant(read, id_first) => reentrant::check(base, storage, read, id_first).await,
    }
    .map_err(|error| AuthError::internal(format!("{case:?}: {error}")))
}

#[tokio::test]
async fn memory_account_id_inputs_preserve_schema_slots_native_values_and_reentrant_policies()
-> AuthResult<()> {
    for case in cases() {
        let store = EphemeralStore::new(Arc::new(AuthConfig::default()));
        let base: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(store.clone());
        check(base, Storage::Memory(store), case).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_account_id_inputs_preserve_schema_slots_native_values_and_reentrant_policies()
-> AuthResult<()> {
    for case in cases() {
        let mut options = ConnectOptions::new("sqlite::memory:");
        let _ = options.max_connections(1);
        let database = Database::connect(options)
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        migrator::run_migrations(&database)
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let base = Arc::new(SeaOrmStore::<BundledSchema>::new(
            AuthConfig::default(),
            database.clone(),
        ));
        check(base, Storage::Sqlite(database), case).await?;
    }
    Ok(())
}
