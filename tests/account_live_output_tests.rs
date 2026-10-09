#![cfg(feature = "seaorm2")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "The paired contract requires complete adapter records, callback order, and durable writes after output errors"
)]

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthStore, CreateAccount, CreateUser, FieldDate,
    FieldMap, FieldValue, UpdateAccount,
    store::{
        EphemeralStore, StatelessSchema,
        database_hooks::{
            DatabaseHookContext, DatabaseHookControl, DatabaseHooks, DatabaseUpdateResult,
        },
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
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

type Events = Arc<Mutex<Vec<Value>>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Path {
    Create,
    Find,
    Update,
    Delete,
}

#[derive(Clone)]
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
                    "SELECT * FROM accounts ORDER BY id".to_owned(),
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
                let value = fields
                    .get(name)
                    .ok_or_else(|| AuthError::internal(format!("Expected Account date {name}")))?
                    .json()?;
                let _ = fields.insert(name.into(), FieldValue::from_json(value)?);
            }
        }
        Ok(fields)
    }
}

fn date(offset: u32) -> FieldDate {
    FieldDate::from_milliseconds(1_893_456_000_000.0 + f64::from(offset) * 1_000.0)
}

fn input(id: &str, account_id: &str, token: &str, scope: &str, updated: u32) -> CreateAccount {
    CreateAccount {
        id: id.into(),
        account_id: account_id.into(),
        provider_id: "provider".into(),
        user_id: "owner".into(),
        access_token: Some(token.to_owned()).into(),
        refresh_token: Some("refresh".into()).into(),
        id_token: Some("id-token".into()).into(),
        access_token_expires_at: Some(date(10)).into(),
        refresh_token_expires_at: Some(date(20)).into(),
        scope: Some(scope.to_owned()).into(),
        password: Some("password".into()).into(),
        created_at: date(0).into(),
        updated_at: date(updated).into(),
        ..Default::default()
    }
}

fn target(token: &str, scope: &str, updated: u32) -> AuthResult<FieldMap> {
    input("target", "subject", token, scope, updated).fields()
}

fn event(events: &Events, value: Value) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Account output trace lock poisoned"))?
        .push(value);
    Ok(())
}

fn observed(events: &Events) -> AuthResult<Vec<Value>> {
    Ok(events
        .lock()
        .map_err(|_| AuthError::internal("Account output trace lock poisoned"))?
        .clone())
}

fn visible(row: Option<&AccountView>) -> AuthResult<Value> {
    match row {
        Some(row) => row.internal_fields()?.json(),
        None => Ok(Value::Null),
    }
}

struct Hooks(Events);

#[better_auth::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for Hooks {
    async fn after_create_account(
        &self,
        row: Option<&AccountView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        event(&self.0, json!(["after-create", visible(row)?]))
    }

    async fn after_update_account(
        &self,
        result: DatabaseUpdateResult<&AccountView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        let DatabaseUpdateResult::One(row) = result else {
            return Err(AuthError::internal(
                "A single Account update must return its first projected row",
            ));
        };
        event(&self.0, json!(["after-update", visible(row)?]))
    }

    async fn before_delete_account(
        &self,
        row: &AccountView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        event(&self.0, json!(["before-delete", visible(Some(row))?]))?;
        Ok(DatabaseHookControl::Continue)
    }

    async fn after_delete_account(
        &self,
        row: &AccountView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        event(&self.0, json!(["after-delete", visible(Some(row))?]))
    }
}

fn reader<S: AuthSchema>(
    writer: Arc<dyn AuthStore<S>>,
    storage: &Storage,
    events: &Events,
    reject: bool,
    duplicate: bool,
) -> AuthResult<Arc<dyn AuthStore<S>>> {
    let mut config = AuthConfig::default();
    let base = writer.clone();
    let storage = storage.clone();
    let trace = events.clone();
    let _ = config.account.additional_fields.insert(
        "accountId".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new_async(move |value| {
                    let writer = writer.clone();
                    let storage = storage.clone();
                    let events = trace.clone();
                    async move {
                        event(&events, json!(["accountId", value.json()?]))?;
                        if duplicate {
                            let rows = storage
                                .read()
                                .await?
                                .into_iter()
                                .map(|row| row.json())
                                .collect::<AuthResult<Vec<_>>>()?;
                            event(&events, json!(["before-write", rows]))?;
                        }
                        let written = writer
                            .update_account(
                                "target",
                                UpdateAccount {
                                    access_token: Some("after".into()).into(),
                                    updated_at: date(1).into(),
                                    ..Default::default()
                                },
                            )
                            .await?;
                        event(
                            &events,
                            json!(["write", written.internal_fields()?.json()?]),
                        )?;
                        if reject {
                            return Err(AuthError::type_error("account-output-rejected"));
                        }
                        Ok(value)
                    }
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let trace = events.clone();
    let _ = config.account.additional_fields.insert(
        "accessToken".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    event(&trace, json!(["accessToken", value.json()?]))?;
                    let token = value
                        .as_str()
                        .ok_or_else(|| AuthError::internal("Expected an Account access token"))?;
                    Ok(format!("{token}:out").into())
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    base.with_runtime(
        Arc::new(config),
        vec![Arc::new(Hooks(events.clone()))],
        Default::default(),
    )
}

async fn check<S: AuthSchema>(
    base: Arc<dyn AuthStore<S>>,
    storage: Storage,
    path: Path,
    reject: bool,
    duplicate: bool,
) -> AuthResult<()> {
    let _ = base
        .create_user(CreateUser {
            id: Some("owner".into()),
            ..CreateUser::new()
                .with_email("owner@account-live-output.test")
                .with_name("Owner")
        })
        .await?;
    let retained = input("retained", "retained-subject", "retained", "read", 0);
    let _ = base.create_account(retained.clone()).await?;
    if path != Path::Create {
        let _ = base
            .create_account(input("target", "subject", "before", "read", 0))
            .await?;
    }
    if duplicate {
        let _ = base
            .create_account(input(
                "target",
                "duplicate-subject",
                "second-before",
                "read",
                0,
            ))
            .await?;
    }
    let events = Events::default();
    let reader = reader(base, &storage, &events, reject, duplicate)?;
    let result = match path {
        Path::Create => {
            reader
                .create_account_optional(input("target", "subject", "before", "read", 0))
                .await
        }
        Path::Find => reader.get_account("provider", "subject").await,
        Path::Update => {
            reader
                .update_account_optional(
                    "target",
                    UpdateAccount {
                        access_token: Some("before".into()).into(),
                        scope: Some("requested".into()).into(),
                        updated_at: date(0).into(),
                        ..Default::default()
                    },
                )
                .await
        }
        Path::Delete => reader.delete_account("target").await.map(|()| None),
    };
    let scope = if path == Path::Update {
        "requested"
    } else {
        "read"
    };
    let mut trace = vec![json!(["accountId", "subject"])];
    if duplicate {
        let second = if path == Path::Update {
            "before"
        } else {
            "second-before"
        };
        trace.push(json!([
            "before-write",
            [
                retained.fields()?.json()?,
                target("before", scope, 0)?.json()?,
                input("target", "duplicate-subject", second, scope, 0)
                    .fields()?
                    .json()?,
            ]
        ]));
    }
    trace.push(json!(["write", target("after", scope, 1)?.json()?]));
    if reject && path != Path::Delete {
        assert!(
            matches!(&result, Err(AuthError::TypeError(message)) if message == "account-output-rejected"),
            "{result:?}"
        );
    } else if path == Path::Delete {
        assert!(result?.is_none());
    } else {
        let projected = target(
            if storage.is_memory() {
                "after:out"
            } else {
                "before:out"
            },
            scope,
            u32::from(storage.is_memory()),
        )?;
        let actual = result?
            .ok_or_else(|| AuthError::internal("Account projection must return the target row"))?;
        assert_eq!(actual.internal_fields()?, projected);
    }
    if !reject {
        let token = if storage.is_memory() {
            "after"
        } else {
            "before"
        };
        let projected = target(
            &format!("{token}:out"),
            scope,
            u32::from(storage.is_memory()),
        )?
        .json()?;
        trace.push(json!(["accessToken", token]));
        match path {
            Path::Create => trace.push(json!(["after-create", projected])),
            Path::Update => trace.push(json!(["after-update", projected])),
            Path::Delete => {
                trace.push(json!(["before-delete", projected]));
                trace.push(json!(["after-delete", projected]));
            }
            Path::Find => {}
        }
    }
    assert_eq!(observed(&events)?, trace, "{path:?}/{reject}/{duplicate}");
    let mut expected = vec![storage.expected(retained.fields()?)?];
    if path != Path::Delete || reject {
        expected.push(storage.expected(target("after", scope, 1)?)?);
        if duplicate {
            expected.push(
                storage
                    .expected(input("target", "duplicate-subject", "after", scope, 1).fields()?)?,
            );
        }
    }
    assert_eq!(
        storage.read().await?,
        expected,
        "{path:?}/{reject}/{duplicate}"
    );
    Ok(())
}

fn memory() -> (Arc<dyn AuthStore<StatelessSchema>>, Storage) {
    let store = EphemeralStore::new(Arc::new(AuthConfig::default()));
    (Arc::new(store.clone()), Storage::Memory(store))
}

#[tokio::test]
async fn memory_account_output_reads_live_fields_and_preserves_writes_after_callback_errors()
-> AuthResult<()> {
    for path in [Path::Create, Path::Find, Path::Update, Path::Delete] {
        for reject in [false, true] {
            let (base, storage) = memory();
            check(base, storage, path, reject, false).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_account_output_keeps_snapshots_and_preserves_writes_after_callback_errors()
-> AuthResult<()> {
    for path in [Path::Create, Path::Find, Path::Update, Path::Delete] {
        for reject in [false, true] {
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
            check(base, Storage::Sqlite(database), path, reject, false).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn memory_account_single_mutations_write_all_duplicate_ids_and_project_only_the_first()
-> AuthResult<()> {
    for path in [Path::Update, Path::Delete] {
        for reject in [false, true] {
            let (base, storage) = memory();
            check(base, storage, path, reject, true).await?;
        }
    }
    Ok(())
}
