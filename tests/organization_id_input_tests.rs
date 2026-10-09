#![cfg(feature = "seaorm2")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "The paired contract checks native records, callback order, and durable writes"
)]

use better_auth_core::{
    AuthConfig, AuthError, AuthRecordFields, AuthResult, AuthSchema, AuthStore, CreateInvitation,
    CreateMember, CreateOrganization, CreateOrganizationRole, CreateTeam, CreateUser, FieldDate,
    FieldMap, FieldValue, FromFieldMap, Member, Organization,
    error::DatabaseError,
    id::{IdGeneration, IdGenerator},
    organization_fields::OrganizationFields,
    store::{EphemeralStore, StatelessSchema, schema::EntityRole},
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
    },
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{
        ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement,
    },
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use std::sync::{Arc, Mutex, OnceLock, Weak};

#[path = "organization_id_input_tests/create.rs"]
mod create;
#[path = "organization_id_input_tests/records.rs"]
mod records;
#[path = "organization_id_input_tests/reentrant.rs"]
mod reentrant;
#[path = "organization_id_input_tests/storage.rs"]
mod storage;

use records::{Entry, Model, create_record, row};
use storage::Storage;
type Events = Arc<Mutex<Vec<FieldValue>>>;

fn date(offset: u32) -> FieldDate {
    FieldDate::from_milliseconds(1_893_456_000_000.0 + f64::from(offset) * 1_000.0)
}

fn trace(kind: &str, value: FieldValue) -> FieldValue {
    vec![kind.into(), value].into()
}

fn event(events: &Events, kind: &str, value: FieldValue) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Organization ID trace lock poisoned"))?
        .push(trace(kind, value));
    Ok(())
}

fn observed(events: &Events) -> AuthResult<Vec<FieldValue>> {
    Ok(events
        .lock()
        .map_err(|_| AuthError::internal("Organization ID trace lock poisoned"))?
        .clone())
}

fn generator(events: &Events, reject: bool) -> IdGeneration {
    let events = events.clone();
    IdGeneration::Custom(IdGenerator::new(move |context| {
        event(&events, "generate", context.model.into())?;
        if reject {
            return Err(AuthError::type_error("organization-id-generator-rejected"));
        }
        Ok(Some("generated".into()))
    }))
}

fn id_sentinel() -> UserFieldConfig {
    UserFieldConfig {
        field_name: Some("ignored_id".into()),
        default_value: Some("ignored-default".into()),
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

fn configured(model: Model, declarations: UserConfig, serial: bool) -> OrganizationFields {
    let mut fields = OrganizationFields::default();
    let configured = match model {
        Model::Organization => &mut fields.organization,
        Model::Member => &mut fields.member,
        Model::Invitation => &mut fields.invitation,
        Model::Team => &mut fields.team,
        Model::Role => &mut fields.organization_role,
    };
    let _ = configured.fields_mut().insert(
        "createdAt".into(),
        UserFieldConfig {
            field_type: UserFieldType::Date,
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(|_| Ok(date(0).into()))),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    if serial {
        for name in model.references() {
            let _ = configured
                .fields_mut()
                .insert((*name).into(), UserFieldConfig::default());
        }
    }
    configured
        .fields_mut()
        .extend(declarations.fields().clone());
    fields
}

fn reader<S: AuthSchema>(
    base: &dyn AuthStore<S>,
    model: Model,
    policy: IdGeneration,
    fields: UserConfig,
) -> AuthResult<Arc<dyn AuthStore<S>>> {
    let serial = matches!(policy, IdGeneration::Serial);
    let mut config = AuthConfig::default();
    config.logger.disabled = Some(true);
    config.advanced.database.generate_id = Some(policy);
    let reader = base.with_runtime(Arc::new(config), Vec::new(), Default::default())?;
    reader.configure_organization_fields(configured(model, fields, serial))?;
    Ok(reader)
}

fn assert_created(
    result: AuthResult<FieldMap>,
    expected: Option<&FieldMap>,
    model: Model,
) -> AuthResult<()> {
    if let Some(expected) = expected {
        assert_eq!(result?, *expected);
    } else {
        let Err(AuthError::Database(DatabaseError::Query(message))) = result else {
            return Err(AuthError::internal(format!(
                "Expected SQLite missing-ID error: {result:?}"
            )));
        };
        assert_eq!(
            message,
            format!(
                "Query Error: error returned from database: (code: 1299) NOT NULL constraint failed: {}.id",
                model.table()
            )
        );
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum Case {
    Native(Entry, create::Native),
    Slot(Entry, create::Slot, create::Mode),
    Serial(Model, create::Slot),
    Reentrant(reentrant::Kind, bool),
    BatchOutputReset,
    OutputError(bool),
}

fn cases(memory: bool) -> Vec<Case> {
    let mut cases = Vec::new();
    for entry in Entry::all() {
        cases.extend(create::Native::ALL.map(|native| Case::Native(entry, native)));
    }
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
            cases.push(Case::Slot(Entry::Create(Model::Organization), slot, mode));
        }
    }
    for slot in [create::Slot::BeforeAlias, create::Slot::AfterAlias] {
        cases.push(Case::Slot(
            Entry::Insert(Model::Member),
            slot,
            create::Mode::Generated,
        ));
        cases.extend(Model::ALL.map(|model| Case::Serial(model, slot)));
    }
    for kind in [
        reentrant::Kind::Found,
        reentrant::Kind::Missing,
        reentrant::Kind::Count,
        reentrant::Kind::Nested,
    ] {
        for id_first in [false, true] {
            cases.push(Case::Reentrant(kind, id_first));
        }
    }
    if memory {
        cases.extend([Case::OutputError(false), Case::OutputError(true)]);
    }
    cases.push(Case::BatchOutputReset);
    assert_eq!(cases.len(), if memory { 77 } else { 75 });
    cases
}

async fn check<S: AuthSchema>(
    base: Arc<dyn AuthStore<S>>,
    storage: Storage,
    case: Case,
) -> AuthResult<()> {
    let model = match case {
        Case::Native(entry, _) | Case::Slot(entry, _, _) => entry.model(),
        Case::Serial(model, _) => model,
        Case::Reentrant(kind, _) => kind.model(),
        Case::OutputError(_) | Case::BatchOutputReset => Model::Organization,
    };
    let baseline = storage.seed(base.as_ref(), model).await?;
    match case {
        Case::Native(entry, native) => create::native(base, storage, baseline, entry, native).await,
        Case::Slot(entry, slot, mode) => {
            create::slot(base, storage, baseline, entry, slot, mode).await
        }
        Case::Serial(model, slot) => create::serial(base, storage, baseline, model, slot).await,
        Case::Reentrant(kind, id_first) => {
            reentrant::check(base, storage, baseline, kind, id_first).await
        }
        Case::OutputError(id_first) => {
            create::output_error(base, storage, baseline, id_first).await
        }
        Case::BatchOutputReset => reentrant::batch_output_reset(base, storage, baseline).await,
    }
    .map_err(|error| AuthError::internal(format!("{case:?}: {error}")))
}

#[tokio::test]
async fn memory_organization_ids_preserve_native_inputs_slots_and_runtime_policy() -> AuthResult<()>
{
    for case in cases(true) {
        let store = EphemeralStore::new(Arc::new(AuthConfig::default()));
        let base: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(store.clone());
        check(base, Storage::Memory(store), case).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_organization_ids_preserve_native_inputs_slots_and_runtime_policy() -> AuthResult<()>
{
    for case in cases(false) {
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
