use super::{
    contract::{TestResult, revive_fields, stored},
    lifecycle_hooks,
    lifecycle_models::Schema,
    trace::{self, Trace},
    values,
};
use better_auth_core::{
    AuthConfig, AuthError, AuthResult, CreateSession, CreateUser, CreateVerification, FieldDate,
    FieldMap, FieldValue, SchemaValue,
    id::{IdGeneration, IdGenerator},
    store::{
        AuthTransaction, SessionCreateWriter, VerificationCreateWriter,
        database_hooks::DatabaseHooks,
    },
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType},
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use tracing::instrument::WithSubscriber;
use tracing_subscriber::prelude::*;

const CASES: [&str; 13] = [
    "user-before-cancel-transaction",
    "user-written-null-direct",
    "user-written-null-transaction",
    "user-after-null-error-direct",
    "user-after-null-error-transaction",
    "user-written-null-rollback",
    "session-secondary-immediate",
    "session-secondary-deferred",
    "session-secondary-before-cancel",
    "session-secondary-deferred-after-error",
    "verification-secondary-immediate",
    "verification-secondary-before-cancel",
    "verification-secondary-after-error",
];

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Case {
    pub(super) name: String,
    pub(super) model: String,
    #[serde(default)]
    pub(super) transaction: bool,
    #[serde(default)]
    pub(super) cancel: bool,
    #[serde(default)]
    pub(super) secondary: bool,
    #[serde(default)]
    pub(super) deferred: bool,
    #[serde(default)]
    pub(super) after_error: bool,
    #[serde(default)]
    pub(super) rollback: bool,
    setup: Vec<String>,
    input: Value,
    pub(super) patch: Value,
    before: Value,
    returned: bool,
    result: Option<Value>,
    error: Option<Value>,
    pub(super) trace: Vec<Value>,
    after: Value,
    pub(super) cache: Vec<Value>,
}

pub(super) fn observe(fields: Option<FieldMap>) -> AuthResult<Value> {
    fields
        .map(|fields| {
            Ok(json!({
                "keys": fields.keys().collect::<Vec<_>>(),
                "fields": values::observe(&FieldValue::from(fields.clone()))?,
            }))
        })
        .transpose()
        .map(|value| value.unwrap_or(Value::Null))
}

fn date(fields: &FieldMap, name: &str) -> AuthResult<FieldDate> {
    match &fields[name] {
        FieldValue::Date(date) => Ok(date.clone()),
        value => Err(AuthError::internal(format!(
            "Expected captured Date for {name}, got {value:?}"
        ))),
    }
}

fn user(fields: &FieldMap) -> AuthResult<CreateUser> {
    let mut input = CreateUser::new();
    input.id = Some(fields["id"].decode()?);
    input.name = SchemaValue::from_field(fields["name"].clone());
    input.email = Some(fields["email"].decode()?);
    input.email_verified = Some(fields["emailVerified"].decode()?);
    input.image = SchemaValue::from_field(fields["image"].clone());
    input.created_at = Some(date(fields, "createdAt")?);
    input.updated_at = Some(date(fields, "updatedAt")?);
    Ok(input)
}

fn session(fields: FieldMap) -> AuthResult<CreateSession> {
    Ok(CreateSession {
        user_id: "owner-a".into(),
        expires_at: date(&fields, "expiresAt")?,
        ip_address: Some(fields["ipAddress"].decode()?),
        user_agent: Some(fields["userAgent"].decode()?),
        impersonated_by: None,
        active_organization_id: None,
        inherited_fields: FieldMap::new(),
        additional_fields: fields,
    })
}

fn verification(fields: FieldMap) -> CreateVerification {
    CreateVerification {
        field_order: fields.keys().cloned().collect(),
        id: SchemaValue::from_field(fields["id"].clone()),
        identifier: SchemaValue::from_field(fields["identifier"].clone()),
        value: SchemaValue::from_field(fields["value"].clone()),
        expires_at: SchemaValue::from_field(fields["expiresAt"].clone()),
        created_at: SchemaValue::from_field(fields["createdAt"].clone()),
        updated_at: SchemaValue::from_field(fields["updatedAt"].clone()),
        additional_fields: FieldMap::new(),
    }
}

fn session_writer(trace: Trace, deferred: bool) -> SessionCreateWriter {
    SessionCreateWriter {
        write_database: true,
        deferred,
        write: Box::new(move |original, actual| {
            Box::pin(async move {
                trace.callback(json!({"phase": "writer:session", "original": observe(Some(original))?, "actual": observe(Some(actual))?}));
                Ok(())
            })
        }),
    }
}

fn verification_writer(trace: Trace) -> VerificationCreateWriter {
    Box::new(move |actual| {
        Box::pin(async move {
            trace.callback(
                json!({"phase": "writer:verification", "actual": observe(Some(actual))?}),
            );
            Ok(())
        })
    })
}

async fn transaction_body(
    tx: &dyn AuthTransaction<Schema>,
    case: &Case,
    trace: Trace,
) -> AuthResult<Value> {
    let fields = revive_fields(&case.input["fields"])?;
    let result = match case.model.as_str() {
        "user" => {
            assert!(
                tx.create_user_optional(user(&fields)?).await?.is_none(),
                "nullable User readback"
            );
            Value::Null
        }
        "session" => observe(
            tx.create_session_with_writer(
                session(fields)?,
                Some(session_writer(trace.clone(), case.deferred)),
            )
            .await?
            .map(FieldMap::from),
        )?,
        "verification" => observe(
            tx.create_verification_with_writer(
                verification(fields),
                Some(verification_writer(trace.clone())),
            )
            .await?
            .map(|record| record.fields())
            .transpose()?,
        )?,
        model => {
            return Err(AuthError::internal(format!(
                "Unknown lifecycle model {model}"
            )));
        }
    };
    trace.callback(json!({"phase": "body:return", "data": result}));
    tx.queue_after_commit(Box::pin(async move {
        trace.callback(json!({"phase": "after:tail"}));
        Ok(())
    }))?;
    if case.rollback {
        return Err(AuthError::internal("creation-body-rollback"));
    }
    Ok(result)
}

async fn storage(database: &DatabaseConnection) -> TestResult<Value> {
    let mut tables = serde_json::Map::new();
    for table in ["user", "session", "verification"] {
        let _ = tables.insert(table.into(), stored(database, table, "id").await?);
    }
    Ok(Value::Object(tables))
}

async fn setup(database: &DatabaseConnection, case: &Case) -> TestResult {
    assert_eq!(case.setup.len(), 2);
    for sql in case.setup[0]
        .split(';')
        .map(str::trim)
        .filter(|sql| !sql.is_empty())
    {
        let _ = database.execute_unprepared(sql).await?;
    }
    for row in case.before["user"].as_array().expect("seeded owners") {
        let owner = revive_fields(&row["row"])?;
        let _ = database.execute_raw(Statement::from_sql_and_values(DbBackend::MySql,
            "INSERT INTO `user` (`id`, `name`, `email`, `emailVerified`, `image`, `createdAt`, `updatedAt`) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [owner["id"].decode::<String>()?.into(), owner["name"].decode::<String>()?.into(),
                owner["email"].decode::<String>()?.into(), 1_i32.into(), Option::<String>::None.into(),
                date(&owner, "createdAt")?.to_datetime()?.expect("seeded date").into(),
                date(&owner, "updatedAt")?.to_datetime()?.expect("seeded date").into()],
        )).await?;
    }
    let _ = database.execute_unprepared(&case.setup[1]).await?;
    assert_eq!(
        storage(database).await?,
        case.before,
        "{} initial storage",
        case.name
    );
    Ok(())
}

fn config(case: &Case, trace: &Trace) -> AuthConfig {
    let mut config = AuthConfig::new("mysql-lifecycle-fixture-secret-at-least-32-characters");
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    config.advanced.database.generate_id = Some(IdGeneration::Custom(IdGenerator::new(|input| {
        Ok(Some(format!("{}-generated-id", input.model)))
    })));
    let field = match case.model.as_str() {
        "user" => "name",
        "session" => "token",
        "verification" => "value",
        _ => unreachable!(),
    };
    let callback = |phase: &'static str| {
        let trace = trace.clone();
        UserFieldTransform::new(move |value| {
            trace.callback(
                json!({"phase": phase, "field": field, "value": values::observe(&value)?}),
            );
            if phase == "input" {
                Ok(format!("{}:stored", value.decode::<String>()?).into())
            } else {
                Ok(value)
            }
        })
    };
    let policy = UserFieldConfig {
        field_type: UserFieldType::String,
        required: Some(true),
        transform: Some(FieldTransforms {
            input: Some(callback("input")),
            output: Some(callback("output")),
        }),
        ..Default::default()
    };
    match case.model.as_str() {
        "user" => {
            let _ = config.user.fields_mut().insert(field.into(), policy);
        }
        "session" => {
            let _ = config.session.fields_mut().insert(field.into(), policy);
        }
        "verification" => {
            let _ = config
                .verification
                .additional_fields
                .insert(field.into(), policy);
        }
        _ => unreachable!(),
    }
    config
}

pub(super) async fn check(mut database: DatabaseConnection, name: &str) -> TestResult {
    let capture: Value =
        serde_json::from_str(include_str!("../fixtures/create-readback-mysql-1.7.6.json"))?;
    assert_eq!(capture["version"], "1.7.6");
    assert_eq!(capture["lifecycle"]["now"], "2030-01-02T03:04:05.000Z");
    let cases: Vec<Case> = serde_json::from_value(capture["lifecycle"]["cases"].clone())?;
    assert_eq!(
        cases
            .iter()
            .map(|case| case.name.as_str())
            .collect::<Vec<_>>(),
        CASES
    );
    let case = cases
        .into_iter()
        .find(|case| case.name == name)
        .expect("named lifecycle case");
    assert_eq!(case.secondary, case.model != "user");
    setup(&database, &case).await?;
    let trace = Trace::default();
    trace.capture(&mut database);
    let config = config(&case, &trace);
    let raw = SeaOrmStore::<Schema>::new(config.clone(), database.clone());
    let hooks: Vec<Arc<dyn DatabaseHooks<Schema>>> = vec![
        Arc::new(lifecycle_hooks::Plugin {
            trace: trace.clone(),
            case: case.clone(),
            patch: revive_fields(&case.patch["fields"])?,
        }),
        Arc::new(lifecycle_hooks::Application(trace.clone())),
    ];
    let store = better_auth_core::store::RuntimeStore::with_runtime(
        &raw,
        Arc::new(config),
        hooks,
        Default::default(),
    )?;
    let subscriber = tracing_subscriber::registry().with(trace.clone());
    let result = async {
        if case.transaction {
            let case = case.clone();
            let trace = trace.clone();
            better_auth_core::store::transaction(store.as_ref(), move |tx| {
                Box::pin(async move { transaction_body(tx, &case, trace).await })
            })
            .await
        } else {
            assert_eq!(case.model, "user");
            assert!(
                store
                    .create_user_optional(user(&revive_fields(&case.input["fields"])?)?)
                    .await?
                    .is_none()
            );
            trace.callback(json!({"phase": "body:return", "data": null}));
            trace.callback(json!({"phase": "after:tail"}));
            Ok(Value::Null)
        }
    }
    .with_subscriber(subscriber)
    .await;
    trace::check_lifecycle(trace.take(), &case)?;
    assert_eq!(result.is_ok(), case.returned, "{name}: {result:?}");
    match result {
        Ok(value) => {
            assert!(case.error.is_none());
            assert_eq!(
                value,
                case.result.unwrap_or(Value::Null),
                "{name} complete result"
            );
        }
        Err(AuthError::Internal(message)) => assert_eq!(
            case.error,
            Some(json!({"name": "Error", "message": message})),
            "{name} callback/rollback error"
        ),
        Err(error) => return Err(error.into()),
    }
    assert_eq!(
        storage(&database).await?,
        case.after,
        "{name} committed or rolled-back rows"
    );
    Ok(())
}
