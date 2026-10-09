#![cfg(feature = "seaorm2")]

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, FieldDate, FieldValue, UpdateUser,
    store::UserStore,
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType},
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectOptions, ConnectionTrait, Database, EntityTrait, Schema},
    store::{__private_test_support::bundled_schema::BundledSchema, entities::user},
};
use serde_json::json;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

type Trace = Arc<Mutex<Vec<&'static str>>>;

fn date() -> FieldDate {
    FieldDate::from_milliseconds(1_893_456_001_000.0)
}

fn record(trace: &Trace, event: &'static str) -> AuthResult<()> {
    trace
        .lock()
        .map_err(|_| AuthError::internal("Query binding trace lock poisoned"))?
        .push(event);
    Ok(())
}

fn take_trace(trace: &Trace) -> AuthResult<Vec<&'static str>> {
    Ok(std::mem::take(&mut *trace.lock().map_err(|_| {
        AuthError::internal("Query binding trace lock poisoned")
    })?))
}

fn config(trace: &Trace, reject: &Arc<AtomicBool>) -> AuthConfig {
    let mut config = AuthConfig::default();
    let input_trace = trace.clone();
    let output_trace = trace.clone();
    let reject = reject.clone();
    let _ = config.user.fields_mut().insert(
        "name".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    record(&input_trace, "name-input")?;
                    if reject.load(Ordering::SeqCst) {
                        return Err(AuthError::internal("user-input-rejected"));
                    }
                    Ok(value)
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    record(&output_trace, "name-output")?;
                    Ok(value)
                })),
            }),
            ..Default::default()
        },
    );
    let default_trace = trace.clone();
    let _ = config.user.fields_mut().insert(
        "image".into(),
        UserFieldConfig {
            default_value_fn: Some(Arc::new(move || {
                record(&default_trace, "image-default")?;
                Ok("creation-only-image".into())
            })),
            ..Default::default()
        },
    );
    let update_trace = trace.clone();
    let input_trace = trace.clone();
    let _ = config.user.fields_mut().insert(
        "updatedAt".into(),
        UserFieldConfig {
            field_type: UserFieldType::Date,
            on_update: Some(Arc::new(move || {
                record(&update_trace, "updated-on-update")?;
                Ok(date().into())
            })),
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    record(&input_trace, "updated-input")?;
                    if value != FieldValue::from(date()) {
                        return Err(AuthError::internal(
                            "Update transform must receive onUpdate date",
                        ));
                    }
                    Ok(value)
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let _ = config.user.fields_mut().insert(
        "id".into(),
        UserFieldConfig {
            field_name: Some("old_id".into()),
            ..Default::default()
        },
    );
    config
}

fn update() -> UpdateUser {
    UpdateUser {
        name: Some("After".into()).into(),
        ..Default::default()
    }
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The paired contract asserts callback order, original errors, complete output, and unchanged storage"
)]
async fn sqlite_user_input_precedes_second_query_binding_and_failed_updates_keep_id_canonical()
-> Result<(), Box<dyn std::error::Error>> {
    for rejected_input in [false, true] {
        let mut options = ConnectOptions::new("sqlite::memory:");
        let _ = options.max_connections(1);
        let database = Database::connect(options).await?;
        let _ = database
            .execute(
                &Schema::new(database.get_database_backend())
                    .create_table_from_entity(user::Entity),
            )
            .await?;
        // Adapter writes or reads would replace the application ID declaration before this update.
        let _ = database
            .execute_unprepared(
                "INSERT INTO users (id, name, email, email_verified, image, created_at, updated_at) \
                 VALUES ('seed', 'Before', 'seed@example.test', 1, NULL, \
                 '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z')",
            )
            .await?;
        let before = user::Entity::find().all(&database).await?;
        assert_eq!(before.len(), 1);
        let trace = Trace::default();
        let reject = Arc::new(AtomicBool::new(rejected_input));
        let store = SeaOrmStore::<BundledSchema>::new(config(&trace, &reject), database.clone());
        let id = FieldValue::from("seed");
        assert_eq!(take_trace(&trace)?, Vec::<&str>::new());
        let result = store.update_user_by_id_value(&id, update()).await;
        if rejected_input {
            assert!(
                matches!(&result, Err(AuthError::Internal(message)) if message == "user-input-rejected"),
                "{result:?}"
            );
            assert_eq!(take_trace(&trace)?, ["name-input"]);
        } else {
            assert!(
                matches!(&result, Err(AuthError::Config(message)) if message == "Field old_id not found in model user"),
                "{result:?}"
            );
            assert_eq!(
                take_trace(&trace)?,
                ["name-input", "updated-on-update", "updated-input"]
            );
        }
        assert_eq!(user::Entity::find().all(&database).await?, before);

        reject.store(false, Ordering::SeqCst);
        let result = store.update_user_by_id_value(&id, update()).await?;
        assert_eq!(
            take_trace(&trace)?,
            [
                "name-input",
                "updated-on-update",
                "updated-input",
                "name-output"
            ]
        );
        assert_eq!(
            serde_json::to_value(result)?,
            json!({
                "id": "seed", "name": "After", "email": "seed@example.test", "emailVerified": true,
                "image": null, "createdAt": "2030-01-01T00:00:00.000Z", "updatedAt": "2030-01-01T00:00:01.000Z",
            })
        );
        let mut expected = before;
        let row = expected
            .first_mut()
            .ok_or_else(|| AuthError::internal("Seed user is missing"))?;
        row.name = Some("After".into());
        row.updated_at = "2030-01-01T00:00:01Z".parse()?;
        assert_eq!(user::Entity::find().all(&database).await?, expected);
    }
    Ok(())
}
