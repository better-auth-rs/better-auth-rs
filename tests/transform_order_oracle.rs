#![cfg(feature = "seaorm2")]

use better_auth::config::{FieldTransforms, UserFieldTransform};
use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthStore, CreateUser, store::EphemeralStore,
    types::ListUsersParams, user_fields::UserFieldConfig,
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::Database,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

async fn observe<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    trace: &Mutex<Vec<String>>,
) -> AuthResult<Value> {
    for name in ["A", "B"] {
        let mut user = CreateUser::new()
            .with_name(name)
            .with_email(format!("{}@transform.test", name.to_lowercase()));
        user.image = Some(format!("{name}.png")).into();
        let _ = store.create_user(user).await?;
    }
    trace
        .lock()
        .map_err(|_| AuthError::internal("Oracle trace mutex was poisoned"))?
        .clear();
    let (rows, _) = store
        .list_users(ListUsersParams {
            sort_by: Some("email".into()),
            sort_direction: Some("asc".into()),
            ..Default::default()
        })
        .await?;
    let values: Vec<_> = rows
        .iter()
        .map(|row| json!({"name":row.name,"image":row.image}))
        .collect();
    assert_eq!(
        *trace
            .lock()
            .map_err(|_| AuthError::internal("Oracle trace mutex was poisoned"))?,
        ["name:A", "name:B", "image:A.png", "image:B.png"]
    );
    assert_eq!(
        values,
        vec![
            json!({"name":"A:1","image":"A.png:3"}),
            json!({"name":"B:2","image":"B.png:4"})
        ]
    );
    Ok(
        json!({"trace":*trace.lock().map_err(|_| AuthError::internal("Oracle trace mutex was poisoned"))?,"values":values}),
    )
}

#[tokio::test]
async fn ordinary_output_transform_matches_upstream() -> AuthResult<()> {
    let mut results = Vec::new();
    for backend in ["memory", "sqlite"] {
        let trace = Arc::new(Mutex::new(Vec::new()));
        let mut config = AuthConfig::default();
        for name in ["name", "image"] {
            let trace = trace.clone();
            let _ = config.user.fields_mut().insert(
                name.into(),
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        output: Some(UserFieldTransform::new(move |value| {
                            let raw = value.as_ref().and_then(Value::as_str).ok_or_else(|| {
                                AuthError::internal("Oracle field must be a string")
                            })?;
                            let mut trace = trace.lock().map_err(|_| {
                                AuthError::internal("Oracle trace mutex was poisoned")
                            })?;
                            trace.push(format!("{name}:{raw}"));
                            Ok(Some(json!(format!("{raw}:{}", trace.len()))))
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
        }
        let config = Arc::new(config);
        let mut result = if backend == "memory" {
            observe(&EphemeralStore::new(config), &trace).await?
        } else {
            let database = Database::connect("sqlite::memory:")
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
            migrator::run_migrations(&database)
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
            observe(&SeaOrmStore::<BundledSchema>::new(config, database), &trace).await?
        };
        let _ = result
            .as_object_mut()
            .ok_or_else(|| AuthError::internal("Oracle result must be an object"))?
            .insert("backend".into(), json!(backend));
        results.push(result);
    }
    let expected: Value =
        serde_json::from_str(include_str!("fixtures/transform-order-upstream.json"))?;
    let observed = json!(results);
    if observed != expected {
        return Err(AuthError::internal(format!(
            "Output transform observations differ from the shared fixture: expected {expected}, observed {observed}"
        )));
    }
    Ok(())
}
