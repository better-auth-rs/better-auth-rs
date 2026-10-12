#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify raw initialization, later field projection, and retained native identity."
)]

use super::*;
use crate::{
    FieldObject,
    store::{RuntimeStore, schema::EntityRole},
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
};

#[tokio::test]
async fn raw_initialization_preserves_physical_records_before_runtime_queries() -> AuthResult<()> {
    let output_inputs = Arc::new(Mutex::new(Vec::new()));
    let mut config = AuthConfig::default();
    let _ = config.user.fields_mut().insert(
        "name".into(),
        UserFieldConfig {
            field_name: Some("display_name".into()),
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(|_| {
                    Err(AuthError::internal(
                        "Raw initialization must not run input transforms",
                    ))
                })),
                output: Some(UserFieldTransform::new({
                    let output_inputs = output_inputs.clone();
                    move |value| {
                        output_inputs
                            .lock()
                            .map_err(|_| AuthError::internal("Output trace lock poisoned"))?
                            .push(value);
                        Ok("Projected User".into())
                    }
                })),
            }),
            ..Default::default()
        },
    );
    let _ = config.user.fields_mut().insert(
        "profileExtra".into(),
        UserFieldConfig {
            default_value_fn: Some(crate::user_fields::UserFieldFactory::new(|| {
                Err(AuthError::internal(
                    "Raw initialization must not evaluate defaults",
                ))
            })),
            ..Default::default()
        },
    );
    let config = Arc::new(config);
    let child = FieldObject::from(FieldMap::from([("phase".into(), "before".into())]));
    let record = FieldMap::from([
        ("extra".into(), child.clone().into()),
        ("email".into(), Value::Null),
        ("id".into(), "seed".into()),
        ("display_name".into(), "Stored User".into()),
        ("ownUndefined".into(), Value::Undefined),
        ("image".into(), Value::Null),
    ]);
    let extra = FieldMap::from([("value".into(), child.clone().into())]);
    let store = EphemeralStore::from_storage(
        config.clone(),
        [
            ("application-table".into(), vec![extra.clone()]),
            ("user".into(), vec![record.clone()]),
            ("session".into(), Vec::new()),
        ],
    )?;
    assert!(
        output_inputs
            .lock()
            .map_err(|_| AuthError::internal("Output trace lock poisoned"))?
            .is_empty()
    );
    store.operation(|operation| {
        assert_eq!(
            operation.root_keys()?,
            ["application-table", "user", "session"]
        );
        assert_eq!(
            operation.capture_table(EntityRole::Session)?.snapshot()?,
            Vec::<FieldMap>::new()
        );
        let table = operation
            .capture_physical_table("application-table")?
            .ok_or_else(|| AuthError::internal("Missing application table"))?;
        assert_eq!(table.snapshot()?, [extra]);
        Ok(())
    })?;
    let stored = store
        .storage_rows(EntityRole::User)?
        .into_iter()
        .next()
        .ok_or_else(|| AuthError::internal("Missing seeded user"))?;
    assert_eq!(stored, record);
    assert_eq!(
        stored.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "extra",
            "email",
            "id",
            "display_name",
            "ownUndefined",
            "image"
        ]
    );
    assert!(
        stored
            .get("extra")
            .is_some_and(|value| value.strict_equals(&child.clone().into()))
    );
    assert_eq!(stored.get("ownUndefined"), Some(&Value::Undefined));
    assert_eq!(stored.get("email"), Some(&Value::Null));
    assert!(!stored.contains_key("profileExtra"));

    let runtime = store.with_runtime(config, Vec::new(), Default::default())?;
    let user = runtime
        .get_user_by_id("seed")
        .await?
        .ok_or_else(|| AuthError::internal("Runtime query missed the seeded user"))?;
    assert_eq!(user.name.field_value(), "Projected User".into());
    assert_eq!(
        *output_inputs
            .lock()
            .map_err(|_| AuthError::internal("Output trace lock poisoned"))?,
        [Value::from("Stored User")]
    );
    assert_eq!(store.storage_rows(EntityRole::User)?, [record]);
    child.set("phase", "after".into())?;
    let retained = stored
        .get("extra")
        .ok_or_else(|| AuthError::internal("Missing retained child"))?;
    assert_eq!(retained.model_property("phase")?, "after".into());
    Ok(())
}
