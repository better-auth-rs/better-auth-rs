use super::*;
use crate::{
    native_sort_contract::{Harness, assert_case, cases, getter_cases},
    store::{RuntimeStore, schema::EntityRole},
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
};

#[tokio::test]
async fn memory_native_sort_replays_complete_source_runtime() -> AuthResult<()> {
    for case in cases("memory") {
        run_case(case, false).await?;
    }
    Ok(())
}

#[tokio::test]
async fn memory_accessor_sort_replays_complete_source_runtime() -> AuthResult<()> {
    for case in getter_cases("memory") {
        run_case(case, true).await?;
    }
    Ok(())
}

async fn run_case(case: &serde_json::Value, accessors: bool) -> AuthResult<()> {
    let harness = if accessors {
        Harness::new_getters(case)?
    } else {
        Harness::new(case)?
    };
    let mut config = AuthConfig::default();
    let output = harness.clone();
    let _ = config.user.fields_mut().insert(
        "name".into(),
        UserFieldConfig {
            required: Some(false),
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| output.output(value))),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let config = Arc::new(config);
    let stored = if accessors {
        let rows = harness
            .rows()
            .into_iter()
            .map(|value| match value {
                Value::Object(object) => Ok(object),
                _ => Err(AuthError::internal(
                    "The source fixture supplies record objects",
                )),
            })
            .collect::<AuthResult<_>>()?;
        EphemeralStore::from_storage_objects(
            config.clone(),
            [
                ("user".into(), rows),
                ("session".into(), Vec::new()),
                ("account".into(), Vec::new()),
                ("verification".into(), Vec::new()),
            ],
        )?
    } else {
        let fields = harness
            .rows()
            .into_iter()
            .map(|row| row.enumerable_fields())
            .collect::<AuthResult<_>>()?;
        EphemeralStore::from_storage(
            config.clone(),
            [
                ("user".into(), fields),
                ("session".into(), Vec::new()),
                ("account".into(), Vec::new()),
                ("verification".into(), Vec::new()),
            ],
        )?
    };
    let rows: Vec<_> = stored.operation(|operation| {
        Ok(operation
            .capture_table(EntityRole::User)?
            .snapshot_refs()?
            .into_iter()
            .map(|row| row.field_value())
            .collect())
    })?;
    if accessors {
        for (stored, supplied) in rows.iter().zip(harness.rows()) {
            assert!(
                stored.strict_equals(&supplied),
                "Storage must retain the supplied accessor receiver"
            );
        }
    } else {
        harness.bind_rows(rows);
    }
    let runtime = stored.with_runtime(config, Vec::new(), Default::default())?;
    let before = harness.before()?;
    let result = runtime
        .list_users(ListUsersParams {
            sort_by: Some("name".into()),
            sort_direction: case["direction"].as_str().map(str::to_owned),
            limit: Some(1000.0),
            ..Default::default()
        })
        .await
        .and_then(|(users, total)| {
            assert_eq!(total, harness.rows().len());
            users
                .into_iter()
                .map(|user| user.field_values().map(Value::from))
                .collect::<AuthResult<Vec<_>>>()
                .map(Value::from)
        });
    assert_case(&harness.finish(before, result)?, case);
    for role in [
        EntityRole::Session,
        EntityRole::Account,
        EntityRole::Verification,
    ] {
        assert!(stored.storage_rows(role)?.is_empty());
    }
    Ok(())
}
