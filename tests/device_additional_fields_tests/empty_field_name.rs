use super::{contract as fields, fixture};

use better_auth::{
    __private_core::{
        AuthResult, AuthSchema, AuthStore, DeviceCode, UpdateDeviceCode,
        store::EphemeralStore,
        user_fields::{UserConfig, UserFieldConfig},
    },
    BetterAuth,
};
use serde_json::{Value, json};
use std::sync::Arc;

fn policies(alias: Option<&str>) -> UserConfig {
    UserConfig {
        additional_fields: Some(
            [(
                "label".into(),
                UserFieldConfig {
                    field_name: alias.map(str::to_owned),
                    required: Some(false),
                    ..Default::default()
                },
            )]
            .into(),
        ),
    }
}

fn display(row: &DeviceCode) -> Value {
    json!({
        "hasLabel": row.additional_fields.contains_key("label"),
        "label": row.additional_fields.get("label").cloned().unwrap_or(Value::Null),
    })
}

async fn observations<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    backend: &str,
) -> AuthResult<Value> {
    let empty = BetterAuth::new(fields::config())
        .store_arc(raw.clone())
        .plugin(fields::Fields(policies(Some(""))))
        .build()
        .await?;
    let omitted = BetterAuth::new(fields::config())
        .store_arc(raw)
        .plugin(fields::Fields(policies(None)))
        .build()
        .await?;
    let mut input = fields::input("empty-field-name");
    input.additional_fields = [("label".into(), json!("label-created"))]
        .into_iter()
        .collect();
    let created = empty.store().create_device_code(input).await?;
    let read_by_omitted = omitted
        .store()
        .get_device_code_by_device_code(&created.device_code)
        .await?
        .expect("ordinary display-field row exists");
    let updated = omitted
        .store()
        .update_device_code(
            &created.id,
            UpdateDeviceCode {
                additional_fields: [("label".into(), json!("label-updated"))]
                    .into_iter()
                    .collect(),
                ..Default::default()
            },
        )
        .await?;
    let read_by_empty = empty
        .store()
        .get_device_code_by_device_code(&created.device_code)
        .await?
        .expect("ordinary display-field row exists");
    Ok(json!({
        "backend": backend,
        "createdByEmpty": display(&created),
        "readByOmitted": display(&read_by_omitted),
        "updatedByOmitted": display(&updated),
        "readByEmpty": display(&read_by_empty),
    }))
}

fn assert_pinned(actual: Value) {
    let fixture: Value =
        serde_json::from_str(include_str!("../fixtures/empty-field-name-1.7.6.json"))
            .expect("captured display-field alias fixture");
    let expected = fixture["cases"]
        .as_array()
        .expect("captured cases")
        .iter()
        .find(|case| case["backend"] == actual["backend"])
        .expect("captured backend");
    assert_eq!(&actual, expected);
}

#[tokio::test]
async fn memory_empty_and_omitted_display_aliases_share_storage() {
    let actual = observations(
        Arc::new(EphemeralStore::new(Arc::new(fields::config()))),
        "memory",
    )
    .await
    .expect("ordinary Memory alias observations");
    assert_pinned(actual);
}

#[tokio::test]
async fn sqlite_empty_and_omitted_display_aliases_share_storage() {
    let (store, _) = fixture::sqlite(fields::config()).await;
    let actual = observations(Arc::new(store), "sqlite")
        .await
        .expect("ordinary SQLite alias observations");
    assert_pinned(actual);
}
