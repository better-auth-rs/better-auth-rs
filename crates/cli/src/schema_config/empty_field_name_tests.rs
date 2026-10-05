use super::*;
use serde_json::{Value, json};

#[test]
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "Fixture and generated-model structure is a test precondition; absence must fail the test."
)]
fn ordinary_display_columns_match_the_pinned_empty_alias_schema() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/empty-field-name-1.7.6.json"
    ))
    .expect("captured display-field alias fixture");
    let mut generated = Vec::new();
    for (view, alias) in [("empty", Some("")), ("omitted", None), ("space", Some(" "))] {
        let mut field = json!({"type": "string", "required": false});
        if let Some(alias) = alias {
            field["fieldName"] = json!(alias);
        }
        let config: SchemaConfig = serde_json::from_value(json!({
            "deviceCode": {"additionalFields": {"label": field}}
        }))
        .expect("ordinary CLI display field parses");
        let definition = better_auth_schema_registry::plugin_schemas()
            .iter()
            .flat_map(|plugin| plugin.extra_entities)
            .find(|entity| entity.role == Some(EntityRole::DeviceCode))
            .expect("Device registry model");
        let entity = Entity::resolve(
            definition,
            better_auth_schema_registry::core_fields(EntityRole::DeviceCode),
            config.0.get("deviceCode"),
            Database::Sqlite,
            Default::default(),
        )
        .expect("ordinary CLI display column resolves");
        let column = &entity
            .fields
            .iter()
            .find(|field| field.ident == "label")
            .expect("declared display field")
            .column;
        let expected = fixture["schemas"]
            .as_array()
            .expect("captured schemas")
            .iter()
            .find(|schema| schema["view"] == view)
            .expect("captured schema view");
        assert_eq!(json!({"view": view, "columns": [column]}), *expected);
        assert_eq!(
            config.0["deviceCode"].additional_fields["label"]
                .field_name
                .as_deref(),
            alias
        );
        let schema = crate::generate::generate_schema(
            &["device-authorization".into()],
            &config,
            false,
            IdGeneration::Random,
            Database::Sqlite,
            Default::default(),
        )
        .expect("ordinary CLI display schema generates");
        assert!(schema.contains("pub label: Option<String>"));
        generated.push(schema);
    }
    assert_eq!(generated[0], generated[1]);
    assert!(generated[2].contains("column_name = \" \""));
}
