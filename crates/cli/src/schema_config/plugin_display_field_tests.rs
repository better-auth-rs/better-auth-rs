use super::json_storage_tests::model_fields;
use super::*;
use quote::ToTokens;
use serde_json::json;

fn generate(config: &SchemaConfig, database: Database) -> Result<String, String> {
    crate::generate::generate_schema(
        &["api-key".into(), "passkey".into()],
        config,
        false,
        IdGeneration::Random,
        database,
        Default::default(),
    )
}

#[expect(
    clippy::expect_used,
    reason = "Generated display-field attributes must parse before their storage names are compared."
)]
fn attribute_value(field: &syn::Field, attribute_name: &str, key: &str) -> Option<String> {
    let mut value = None;
    for attribute in &field.attrs {
        if attribute.path().is_ident(attribute_name) {
            attribute
                .parse_nested_meta(|meta| {
                    if meta.path.is_ident(key) {
                        value = Some(meta.value()?.parse::<syn::LitStr>()?.value());
                    }
                    Ok(())
                })
                .expect("generated display-field attribute");
        }
    }
    value
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "Configuration and generated model fields are required observations for the storage contract."
)]
fn plugin_display_fields_generate_declared_storage_types_and_aliases() {
    for field_type in [
        json!("string"),
        json!(["personal", "shared"]),
        json!("json"),
    ] {
        for required in [None, Some(true), Some(false)] {
            let declaration = |column: &str| {
                let mut field = json!({ "type": field_type, "fieldName": column });
                if let Some(required) = required {
                    let _ = field
                        .as_object_mut()
                        .expect("field declaration object")
                        .insert("required".into(), json!(required));
                }
                field
            };
            let config: SchemaConfig = serde_json::from_value(json!({
                "apikey": { "additionalFields": {
                    "name": declaration("stored_api_name")
                } },
                "passkey": { "additionalFields": {
                    "name": declaration("stored_passkey_name"),
                    "aaguid": declaration("stored_aaguid")
                } }
            }))
            .expect("display-field generation configuration");
            for database in [Database::Sqlite, Database::Postgres, Database::Mysql] {
                let source = generate(&config, database).expect("display-field schema generates");
                let api_key = model_fields(&source, "api_key");
                let passkey = model_fields(&source, "passkey");
                let expected = match (field_type.as_str(), database) {
                    (Some("json"), Database::Sqlite) => "better_auth::seaorm::SqlText",
                    (Some("json"), _) => "Json",
                    _ => "String",
                };
                let expected = if required == Some(false) {
                    format!("Option<{expected}>")
                } else {
                    expected.to_owned()
                };
                let expected: syn::Type =
                    syn::parse_str(&expected).expect("expected display-field storage type");
                for (model, name, column) in [
                    (&api_key, "name", "stored_api_name"),
                    (&passkey, "name", "stored_passkey_name"),
                    (&passkey, "aaguid", "stored_aaguid"),
                ] {
                    let field = model
                        .get(name)
                        .expect("native display field remains present");
                    assert_eq!(
                        field.ty.to_token_stream().to_string(),
                        expected.to_token_stream().to_string(),
                        "{column}: {field_type}, required={required:?}"
                    );
                    assert_eq!(
                        attribute_value(field, "sea_orm", "column_name").as_deref(),
                        Some(column)
                    );
                    assert_eq!(
                        attribute_value(field, "serde", "rename").as_deref(),
                        Some(column)
                    );
                    assert!(!field.attrs.iter().any(|attr| attr.path().is_ident("auth")));
                }
                for (model, name) in [(&api_key, "key_hash"), (&passkey, "public_key")] {
                    assert_eq!(
                        model
                            .get(name)
                            .expect("native credential field")
                            .ty
                            .to_token_stream()
                            .to_string(),
                        quote::quote!(String).to_string()
                    );
                }
                assert!(!passkey.contains_key("credential"));
            }
        }
    }
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "The negative configurations must deserialize before generation rejects unsafe native replacements."
)]
fn plugin_display_fields_reject_other_types_references_and_native_aliases() {
    for (model, display, native, immutable) in [
        ("apikey", "name", "key", "key"),
        ("passkey", "name", "credentialID", "credentialID"),
        ("passkey", "aaguid", "name", "counter"),
    ] {
        for field in [
            json!({ "type": "number" }),
            json!({ "type": "boolean" }),
            json!({ "type": "date" }),
            json!({ "type": "string[]" }),
            json!({ "type": "number[]" }),
            json!({ "type": [] }),
            json!({ "type": "json", "references": { "model": "user", "field": "id" } }),
            json!({ "type": "string", "fieldName": native }),
        ] {
            let config: SchemaConfig = serde_json::from_value(json!({
                (model): { "additionalFields": { (display): field } }
            }))
            .expect("unsupported display-field configuration");
            assert!(
                generate(&config, Database::Sqlite).is_err(),
                "accepted {model}.{display}: {field}"
            );
        }
        for field in [
            json!({ "type": "string" }),
            json!({ "type": "json", "fieldName": "custom_column" }),
        ] {
            let config: SchemaConfig = serde_json::from_value(json!({
                (model): { "additionalFields": { (immutable): field } }
            }))
            .expect("native replacement configuration");
            assert!(generate(&config, Database::Sqlite).is_err());
        }
        let config: SchemaConfig = serde_json::from_value(json!({
            (model): { "additionalFields": {
                "nickname": { "type": "string", "fieldName": display }
            } }
        }))
        .expect("additional field occupying a native display column");
        assert!(generate(&config, Database::Sqlite).is_err());
    }
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "Each ordered declaration must deserialize before the shared storage-column conflict is checked."
)]
fn plugin_display_field_column_conflicts_do_not_depend_on_declaration_order() {
    for (model, display) in [
        ("apikey", "name"),
        ("passkey", "name"),
        ("passkey", "aaguid"),
    ] {
        for (extra_name, extra_column) in [("stored_display", "other"), ("extra", "stored_display")]
        {
            for display_first in [false, true] {
                let mut fields = indexmap::IndexMap::new();
                let display_field: AdditionalField = serde_json::from_value(json!({
                    "type": "json", "fieldName": "stored_display"
                }))
                .expect("display declaration");
                let extra: AdditionalField = serde_json::from_value(json!({
                    "type": "string", "fieldName": extra_column
                }))
                .expect("conflicting additional declaration");
                if display_first {
                    let _ = fields.insert(display.to_owned(), display_field);
                    let _ = fields.insert(extra_name.to_owned(), extra);
                } else {
                    let _ = fields.insert(extra_name.to_owned(), extra);
                    let _ = fields.insert(display.to_owned(), display_field);
                }
                let config = SchemaConfig(BTreeMap::from([(
                    model.to_owned(),
                    ModelConfig {
                        additional_fields: fields,
                        ..Default::default()
                    },
                )]));
                assert!(generate(&config, Database::Sqlite).is_err());
            }
        }
    }
    let config: SchemaConfig = serde_json::from_value(json!({
        "passkey": { "additionalFields": {
            "name": { "type": "json", "fieldName": "shared_display" },
            "aaguid": { "type": "json", "fieldName": "shared_display" }
        } }
    }))
    .expect("two displays with one storage column");
    assert!(generate(&config, Database::Sqlite).is_err());
}
