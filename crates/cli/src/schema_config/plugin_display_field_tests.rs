use super::json_storage_tests::{model_fields, reference_policy};
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
    reason = "Both generation modes must preserve the observed API Key column names and explicit display mapping."
)]
fn plugin_display_field_api_key_names_preserve_legacy_regeneration() {
    let config: SchemaConfig = serde_json::from_value(json!({
        "apikey": { "additionalFields": {
            "name": { "type": "json", "required": false, "fieldName": "stored_display" }
        } }
    }))
    .expect("display declaration");
    for database in [Database::Sqlite, Database::Postgres, Database::Mysql] {
        for legacy in [false, true] {
            let source = crate::generate::generate_schema(
                &["api-key".into()],
                &config,
                false,
                IdGeneration::Random,
                database,
                SchemaOptions {
                    api_key_legacy_schema: legacy,
                    ..Default::default()
                },
            )
            .expect("API Key schema generates");
            assert_eq!(
                super::empty_model_name_tests::table_name(&source, "api_key"),
                if legacy { "api_keys" } else { "apikey" }
            );
            let fields = model_fields(&source, "api_key");
            for (rust_name, native_name, legacy_name) in [
                ("created_at", "createdAt", "created_at"),
                ("reference_id", "referenceId", "reference_id"),
                ("key_hash", "key", "key"),
                ("name", "stored_display", "stored_display"),
            ] {
                let field = fields.get(rust_name).expect("API Key column");
                let column = attribute_value(field, "sea_orm", "column_name")
                    .unwrap_or_else(|| rust_name.to_owned());
                assert_eq!(column, if legacy { legacy_name } else { native_name });
            }
            for name in ["enabled", "rate_limit_enabled"] {
                let expected = if legacy {
                    quote::quote!(bool)
                } else {
                    quote::quote!(Option<bool>)
                };
                assert_eq!(
                    fields
                        .get(name)
                        .expect("API Key Boolean field")
                        .ty
                        .to_token_stream()
                        .to_string(),
                    expected.to_string()
                );
            }
            for name in [
                "refill_interval",
                "refill_amount",
                "rate_limit_time_window",
                "rate_limit_max",
                "request_count",
                "remaining",
            ] {
                let expected = if legacy {
                    quote::quote!(Option<f64>)
                } else {
                    quote::quote!(Option<better_auth::seaorm::SqlNumber>)
                };
                assert_eq!(
                    fields
                        .get(name)
                        .expect("API Key numeric field")
                        .ty
                        .to_token_stream()
                        .to_string(),
                    expected.to_string()
                );
            }
        }
    }
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
                    assert_eq!(
                        reference_policy(field).expect("configured display field reference policy"),
                        Some(false)
                    );
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
    reason = "Each declaration must deserialize before generated replacement fields are inspected."
)]
fn plugin_native_fields_accept_complete_replacement_declarations() {
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
            .expect("replacement field configuration");
            assert_eq!(
                generate(&config, Database::Sqlite).is_ok(),
                field.get("type") != Some(&json!([])),
                "unexpected initialization result for {model}.{display}: {field}"
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
            let source = generate(&config, Database::Sqlite).expect("native replacement generates");
            let module = if model == "apikey" { "api_key" } else { model };
            let fields = model_fields(&source, module);
            let name = match immutable {
                "key" => "key_hash",
                "credentialID" => "credential_id",
                name => name,
            };
            let generated = fields.get(name).expect("replacement retains native slot");
            let expected = if field["type"] == "json" {
                quote::quote!(better_auth::seaorm::SqlText)
            } else {
                quote::quote!(String)
            };
            assert_eq!(
                generated.ty.to_token_stream().to_string(),
                expected.to_string()
            );
        }
        let config: SchemaConfig = serde_json::from_value(json!({
            (model): { "additionalFields": {
                "nickname": { "type": "string", "fieldName": display }
            } }
        }))
        .expect("additional field occupying a native display column");
        let source = generate(&config, Database::Sqlite).expect("shared native column generates");
        let module = if model == "apikey" { "api_key" } else { model };
        let fields = model_fields(&source, module);
        assert!(!fields.contains_key("nickname"));
        assert_eq!(
            fields
                .get(display)
                .expect("first physical slot remains")
                .ty
                .to_token_stream()
                .to_string(),
            quote::quote!(String).to_string()
        );
    }
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "Each ordered declaration must deserialize before physical-column replacement is checked."
)]
fn plugin_native_columns_keep_first_position_and_last_declaration() {
    for (model, display) in [
        ("apikey", "name"),
        ("apikey", "enabled"),
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
                let source =
                    generate(&config, Database::Sqlite).expect("physical column aliases generate");
                let module = if model == "apikey" { "api_key" } else { model };
                let fields = model_fields(&source, module);
                let field = fields.get(display).expect("native position remains");
                let expected = if extra_column == "stored_display" {
                    quote::quote!(String)
                } else {
                    quote::quote!(better_auth::seaorm::SqlText)
                };
                assert_eq!(field.ty.to_token_stream().to_string(), expected.to_string());
                assert_eq!(
                    fields.contains_key(extra_name),
                    extra_column != "stored_display"
                );
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
    let source = generate(&config, Database::Sqlite).expect("shared display column generates");
    let fields = model_fields(&source, "passkey");
    assert!(!fields.contains_key("aaguid"));
    assert_eq!(
        attribute_value(
            fields.get("name").expect("shared display field"),
            "sea_orm",
            "column_name"
        ),
        Some("shared_display".into())
    );
}
