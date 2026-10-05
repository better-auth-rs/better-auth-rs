use super::*;
use quote::ToTokens;
use serde_json::json;

#[expect(
    clippy::expect_used,
    reason = "Fixture and generated-model structure is a test precondition; absence must fail the test."
)]
fn model_fields(source: &str, name: &str) -> BTreeMap<String, syn::Field> {
    syn::parse_file(source)
        .expect("generated source parses")
        .items
        .into_iter()
        .find_map(|item| match item {
            syn::Item::Mod(module) if module.ident == name => module.content,
            _ => None,
        })
        .expect("generated model module")
        .1
        .into_iter()
        .find_map(|item| match item {
            syn::Item::Struct(model) if model.ident == "Model" => Some(model.fields),
            _ => None,
        })
        .expect("generated Model")
        .into_iter()
        .map(|field| {
            (
                field.ident.as_ref().expect("named model field").to_string(),
                field,
            )
        })
        .collect()
}

#[test]
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "Fixture and generated-model structure is a test precondition; absence must fail the test."
)]
fn sqlite_json_storage_changes_only_fresh_nonreference_application_fields() {
    let config: SchemaConfig = serde_json::from_value(json!({
        "organization": { "additionalFields": {
            "requiredSettings": { "type": "json", "required": true },
            "settings": { "type": "json", "required": false, "fieldName": "stored_settings" },
            "displayReference": { "type": "json", "required": false,
                "references": { "model": "user", "field": "id" } },
            "tags": { "type": "string[]", "required": false }
        } },
        "team": { "additionalFields": { "name": { "type": "json", "required": false } } }
    }))
    .expect("ordinary generation configuration");
    for (database, json_type) in [
        (Database::Sqlite, "better_auth::seaorm::SqlText"),
        (Database::Postgres, "Json"),
        (Database::Mysql, "Json"),
    ] {
        let source = crate::generate::generate_schema(
            &["organization".into()],
            &config,
            false,
            IdGeneration::Random,
            database,
            false,
            false,
        )
        .expect("backend-specific schema generates");
        let organization = model_fields(&source, "organization");
        for (name, expected) in [
            ("required_settings", json_type.to_owned()),
            ("settings", format!("Option<{json_type}>")),
            (
                "display_reference",
                "Option<better_auth::seaorm::ReferenceId>".into(),
            ),
            ("tags", "Option<StringArray>".into()),
        ] {
            let expected: syn::Type =
                syn::parse_str(&expected).expect("expected public field type");
            assert_eq!(
                organization[name].ty.to_token_stream().to_string(),
                expected.to_token_stream().to_string(),
                "{name}"
            );
        }
        let settings = &organization["settings"];
        assert!(settings.attrs.iter().any(|attribute| {
            attribute.path().is_ident("serde")
                && attribute
                    .to_token_stream()
                    .to_string()
                    .contains("stored_settings")
        }));
        assert!(
            !settings
                .attrs
                .iter()
                .any(|attribute| attribute.path().is_ident("auth"))
        );
        assert!(
            organization["display_reference"]
                .attrs
                .iter()
                .any(|attribute| {
                    attribute.path().is_ident("auth")
                        && attribute
                            .to_token_stream()
                            .to_string()
                            .contains("reference")
                })
        );
        assert_eq!(
            model_fields(&source, "team")["name"]
                .ty
                .to_token_stream()
                .to_string(),
            syn::parse_str::<syn::Type>("Option<Json>")
                .expect("native JSON override type")
                .to_token_stream()
                .to_string()
        );
    }
}
