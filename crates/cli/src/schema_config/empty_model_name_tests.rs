use super::*;
use serde_json::{Value, json};

#[expect(
    clippy::expect_used,
    reason = "Fixture and generated-model structure is a test precondition; absence must fail the test."
)]
fn table_name(source: &str, module: &str) -> String {
    let file = syn::parse_file(source).expect("generated schema parses");
    let model = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Mod(item) if item.ident == module => item.content.as_ref(),
            _ => None,
        })
        .expect("generated model module")
        .1
        .iter()
        .find_map(|item| match item {
            syn::Item::Struct(item) if item.ident == "Model" => Some(item),
            _ => None,
        })
        .expect("generated entity model");
    let mut name = None;
    for attribute in &model.attrs {
        if attribute.path().is_ident("sea_orm") {
            attribute
                .parse_nested_meta(|meta| {
                    if meta.path.is_ident("table_name") {
                        name = Some(meta.value()?.parse::<syn::LitStr>()?.value());
                    }
                    Ok(())
                })
                .expect("generated table attribute");
        }
    }
    name.expect("generated table name")
}

#[test]
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "Fixture and generated-model structure is a test precondition; absence must fail the test."
)]
fn empty_model_names_preserve_each_generator_default_and_raw_declaration() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/empty-model-name-1.7.6.json"
    ))
    .expect("captured ordinary model-name fixture");
    for (model, module, rust_default, upstream_default) in [
        ("user", "user", "users", "user"),
        (
            "organization",
            "organization",
            "organization",
            "organization",
        ),
        ("rateLimit", "rate_limit", "rate_limit", "rateLimit"),
    ] {
        let captured = fixture["cases"]
            .as_array()
            .expect("captured model cases")
            .iter()
            .find(|case| case["model"] == model)
            .expect("captured model");
        let mut tables = Vec::new();
        let mut schemas = Vec::new();
        for captured in captured["views"].as_array().expect("captured model views") {
            let alias = captured["modelName"].as_str();
            let mut declaration = json!({});
            if let Some(alias) = alias {
                declaration["modelName"] = json!(alias);
            }
            assert_eq!(captured["hasModelName"], json!(alias.is_some()));
            let config: SchemaConfig =
                serde_json::from_value(json!({(model): declaration})).expect("model config parses");
            let schema = crate::generate::generate_schema(
                &if model == "organization" {
                    vec!["organization".into()]
                } else {
                    Vec::new()
                },
                &config,
                model == "rateLimit",
                IdGeneration::Random,
                Database::Sqlite,
            )
            .expect("ordinary model schema generates");
            let table = table_name(&schema, module);
            let nonempty = alias.filter(|name| !name.is_empty());
            assert_eq!(table, nonempty.unwrap_or(rust_default));
            assert_eq!(
                captured["tableName"],
                json!(nonempty.unwrap_or(upstream_default))
            );
            if model == "organization" || nonempty.is_some() {
                assert_eq!(json!(table), captured["tableName"]);
            }
            assert_eq!(config.0[model].model_name.as_deref(), alias);
            if model == "user" {
                let declaration = alias.map_or_else(
                    || "model_name: None".to_owned(),
                    |name| format!("model_name: Some({name:?})"),
                );
                assert!(schema.contains(&declaration));
            } else if model == "rateLimit" {
                if let Some(name) = alias {
                    assert!(schema.contains(&format!("model_name = {name:?}")));
                } else {
                    assert!(!schema.contains("model_name ="));
                }
            }
            tables.push(table);
            schemas.push(schema);
        }
        assert_eq!(tables.len(), 4);
        assert_eq!(tables[0], tables[1]);
        if model == "organization" {
            assert_eq!(schemas[0], schemas[1]);
        }
    }
}
