use super::*;
use quote::ToTokens;
use serde_json::{Value, json};

#[expect(
    clippy::expect_used,
    reason = "Generated model structure is a test precondition; absence must fail the test."
)]
fn model_field(file: &syn::File, module: &str, name: &str) -> syn::Field {
    file.items
        .iter()
        .find_map(|item| match item {
            syn::Item::Mod(item) if item.ident == module => item.content.as_ref(),
            _ => None,
        })
        .expect("generated model module")
        .1
        .iter()
        .find_map(|item| match item {
            syn::Item::Struct(item) if item.ident == "Model" => Some(&item.fields),
            _ => None,
        })
        .expect("generated Model")
        .iter()
        .find(|field| field.ident.as_ref().is_some_and(|ident| ident == name))
        .expect("generated native field")
        .clone()
}

#[expect(
    clippy::expect_used,
    reason = "Generated field attributes must parse completely before their values are compared."
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
                .expect("generated field attribute");
        }
    }
    value
}

#[expect(
    clippy::expect_used,
    reason = "The generated declaration AST and every mapping pair must exist with the expected shape."
)]
fn assert_raw_fields(file: &syn::File, model: &str, expected: Option<&BTreeMap<String, String>>) {
    let body = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Impl(item) => item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == "model_declarations" => {
                    Some(&method.block)
                }
                _ => None,
            }),
            _ => None,
        })
        .expect("generated model_declarations method");
    let array = match body.stmts.as_slice() {
        [syn::Stmt::Expr(syn::Expr::Reference(reference), None)] => match reference.expr.as_ref() {
            syn::Expr::Array(array) => Some(array),
            _ => None,
        },
        _ => None,
    }
    .expect("complete static model declaration array");
    if model == "organization" {
        assert!(
            array.elems.is_empty(),
            "Organization has no core model declaration"
        );
        return;
    }
    assert_eq!(array.elems.len(), 1);
    let declaration = array
        .elems
        .first()
        .and_then(|value| match value {
            syn::Expr::Struct(value) => Some(value),
            _ => None,
        })
        .expect("single generated core declaration");
    assert_eq!(declaration.fields.len(), 3);
    let member = |name: &str| {
        declaration.fields.iter().find_map(|field| {
            matches!(&field.member, syn::Member::Named(ident) if ident == name)
                .then_some(&field.expr)
        })
    };
    let role = member("role")
        .and_then(|value| match value {
            syn::Expr::Path(value) => value
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string()),
            _ => None,
        })
        .expect("declared core role");
    assert_eq!(
        role,
        if model == "user" {
            "User"
        } else {
            "Verification"
        }
    );
    assert!(
        matches!(member("model_name"), Some(syn::Expr::Path(value)) if value.path.is_ident("None"))
    );
    let expression = member("fields").expect("complete raw fields declaration");
    let actual = match expression {
        syn::Expr::Path(value) if value.path.is_ident("None") => Some(None),
        syn::Expr::Call(call) => {
            assert!(
                matches!(call.func.as_ref(), syn::Expr::Path(value) if value.path.is_ident("Some"))
            );
            assert_eq!(call.args.len(), 1);
            let values = call
                .args
                .first()
                .and_then(|value| match value {
                    syn::Expr::Reference(reference) => match reference.expr.as_ref() {
                        syn::Expr::Array(array) => Some(&array.elems),
                        _ => None,
                    },
                    _ => None,
                })
                .expect("complete raw mapping array");
            let mut fields = BTreeMap::new();
            for value in values {
                let pair = match value {
                    syn::Expr::Tuple(pair) => Some(&pair.elems),
                    _ => None,
                }
                .expect("raw mapping tuple");
                assert_eq!(pair.len(), 2);
                let mut strings = pair.iter().map(|value| match value {
                    syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Str(value),
                        ..
                    }) => Some(value.value()),
                    _ => None,
                });
                let name = strings.next().flatten().expect("raw logical name");
                let value = strings
                    .next()
                    .flatten()
                    .expect("raw physical name declaration");
                assert!(
                    fields.insert(name, value).is_none(),
                    "duplicate declaration"
                );
            }
            Some(Some(fields))
        }
        _ => None,
    }
    .expect("raw fields are None or the complete Some mapping array");
    assert_eq!(actual.as_ref(), expected);
}

fn presence(value: Option<&str>) -> Value {
    value.map_or_else(
        || json!({"present": false}),
        |value| json!({"present": true, "value": value}),
    )
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "The complete captured schema and generated native fields are required test observations."
)]
fn native_field_mappings_match_upstream_and_preserve_raw_declarations() {
    let expected: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/native-empty-field-mapping-1.7.6.json"
    ))
    .expect("captured ordinary native field mapping fixture");
    let mut cases = Vec::new();
    for (name, model, logical, native, custom) in [
        ("user-name", "user", "name", "name", "stored_user_name"),
        (
            "organization-name",
            "organization",
            "name",
            "name",
            "stored_organization_name",
        ),
        (
            "verification-created-at",
            "verification",
            "createdAt",
            "created_at",
            "stored_verification_created_at",
        ),
    ] {
        let mut views = Vec::new();
        for (view, alias) in [
            ("omitted", None),
            ("empty", Some("")),
            ("custom", Some(custom)),
            ("space", Some(" ")),
        ] {
            let declaration =
                alias.map_or_else(|| json!({}), |alias| json!({"fields": {(logical): alias}}));
            let config: SchemaConfig = serde_json::from_value(json!({(model): declaration}))
                .expect("ordinary native mapping configuration");
            let expected_fields =
                alias.map(|alias| BTreeMap::from([(logical.to_owned(), alias.to_owned())]));
            assert_eq!(
                config.0.get(model).expect("configured model").fields,
                expected_fields
            );
            let plugins = if model == "organization" {
                vec!["organization".into()]
            } else {
                Vec::new()
            };
            let source = crate::generate::generate_schema(
                &plugins,
                &config,
                false,
                IdGeneration::Random,
                Database::Sqlite,
                false,
                false,
            )
            .expect("ordinary native schema generates");
            let file = syn::parse_file(&source).expect("generated source parses");
            let field = model_field(&file, model, native);
            let physical = attribute_value(&field, "sea_orm", "column_name").unwrap_or_else(|| {
                field
                    .ident
                    .as_ref()
                    .expect("named native field")
                    .to_string()
            });
            assert_raw_fields(&file, model, expected_fields.as_ref());
            views.push(
                json!({"view": view, "declaration": declaration, "physicalColumn": physical}),
            );
        }
        cases.push(json!({"name": name, "model": model, "field": logical, "views": views}));
    }
    assert_eq!(json!({"version": "1.7.6", "cases": cases}), expected);
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "Generated displayUsername attributes and raw declarations must be present for complete comparison."
)]
fn empty_display_username_mapping_preserves_distinct_physical_and_serialized_defaults() {
    let mut observations = Vec::new();
    let mut fields = Vec::new();
    for (view, alias) in [
        ("omitted", None),
        ("empty", Some("")),
        ("custom", Some("stored_display_name")),
        ("space", Some(" ")),
    ] {
        let declaration = alias.map_or_else(
            || json!({}),
            |alias| json!({"fields": {"displayUsername": alias}}),
        );
        let config: SchemaConfig = serde_json::from_value(json!({"user": declaration}))
            .expect("displayUsername mapping configuration");
        let expected_fields =
            alias.map(|alias| BTreeMap::from([("displayUsername".to_owned(), alias.to_owned())]));
        assert_eq!(
            config.0.get("user").expect("configured user").fields,
            expected_fields
        );
        let source = crate::generate::generate_schema(
            &["username".into()],
            &config,
            false,
            IdGeneration::Random,
            Database::Sqlite,
            false,
            false,
        )
        .expect("username schema generates");
        let file = syn::parse_file(&source).expect("generated username source parses");
        let field = model_field(&file, "user", "display_username");
        let column = attribute_value(&field, "sea_orm", "column_name");
        let serialized = attribute_value(&field, "serde", "rename");
        let native = field
            .ident
            .as_ref()
            .expect("named displayUsername field")
            .to_string();
        observations.push(json!({
            "view": view,
            "rustField": native,
            "rustType": field.ty.to_token_stream().to_string(),
            "seaOrmColumnName": presence(column.as_deref()),
            "effectiveColumn": column.as_deref().unwrap_or(&native),
            "serdeRename": presence(serialized.as_deref()),
            "declaration": declaration,
        }));
        assert_raw_fields(&file, "user", expected_fields.as_ref());
        fields.push(field.to_token_stream().to_string());
    }
    let rust_type = quote::quote!(Option<String>).to_string();
    assert_eq!(
        observations,
        vec![
            json!({"view":"omitted","rustField":"display_username","rustType":rust_type,"seaOrmColumnName":{"present":false},"effectiveColumn":"display_username","serdeRename":{"present":true,"value":"displayUsername"},"declaration":{}}),
            json!({"view":"empty","rustField":"display_username","rustType":rust_type,"seaOrmColumnName":{"present":false},"effectiveColumn":"display_username","serdeRename":{"present":true,"value":"displayUsername"},"declaration":{"fields":{"displayUsername":""}}}),
            json!({"view":"custom","rustField":"display_username","rustType":rust_type,"seaOrmColumnName":{"present":true,"value":"stored_display_name"},"effectiveColumn":"stored_display_name","serdeRename":{"present":true,"value":"stored_display_name"},"declaration":{"fields":{"displayUsername":"stored_display_name"}}}),
            json!({"view":"space","rustField":"display_username","rustType":rust_type,"seaOrmColumnName":{"present":true,"value":" "},"effectiveColumn":" " ,"serdeRename":{"present":true,"value":" "},"declaration":{"fields":{"displayUsername":" "}}}),
        ]
    );
    assert_eq!(
        fields.first().expect("omitted field AST"),
        fields.get(1).expect("empty field AST")
    );
}
