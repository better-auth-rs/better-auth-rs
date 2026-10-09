#![allow(
    clippy::unwrap_used,
    reason = "test failures must include filesystem and process errors"
)]

use quote::ToTokens;
use std::{fs, process::Command};

fn model(source: &str, module: &str) -> syn::ItemStruct {
    syn::parse_file(source)
        .unwrap()
        .items
        .into_iter()
        .find_map(|item| match item {
            syn::Item::Mod(item) if item.ident == module => item.content,
            _ => None,
        })
        .unwrap()
        .1
        .into_iter()
        .find_map(|item| match item {
            syn::Item::Struct(item) if item.ident == "Model" => Some(item),
            _ => None,
        })
        .unwrap()
}

#[test]
fn generation_rejects_unknown_plugins_and_requires_explicit_overwrite() {
    let directory =
        std::env::temp_dir().join(format!("better-auth-cli-output-{}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    let output = directory.join("auth_schema.rs");
    let generate = |plugins: &str, force: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_better-auth-rs"));
        let _ = command
            .args(["generate", "--plugins", plugins, "--output"])
            .arg(&output);
        if force {
            let _ = command.arg("--force");
        }
        command.output().unwrap()
    };
    let unknown = generate("two-facor", false);
    assert!(!unknown.status.success());
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("unknown plugin"));
    assert!(!output.exists());
    fs::write(&output, "application-owned schema").unwrap();
    assert!(!generate("two-factor", false).status.success());
    assert_eq!(
        fs::read_to_string(&output).unwrap(),
        "application-owned schema"
    );
    let forced = generate("two-factor,two-factor", true);
    assert!(
        forced.status.success(),
        "{}",
        String::from_utf8_lossy(&forced.stderr)
    );
    let schema = fs::read_to_string(&output).unwrap();
    assert_eq!(schema.matches("mod two_factor").count(), 1);
    assert!(schema.contains("create_auth_tables"));
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn invalid_schema_configuration_preserves_existing_output() {
    let directory =
        std::env::temp_dir().join(format!("better-auth-cli-config-{}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    let config = directory.join("schema.json");
    let output = directory.join("schema.rs");
    fs::write(&output, "application-owned schema").unwrap();
    for (schema, message) in [
        (
            r#"{"unknown":{"modelName":"custom"}}"#,
            "unknown schema model",
        ),
        (
            r#"{"rateLimit":{"modelName":"request_limits"}}"#,
            "requires its plugin or database storage option to be enabled",
        ),
        (
            r#"{"organization":{"fields":{"missing":"custom"}}}"#,
            "unknown configurable field",
        ),
        (
            r#"{"organization":{"fields":{"name":"slug"}}}"#,
            "duplicate database column",
        ),
        (
            r#"{"organization":{"additionalFields":{"firstName":{"type":"string"},"first_name":{"type":"string"}}}}"#,
            "conflicting Rust field",
        ),
        (
            r#"{"organization":{"additionalFields":{"label":{"type":"object"}}}}"#,
            "unsupported additional field type",
        ),
        (
            r#"{"organization":{"modelName":"user"}}"#,
            "duplicate database table",
        ),
        (
            r#"{"teamMember":{"additionalFields":{"label":{"type":"string"}}}}"#,
            "does not support additionalFields",
        ),
        (
            r#"{"organization":{"additionalFields":{"owner":{"type":"string","references":{"model":"user","field":"id","onDelete":"delete"}}}}}"#,
            "unknown variant",
        ),
        (
            r#"{"organization":{"additionalFields":{"owner":{"type":"string","references":{"model":"user"}}}}}"#,
            "missing field `field`",
        ),
    ] {
        fs::write(&config, schema).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_better-auth-rs"))
            .args([
                "generate",
                "--plugins",
                "organization",
                "--force",
                "--schema-config",
            ])
            .arg(&config)
            .arg("--output")
            .arg(&output)
            .output()
            .unwrap();
        assert!(!result.status.success(), "{schema}");
        assert!(
            String::from_utf8_lossy(&result.stderr).contains(message),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            fs::read_to_string(&output).unwrap(),
            "application-owned schema"
        );
    }
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn two_factor_native_replacements_select_complete_storage_declarations() {
    let directory = std::env::temp_dir().join(format!(
        "better-auth-cli-two-factor-fields-{}",
        std::process::id()
    ));
    fs::create_dir(&directory).unwrap();
    let config = directory.join("schema.json");
    let output = directory.join("schema.rs");
    fs::write(&output, "application-owned schema").unwrap();
    for (fields, name, ty, column) in [
        (
            r#"{"secret":{"type":"string"}}"#,
            "secret",
            "String",
            "secret",
        ),
        (
            r#"{"label":{"type":"string","fieldName":"stored_secret"}}"#,
            "secret",
            "String",
            "stored_secret",
        ),
        (
            r#"{"createdAt":{"type":"date"}}"#,
            "created_at",
            "DateTimeUtc",
            "createdAt",
        ),
        (
            r#"{"label":{"type":"date","fieldName":"updated_at"}}"#,
            "label",
            "DateTimeUtc",
            "updated_at",
        ),
    ] {
        fs::write(
            &config,
            format!(
                r#"{{"twoFactor":{{"fields":{{"secret":"stored_secret"}},"additionalFields":{fields}}}}}"#
            ),
        )
        .unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_better-auth-rs"))
            .args([
                "generate",
                "--plugins",
                "two-factor",
                "--force",
                "--schema-config",
            ])
            .arg(&config)
            .arg("--output")
            .arg(&output)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let source = fs::read_to_string(&output).unwrap();
        let entity = model(&source, "two_factor");
        let field = entity
            .fields
            .iter()
            .find(|field| field.ident.as_ref().unwrap() == name)
            .unwrap();
        assert_eq!(field.ty.to_token_stream().to_string(), ty);
        let declaration = field.to_token_stream().to_string();
        assert!(declaration.contains("reference = false"), "{declaration}");
        if name == column {
            assert!(!declaration.contains("column_name"), "{declaration}");
            assert!(!source.contains("stored_secret"));
        } else {
            assert!(
                declaration.contains(&format!("column_name = \"{column}\"")),
                "{declaration}"
            );
        }
        assert!(
            !entity
                .fields
                .iter()
                .any(|field| field.ident.as_ref().unwrap() == "updated_at")
        );
        assert_eq!(
            entity.fields.len(),
            if name == "created_at" || name == "label" {
                8
            } else {
                7
            }
        );
    }
    fs::write(&output, "application-owned schema").unwrap();
    fs::write(
        &config,
        r#"{"twoFactor":{"additionalFields":{"label":{"type":"string","fieldName":"id"}}}}"#,
    )
    .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_better-auth-rs"))
        .args([
            "generate",
            "--plugins",
            "two-factor",
            "--force",
            "--schema-config",
        ])
        .arg(&config)
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("maps a field to the primary key column")
    );
    assert_eq!(
        fs::read_to_string(&output).unwrap(),
        "application-owned schema"
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn legacy_user_defaults_do_not_reach_native_or_replaced_fields() {
    let directory = std::env::temp_dir().join(format!(
        "better-auth-cli-user-defaults-{}",
        std::process::id()
    ));
    fs::create_dir(&directory).unwrap();
    let config = directory.join("schema.json");
    fs::write(&config, r#"{"user":{"additionalFields":{"metadata":{"type":"json","required":false},"banned":{"type":"boolean","required":false},"twoFactorEnabled":{"type":"boolean","required":false}}}}"#).unwrap();
    for database in ["sqlite", "postgres", "mysql"] {
        for legacy in [false, true] {
            for replaced in [false, true] {
                let mut command = Command::new(env!("CARGO_BIN_EXE_better-auth-rs"));
                let _ = command.args([
                    "generate",
                    "--plugins",
                    "admin,two-factor",
                    "--database",
                    database,
                ]);
                if legacy {
                    let _ = command.arg("--two-factor-legacy-schema");
                }
                if replaced {
                    let _ = command.arg("--schema-config").arg(&config);
                }
                let result = command.output().unwrap();
                assert!(
                    result.status.success(),
                    "{}",
                    String::from_utf8_lossy(&result.stderr)
                );
                let source = String::from_utf8(result.stdout).unwrap();
                for field in model(&source, "user").fields {
                    let name = field.ident.as_ref().unwrap().to_string();
                    let declaration = field.to_token_stream().to_string();
                    let expected = !replaced
                        && (matches!(name.as_str(), "metadata" | "banned")
                            || name == "two_factor_enabled" && legacy);
                    assert_eq!(
                        declaration.contains("default_"),
                        expected,
                        "{database}, legacy={legacy}, replaced={replaced}: {declaration}"
                    );
                    if expected {
                        assert!(
                            declaration.contains(if name == "metadata" {
                                "('{}')"
                            } else {
                                "default_value = false"
                            }),
                            "{declaration}"
                        );
                    }
                }
            }
        }
    }
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn generated_references_use_backend_constraints_and_preserve_field_types() {
    let directory = std::env::temp_dir().join(format!(
        "better-auth-cli-backend-references-{}",
        std::process::id()
    ));
    fs::create_dir(&directory).unwrap();
    let config = directory.join("schema.json");
    fs::write(
        &config,
        r#"{
            "user": { "modelName": "app_users" },
            "organization": {
                "modelName": "app_organizations",
                "additionalFields": {
                    "owner": {
                        "type": "number",
                        "references": { "model": "user", "field": "id" }
                    },
                    "externalOwner": {
                        "type": "string",
                        "required": false,
                        "references": {
                            "model": "external_tenants",
                            "field": "tenant_code",
                            "onDelete": "restrict"
                        }
                    }
                }
            },
            "teamMember": { "fields": { "teamId": "group_id", "userId": "subject_id" } }
        }"#,
    )
    .unwrap();
    for database in ["sqlite", "postgres", "mysql"] {
        let result = Command::new(env!("CARGO_BIN_EXE_better-auth-rs"))
            .args([
                "generate",
                "--plugins",
                "all",
                "--database",
                database,
                "--schema-config",
            ])
            .arg(&config)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let source = String::from_utf8(result.stdout).unwrap();
        let physical_foreign_keys = database != "mysql";
        assert_eq!(
            source.contains(".foreign_key("),
            physical_foreign_keys,
            "{database}"
        );
        assert_eq!(
            source.contains("ForeignKey"),
            physical_foreign_keys,
            "{database}"
        );
        for constraint in [
            "fk_session_userId",
            "fk_teamMember_group_id",
            "fk_teamMember_subject_id",
            "fk_app_organizations_owner",
            "fk_app_organizations_externalOwner",
        ] {
            assert_eq!(
                source.contains(constraint),
                database == "sqlite",
                "{database}: {constraint}"
            );
        }
        assert_eq!(source.contains("\"fk_"), database == "sqlite", "{database}");
        assert_eq!(
            source.contains("ForeignKeyAction::Restrict"),
            physical_foreign_keys,
            "{database}"
        );
        for (module, field, ty, reference) in [
            ("session", "user_id", "String", None),
            ("team_member", "team_id", "String", None),
            ("team_member", "user_id", "String", None),
            (
                "organization",
                "owner",
                "better_auth :: seaorm :: ReferenceId",
                Some(true),
            ),
            (
                "organization",
                "external_owner",
                "Option < String >",
                Some(false),
            ),
        ] {
            let entity = model(&source, module);
            let field = entity
                .fields
                .iter()
                .find(|candidate| candidate.ident.as_ref().unwrap() == field)
                .unwrap();
            assert_eq!(
                field.ty.to_token_stream().to_string(),
                ty,
                "{database}: {module}"
            );
            if let Some(reference) = reference {
                assert!(
                    field
                        .to_token_stream()
                        .to_string()
                        .contains(&format!("reference = {reference}")),
                    "{database}: {module}"
                );
            }
        }
    }
    fs::remove_dir_all(directory).unwrap();
}
