#![allow(
    clippy::unwrap_used,
    reason = "test failures must include filesystem and process errors"
)]

use std::{fs, process::Command};

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
fn two_factor_additional_fields_cannot_replace_native_fields() {
    let directory = std::env::temp_dir().join(format!(
        "better-auth-cli-two-factor-fields-{}",
        std::process::id()
    ));
    fs::create_dir(&directory).unwrap();
    let config = directory.join("schema.json");
    let output = directory.join("schema.rs");
    fs::write(&output, "application-owned schema").unwrap();
    for fields in [
        r#"{"secret":{"type":"string"}}"#,
        r#"{"label":{"type":"string","fieldName":"stored_secret"}}"#,
        r#"{"createdAt":{"type":"date"}}"#,
        r#"{"label":{"type":"date","fieldName":"updated_at"}}"#,
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
        assert!(!result.status.success(), "{fields}");
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("cannot replace native field"),
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
