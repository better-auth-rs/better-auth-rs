use better_auth::config::{FieldTransforms, UserFieldTransform};
use better_auth::config::{UserConfig, UserFieldConfig, UserFieldType};
use better_auth::plugins::organization::OrganizationConfig;
use serde_json::{Value, json};
use std::sync::Arc;

fn text(input: &'static str, output: &'static str) -> UserFieldConfig {
    let suffix = |suffix: &'static str| {
        UserFieldTransform::new(move |value: Option<Value>| {
            let value = value
                .and_then(|value| value.as_str().map(str::to_owned))
                .ok_or_else(|| better_auth::AuthError::bad_request("Expected a string field"))?;
            Ok(Some(json!(format!("{value}{suffix}"))))
        })
    };
    UserFieldConfig {
        required: Some(true),
        transform: Some(FieldTransforms {
            input: Some(suffix(input)),
            output: Some(suffix(output)),
        }),
        ..Default::default()
    }
}

pub fn configure(config: &mut OrganizationConfig) {
    config.teams.enabled = true;
    config.teams.default_team = false;
    config.schema.organization = UserConfig {
        additional_fields: Some(
            [
                ("id".into(), id()),
                ("name".into(), text(":in", ":out")),
                (
                    "logo".into(),
                    UserFieldConfig {
                        required: Some(false),
                        input: Some(false),
                        default_value: Some(json!("default-logo")),
                        ..Default::default()
                    },
                ),
                (
                    "createdAt".into(),
                    UserFieldConfig {
                        field_type: UserFieldType::Date,
                        input: Some(false),
                        returned: Some(false),
                        ..Default::default()
                    },
                ),
            ]
            .into(),
        ),
    };
    config.schema.member = UserConfig {
        additional_fields: Some(
            [(
                "role".into(),
                UserFieldConfig {
                    returned: Some(false),
                    ..text(",member", ",admin")
                },
            )]
            .into(),
        ),
    };
    config.schema.invitation = UserConfig {
        additional_fields: Some(
            [
                ("id".into(), id()),
                ("role".into(), text(",member", ",admin")),
            ]
            .into(),
        ),
    };
    config.schema.team = UserConfig {
        additional_fields: Some(
            [
                ("id".into(), id()),
                ("name".into(), text(":team-in", ":team-out")),
                (
                    "updatedAt".into(),
                    UserFieldConfig {
                        field_type: UserFieldType::Date,
                        required: Some(false),
                        input: Some(false),
                        on_update: Some(Arc::new(|| json!("2020-01-02T03:04:05.000Z"))),
                        ..Default::default()
                    },
                ),
            ]
            .into(),
        ),
    };
    config.schema.organization_role = UserConfig {
        additional_fields: Some([("role".into(), text("_stored", "_visible"))].into()),
    };
}

fn id() -> UserFieldConfig {
    UserFieldConfig {
        required: Some(false),
        field_name: Some("unused_id".into()),
        default_value: Some(json!("unused-default")),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(|_| {
                Err(better_auth::AuthError::bad_request(
                    "ID policies must not execute",
                ))
            })),
            output: Some(UserFieldTransform::new(|_| {
                Err(better_auth::AuthError::bad_request(
                    "ID policies must not execute",
                ))
            })),
        }),
        ..Default::default()
    }
}
