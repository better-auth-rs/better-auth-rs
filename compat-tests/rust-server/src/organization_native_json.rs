use better_auth::config::UserFieldTransform;
use better_auth::config::{UserConfig, UserFieldConfig, UserFieldType};
use better_auth::plugins::organization::OrganizationConfig;
use serde_json::{Value, json};
use std::sync::Arc;

fn replace(from: &'static str, to: &'static str) -> better_auth::config::UserFieldTransform {
    UserFieldTransform::new(move |value| {
        Ok(value.map(|value| match value {
            Value::String(value) => json!(value.replace(from, to)),
            value => value,
        }))
    })
}

pub fn configure(config: &mut OrganizationConfig, profile: &str) {
    let json_type = profile == "organization-native-json-object";
    config.teams.default_team = false;
    config.hooks = Some(Arc::new(JsonHooks));
    config.schema.organization = UserConfig {
        additional_fields: [(
            "metadata".into(),
            UserFieldConfig {
                field_type: if json_type {
                    UserFieldType::Json
                } else {
                    UserFieldType::String
                },
                required: Some(false),
                default_value: Some(json!(r#"{"source":"default"}"#)),
                input_transform: Some(replace("source", "stored")),
                output_transform: Some(UserFieldTransform::new(move |value| {
                    if json_type
                        && value
                            .as_ref()
                            .is_some_and(|value| !value.is_null() && !value.is_string())
                    {
                        return Err(better_auth::AuthError::internal(
                            "JSON output callback requires stored text",
                        ));
                    }
                    replace("stored", "visible").call_sync(value)
                })),
                ..Default::default()
            },
        )]
        .into(),
    };
    config.schema.organization_role = UserConfig {
        additional_fields: [
            (
                "permission".into(),
                UserFieldConfig {
                    field_type: if json_type {
                        UserFieldType::Json
                    } else {
                        UserFieldType::String
                    },
                    required: Some(false),
                    input_transform: Some(replace("create", "delete")),
                    output_transform: Some(replace("delete", "update")),
                    on_update: Some(Arc::new(|| json!(r#"{"member":["create"]}"#))),
                    ..Default::default()
                },
            ),
            (
                "role".into(),
                UserFieldConfig {
                    required: Some(false),
                    ..Default::default()
                },
            ),
            (
                "organizationId".into(),
                UserFieldConfig {
                    required: Some(false),
                    ..Default::default()
                },
            ),
            (
                "id".into(),
                UserFieldConfig {
                    required: Some(false),
                    field_name: Some("ignored_id".into()),
                    ..Default::default()
                },
            ),
        ]
        .into(),
    };
}

struct JsonHooks;

#[async_trait::async_trait]
impl better_auth::plugins::organization::hooks::OrganizationHooks for JsonHooks {
    async fn before_update_organization(
        &self,
        data: &mut better_auth_core::UpdateOrganization,
        _actor: better_auth::plugins::organization::hooks::OrganizationActor<'_>,
    ) -> better_auth::AuthResult<()> {
        if data
            .metadata
            .as_ref()
            .and_then(Value::as_object)
            .is_some_and(|value| value.contains_key("clear"))
        {
            data.metadata = Some(Value::Null);
        }
        Ok(())
    }
}
