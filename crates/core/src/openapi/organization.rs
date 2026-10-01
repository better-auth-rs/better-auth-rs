use serde_json::{Map, Value, json};

use crate::{
    AuthError, AuthResult,
    organization_fields::OrganizationFields,
    user_fields::{UserConfig, UserFieldType},
};

use super::OpenApiPluginMetadata;

impl OpenApiPluginMetadata {
    /// Apply the Organization plugin's configured field schemas at their route-specific merge boundaries.
    pub fn organization_fields(mut self, fields: &OrganizationFields) -> AuthResult<Self> {
        for (model, fields) in [
            ("organization", &fields.organization),
            ("member", &fields.member),
            ("invitation", &fields.invitation),
            ("team", &fields.team),
        ] {
            if self.models.contains_key(model) {
                self = self.model(model, fields);
            }
        }
        for (key, model, pointer, base_last, partial, force_optional) in [
            (
                "createOrganization",
                &fields.organization,
                "/content/application~1json/schema",
                false,
                false,
                false,
            ),
            (
                "updateOrganization",
                &fields.organization,
                "/content/application~1json/schema/properties/data",
                true,
                true,
                false,
            ),
            (
                "createInvitation",
                &fields.invitation,
                "/content/application~1json/schema",
                false,
                false,
                false,
            ),
            (
                "addMember",
                &fields.member,
                "/content/application~1json/schema",
                false,
                false,
                false,
            ),
            (
                "createTeam",
                &fields.team,
                "/content/application~1json/schema",
                false,
                false,
                false,
            ),
            (
                "updateTeam",
                &fields.team,
                "/content/application~1json/schema/properties/data",
                false,
                true,
                false,
            ),
            (
                "createOrgRole",
                &fields.organization_role,
                "/content/application~1json/schema/properties/additionalFields",
                false,
                false,
                false,
            ),
            (
                "updateOrgRole",
                &fields.organization_role,
                "/content/application~1json/schema/allOf/0/properties/data",
                false,
                false,
                true,
            ),
        ] {
            let Some(endpoint) = self.endpoint_mut(key) else {
                continue;
            };
            let schema = endpoint
                .metadata
                .request_body
                .as_mut()
                .and_then(|body| body.pointer_mut(pointer))
                .and_then(Value::as_object_mut)
                .ok_or_else(|| {
                    AuthError::config(format!(
                        "OpenAPI Organization endpoint {key} omits {pointer}"
                    ))
                })?;
            overlay(schema, model, base_last, partial, force_optional);
        }
        if self.models.contains_key("organizationRole") {
            let mut role = fields.organization_role.clone();
            for field in role.fields_mut().values_mut() {
                field.required = Some(false);
            }
            self = self.model("organizationRole", &role);
        }
        Ok(self)
    }
}

fn overlay(
    schema: &mut Map<String, Value>,
    fields: &UserConfig,
    base_last: bool,
    partial: bool,
    force_optional: bool,
) {
    let base = schema
        .get("properties")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let base_fields: indexmap::IndexMap<String, (Value, bool)> = base
        .into_iter()
        .map(|(key, property)| {
            let is_required = required.contains(&Value::String(key.clone()));
            (key, (property, is_required))
        })
        .collect();
    let additional: indexmap::IndexMap<String, (Value, bool)> = fields
        .fields()
        .iter()
        .filter(|(_, field)| field.input())
        .map(|(key, field)| {
            let optional = force_optional || field.required == Some(false);
            let mut property = match &field.field_type {
                UserFieldType::String | UserFieldType::Date | UserFieldType::Json => {
                    json!({"type":"string"})
                }
                UserFieldType::Number => json!({"type":"number"}),
                UserFieldType::Boolean => json!({"type":"boolean"}),
                UserFieldType::StringArray => json!({"type":"array","items":{"type":"string"}}),
                UserFieldType::NumberArray => json!({"type":"array","items":{"type":"number"}}),
                UserFieldType::Enum(_) => json!({}),
            };
            if optional {
                if let Some(kind) = property.get("type").cloned() {
                    if let Some(property) = property.as_object_mut() {
                        let _ = property.insert("type".into(), json!([kind, "null"]));
                    }
                } else {
                    property = json!({"anyOf":[property,{"type":"null"}]});
                }
            }
            (key.clone(), (property, !optional && !partial))
        })
        .collect();
    let mut merged = if base_last {
        additional.clone()
    } else {
        base_fields.clone()
    };
    merged.extend(if base_last { base_fields } else { additional });
    let required: Vec<_> = merged
        .iter()
        .filter(|(_, (_, required))| *required)
        .map(|(key, _)| Value::String(key.clone()))
        .collect();
    let _ = schema.insert(
        "properties".into(),
        Value::Object(
            merged
                .into_iter()
                .map(|(key, (value, _))| (key, value))
                .collect(),
        ),
    );
    if required.is_empty() {
        let _ = schema.remove("required");
    } else {
        let _ = schema.insert("required".into(), Value::Array(required));
    }
}
