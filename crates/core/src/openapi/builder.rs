use std::collections::HashSet;

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::{HttpMethod, user_fields::UserConfig};

/// Documentation supplied by an endpoint. The endpoint retains its own input validation.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenApiRouteMetadata {
    pub description: Option<String>,
    pub operation_id: Option<String>,
    pub tags: Option<Vec<String>>,
    pub parameters: Option<Vec<Value>>,
    pub request_body: Option<Value>,
    #[serde(default)]
    pub responses: Map<String, Value>,
    #[serde(default)]
    pub server_only: bool,
}

#[derive(Debug, Serialize)]
pub struct OpenApiSpec {
    pub openapi: String,
    pub info: OpenApiInfo,
    pub components: Value,
    pub security: Vec<Value>,
    pub servers: Vec<Value>,
    pub tags: Vec<Value>,
    pub paths: IndexMap<String, IndexMap<String, Value>>,
}

#[derive(Debug, Serialize)]
pub struct OpenApiInfo {
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub version: String,
}

pub struct OpenApiBuilder {
    spec: OpenApiSpec,
    used_ids: HashSet<String>,
    models: Map<String, Value>,
    user_input: Map<String, Value>,
    user_required: Vec<String>,
}

impl OpenApiBuilder {
    pub fn new(title: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            spec: OpenApiSpec {
                openapi: "3.1.1".into(),
                info: OpenApiInfo {
                    title: title.into(),
                    version: version.into(),
                    description: None,
                },
                components: Value::Null,
                security: vec![json!({"apiKeyCookie":[],"bearerAuth":[]})],
                servers: Vec::new(),
                tags: vec![
                    json!({"name":"Default","description":"Default endpoints that are included with Better Auth by default. These endpoints are not part of any plugin."}),
                ],
                paths: IndexMap::new(),
            },
            used_ids: HashSet::new(),
            models: Map::new(),
            user_input: Map::new(),
            user_required: Vec::new(),
        }
    }

    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.spec.info.description = Some(description.into());
        self
    }

    pub fn base_url(mut self, base_url: &str) -> Self {
        self.spec.servers = vec![json!({"url":base_url})];
        self
    }

    pub fn user_input(self, fields: UserConfig) -> Self {
        let mut properties = Map::new();
        let mut required = Vec::new();
        for (name, field) in fields.fields() {
            if !field.input() {
                continue;
            }
            let _ = properties.insert(name.clone(), super::field_schema::input_property(field));
            if field.required == Some(true)
                && field.default_value.is_none()
                && field.default_value_fn.is_none()
            {
                required.push(name.clone());
            }
        }
        self.user_input_properties(properties, required)
    }

    pub fn user_input_properties(
        mut self,
        properties: Map<String, Value>,
        required: Vec<String>,
    ) -> Self {
        self.user_input = properties;
        self.user_required = required;
        self
    }

    pub fn model(self, logical_name: &str, fields: &UserConfig) -> Self {
        let mut properties = Map::new();
        let mut required = Vec::new();
        for (name, field) in fields.fields() {
            let _ = properties.insert(name.clone(), super::field_schema::component_property(field));
            if field.required == Some(true) && field.returned() && !required.contains(name) {
                required.push(name.clone());
            }
        }
        self.model_properties(logical_name, properties, required)
    }

    pub fn model_properties(
        mut self,
        logical_name: &str,
        fields: Map<String, Value>,
        required_fields: Vec<String>,
    ) -> Self {
        let mut properties =
            Map::from_iter([("id".into(), json!({"type":"string","readOnly":true}))]);
        properties.extend(fields);
        let mut required = vec!["id".to_owned()];
        for name in required_fields {
            if !required.contains(&name) {
                required.push(name);
            }
        }
        let name = capitalize(logical_name);
        let _ = self.models.insert(
            name,
            json!({"type":"object","properties":properties,"required":required}),
        );
        self
    }

    pub fn documented_route(
        mut self,
        method: &HttpMethod,
        path: &str,
        plugin: Option<&str>,
        metadata: &OpenApiRouteMetadata,
    ) -> Self {
        let method_name = match method {
            HttpMethod::Get => "get",
            HttpMethod::Delete => "delete",
            HttpMethod::Post => "post",
            HttpMethod::Put => "put",
            HttpMethod::Patch => "patch",
            HttpMethod::Options | HttpMethod::Head => return self,
        };
        if metadata.server_only {
            return self;
        }
        let tags = match plugin {
            None => std::iter::once("Default".to_owned())
                .chain(metadata.tags.clone().unwrap_or_default())
                .collect(),
            Some(plugin) => metadata
                .tags
                .clone()
                .unwrap_or_else(|| vec![capitalize(plugin)]),
        };
        let mut parameters = metadata.parameters.clone().unwrap_or_default();
        for parameter in path.split('/').filter_map(|segment| {
            segment.strip_prefix(':').or_else(|| {
                segment
                    .strip_prefix('{')
                    .and_then(|segment| segment.strip_suffix('}'))
            })
        }) {
            if !parameters.iter().any(|value| {
                value.get("in").and_then(Value::as_str) == Some("path")
                    && value.get("name").and_then(Value::as_str) == Some(parameter)
            }) {
                parameters.push(json!({"name":parameter,"in":"path","required":true,"schema":{"type":"string"}}));
            }
        }
        let mut operation = Map::from_iter([("tags".into(), json!(tags))]);
        if let Some(description) = &metadata.description {
            let _ = operation.insert("description".into(), json!(description));
        }
        if let Some(id) = metadata.operation_id.as_deref().filter(|id| !id.is_empty()) {
            let _ = operation.insert(
                "operationId".into(),
                json!(self.operation_id(id, method_name)),
            );
        }
        let _ = operation.insert("security".into(), json!([{"bearerAuth":[]}]));
        let _ = operation.insert("parameters".into(), json!(parameters));
        if matches!(
            method,
            HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch
        ) {
            let mut body = metadata.request_body.clone();
            if plugin.is_none() {
                body = self.apply_user_input(path, body);
                if body.is_none() {
                    body = Some(
                        json!({"content":{"application/json":{"schema":{"type":"object","properties":{}}}}}),
                    );
                }
            }
            if let Some(body) = body {
                let _ = operation.insert("requestBody".into(), body);
            }
        }
        let _ = operation.insert("responses".into(), responses(&metadata.responses));
        let path = path
            .split('/')
            .map(|segment| {
                segment
                    .strip_prefix(':')
                    .map_or_else(|| segment.to_owned(), |name| format!("{{{name}}}"))
            })
            .collect::<Vec<_>>()
            .join("/");
        let _ = self
            .spec
            .paths
            .entry(path)
            .or_default()
            .insert(method_name.into(), Value::Object(operation));
        self
    }

    fn operation_id(&mut self, id: &str, method: &str) -> String {
        if self.used_ids.insert(id.to_owned()) {
            return id.to_owned();
        }
        let prefix = format!("{id}{}", capitalize(method));
        let mut candidate = prefix.clone();
        let mut suffix = 2;
        while !self.used_ids.insert(candidate.clone()) {
            candidate = format!("{prefix}{suffix}");
            suffix += 1;
        }
        candidate
    }

    fn apply_user_input(&self, path: &str, body: Option<Value>) -> Option<Value> {
        if !matches!(path, "/sign-up/email" | "/update-user") {
            return body;
        }
        if self.user_input.is_empty() {
            return body;
        }
        let body = body.unwrap_or_else(|| json!({}));
        let mut schema = body
            .pointer("/content/application~1json/schema")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let mut body = body.as_object().cloned().unwrap_or_default();
        if schema.get("type").is_none_or(Value::is_null) {
            let _ = schema.insert("type".into(), json!("object"));
        }
        let mut properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let mut required = schema
            .get("required")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for (name, field) in &self.user_input {
            let _ = properties
                .entry(name.clone())
                .or_insert_with(|| field.clone());
        }
        if path == "/sign-up/email" {
            for name in &self.user_required {
                let name = json!(name);
                if !required.contains(&name) {
                    required.push(name);
                }
            }
        }
        let _ = schema.insert("properties".into(), json!(properties));
        if !required.is_empty() {
            let _ = schema.insert("required".into(), json!(required));
        }
        let _ = body.insert(
            "content".into(),
            json!({"application/json":{"schema":schema}}),
        );
        Some(Value::Object(body))
    }

    pub fn build(mut self) -> OpenApiSpec {
        self.spec.components = json!({
            "schemas": self.models,
            "securitySchemes": {
                "apiKeyCookie": {"type":"apiKey","in":"cookie","name":"apiKeyCookie","description":"API Key authentication via cookie"},
                "bearerAuth": {"type":"http","scheme":"bearer","description":"Bearer token authentication"},
            },
        });
        self.spec
    }
}

fn capitalize(value: &str) -> String {
    let mut chars = value.chars();
    chars.next().map_or_else(String::new, |first| {
        if first.len_utf16() == 2 {
            value.to_owned()
        } else {
            first.to_uppercase().chain(chars).collect()
        }
    })
}

fn responses(explicit: &Map<String, Value>) -> Value {
    let mut responses = Map::new();
    for (status, description, required) in [
        (
            "400",
            "Bad Request. Usually due to missing parameters, or invalid parameters.",
            true,
        ),
        (
            "401",
            "Unauthorized. Due to missing or invalid authentication.",
            true,
        ),
        (
            "403",
            "Forbidden. You do not have permission to access this resource or to perform this action.",
            false,
        ),
        (
            "404",
            "Not Found. The requested resource was not found.",
            false,
        ),
        (
            "429",
            "Too Many Requests. You have exceeded the rate limit. Try again later.",
            false,
        ),
        (
            "500",
            "Internal Server Error. This is a problem with the server that you cannot fix.",
            false,
        ),
    ] {
        let mut schema = Map::from_iter([
            ("type".into(), json!("object")),
            ("properties".into(), json!({"message":{"type":"string"}})),
        ]);
        if required {
            let _ = schema.insert("required".into(), json!(["message"]));
        }
        let _ = responses.insert(
            status.into(),
            json!({"content":{"application/json":{"schema":schema}},"description":description}),
        );
    }
    responses.extend(explicit.clone());
    Value::Object(responses)
}

impl OpenApiSpec {
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
    pub fn to_value(&self) -> serde_json::Result<Value> {
        serde_json::to_value(self)
    }
}
