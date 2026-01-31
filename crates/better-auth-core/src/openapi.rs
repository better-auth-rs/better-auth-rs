use serde::Serialize;
use std::collections::BTreeMap;

use crate::plugin::AuthPlugin;
use crate::types::HttpMethod;

/// Minimal OpenAPI 3.1.0 spec builder that collects routes from plugins.
///
/// Produces a JSON document compatible with the OpenAPI 3.1.0 specification.
/// This is intentionally lightweight — it captures paths and methods from
/// registered plugins without requiring schema derives on every type.
#[derive(Debug, Serialize)]
pub struct OpenApiSpec {
    pub openapi: String,
    pub info: OpenApiInfo,
    pub paths: BTreeMap<String, BTreeMap<String, OpenApiOperation>>,
}

#[derive(Debug, Serialize)]
pub struct OpenApiInfo {
    pub title: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpenApiOperation {
    #[serde(rename = "operationId")]
    pub operation_id: String,
    pub summary: String,
    pub tags: Vec<String>,
    pub responses: BTreeMap<String, OpenApiResponse>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpenApiResponse {
    pub description: String,
}

/// Builder for constructing an OpenAPI spec from plugins and core routes.
pub struct OpenApiBuilder {
    title: String,
    version: String,
    description: Option<String>,
    paths: BTreeMap<String, BTreeMap<String, OpenApiOperation>>,
}

impl OpenApiBuilder {
    pub fn new(title: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            version: version.into(),
            description: None,
            paths: BTreeMap::new(),
        }
    }

    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Add a single route entry.
    pub fn route(mut self, method: &HttpMethod, path: &str, operation_id: &str, tag: &str) -> Self {
        let method_str = match method {
            HttpMethod::Get => "get",
            HttpMethod::Post => "post",
            HttpMethod::Put => "put",
            HttpMethod::Delete => "delete",
            HttpMethod::Patch => "patch",
            HttpMethod::Options => "options",
            HttpMethod::Head => "head",
        };

        let operation = OpenApiOperation {
            operation_id: operation_id.to_string(),
            summary: operation_id.replace('_', " "),
            tags: vec![tag.to_string()],
            responses: {
                let mut r = BTreeMap::new();
                r.insert("200".to_string(), OpenApiResponse {
                    description: "Successful response".to_string(),
                });
                r
            },
        };

        self.paths
            .entry(path.to_string())
            .or_default()
            .insert(method_str.to_string(), operation);
        self
    }

    /// Register all routes from a plugin.
    pub fn plugin(mut self, plugin: &dyn AuthPlugin) -> Self {
        let tag = plugin.name();
        for route in plugin.routes() {
            self = self.route(&route.method, &route.path, &route.handler, tag);
        }
        self
    }

    /// Register core routes that are not part of any plugin.
    pub fn core_routes(self) -> Self {
        self.route(&HttpMethod::Get, "/ok", "ok", "core")
            .route(&HttpMethod::Get, "/error", "error", "core")
            .route(&HttpMethod::Post, "/update-user", "update_user", "core")
            .route(&HttpMethod::Post, "/delete-user", "delete_user", "core")
            .route(&HttpMethod::Post, "/change-email", "change_email", "core")
            .route(&HttpMethod::Get, "/delete-user/callback", "delete_user_callback", "core")
    }

    /// Build the final OpenAPI spec.
    pub fn build(self) -> OpenApiSpec {
        OpenApiSpec {
            openapi: "3.1.0".to_string(),
            info: OpenApiInfo {
                title: self.title,
                version: self.version,
                description: self.description,
            },
            paths: self.paths,
        }
    }
}

impl OpenApiSpec {
    /// Serialize the spec to a JSON string.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    /// Serialize the spec to a `serde_json::Value`.
    pub fn to_value(&self) -> serde_json::Result<serde_json::Value> {
        serde_json::to_value(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_core_routes() {
        let spec = OpenApiBuilder::new("Better Auth", "0.1.0")
            .description("Authentication API")
            .core_routes()
            .build();

        assert_eq!(spec.openapi, "3.1.0");
        assert_eq!(spec.info.title, "Better Auth");
        assert!(spec.paths.contains_key("/ok"));
        assert!(spec.paths.contains_key("/error"));
        assert!(spec.paths.contains_key("/update-user"));
        assert!(spec.paths.contains_key("/delete-user"));

        // /ok should have a GET operation
        let ok_path = &spec.paths["/ok"];
        assert!(ok_path.contains_key("get"));
        assert_eq!(ok_path["get"].operation_id, "ok");
    }

    #[test]
    fn test_builder_custom_route() {
        let spec = OpenApiBuilder::new("Test", "1.0.0")
            .route(&HttpMethod::Post, "/sign-in/email", "sign_in_email", "email-password")
            .build();

        let path = &spec.paths["/sign-in/email"];
        assert!(path.contains_key("post"));
        assert_eq!(path["post"].tags, vec!["email-password"]);
    }

    #[test]
    fn test_spec_to_json() {
        let spec = OpenApiBuilder::new("Test", "1.0.0")
            .core_routes()
            .build();

        let json = spec.to_json().unwrap();
        assert!(json.contains("\"openapi\": \"3.1.0\""));
        assert!(json.contains("\"/ok\""));
    }

    #[test]
    fn test_spec_to_value() {
        let spec = OpenApiBuilder::new("Test", "1.0.0")
            .core_routes()
            .build();

        let value = spec.to_value().unwrap();
        assert_eq!(value["openapi"], "3.1.0");
        assert!(value["paths"]["/ok"]["get"]["operationId"].is_string());
    }
}
