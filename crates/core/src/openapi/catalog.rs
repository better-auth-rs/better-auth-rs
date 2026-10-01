use std::sync::OnceLock;

use serde::Deserialize;
use serde_json::Value;

use crate::{AuthError, AuthResult, HttpMethod};

use super::OpenApiRouteMetadata;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Endpoint {
    pub key: String,
    pub path: Option<String>,
    pub document_method_order: Vec<String>,
    pub metadata: OpenApiRouteMetadata,
}

impl Endpoint {
    pub(super) fn methods(&self) -> AuthResult<Vec<HttpMethod>> {
        self.document_method_order
            .iter()
            .map(|method| match method.as_str() {
                "GET" => Ok(HttpMethod::Get),
                "POST" => Ok(HttpMethod::Post),
                "PUT" => Ok(HttpMethod::Put),
                "PATCH" => Ok(HttpMethod::Patch),
                "DELETE" => Ok(HttpMethod::Delete),
                "HEAD" => Ok(HttpMethod::Head),
                "OPTIONS" => Ok(HttpMethod::Options),
                _ => Err(AuthError::config(format!(
                    "Invalid OpenAPI method {method}"
                ))),
            })
            .collect()
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Field {
    pub key: String,
    pub property: Value,
    pub required: bool,
    pub condition: Option<String>,
    pub input_property: Option<Value>,
    #[serde(default)]
    pub input_required: bool,
}

#[derive(Clone, Deserialize)]
pub(super) struct Model {
    pub key: String,
    pub fields: Vec<Field>,
    pub condition: Option<String>,
    pub placement: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct EndpointGroup {
    pub id: Option<String>,
    pub endpoints: Vec<Endpoint>,
}

#[derive(Deserialize)]
pub(super) struct ModelGroup {
    pub id: Option<String>,
    pub models: Vec<Model>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Groups<T> {
    format_version: u32,
    groups: Vec<T>,
}

pub(super) struct Catalog {
    pub endpoints: Vec<EndpointGroup>,
    pub models: Vec<ModelGroup>,
}

impl Catalog {
    pub(super) fn endpoints(&self, id: Option<&str>) -> &[Endpoint] {
        self.endpoints
            .iter()
            .find(|group| group.id.as_deref() == id)
            .map_or(&[], |group| group.endpoints.as_slice())
    }

    pub(super) fn models(&self, id: Option<&str>) -> &[Model] {
        self.models
            .iter()
            .find(|group| group.id.as_deref() == id)
            .map_or(&[], |group| group.models.as_slice())
    }
}

fn parse() -> Result<Catalog, String> {
    let endpoints: Groups<EndpointGroup> =
        serde_json::from_str(include_str!("descriptors/endpoints.json"))
            .map_err(|error| format!("Invalid OpenAPI endpoint catalog: {error}"))?;
    let models: Groups<ModelGroup> = serde_json::from_str(include_str!("descriptors/models.json"))
        .map_err(|error| format!("Invalid OpenAPI model catalog: {error}"))?;
    if endpoints.format_version != 1 || models.format_version != 1 {
        return Err("Unsupported OpenAPI descriptor format".into());
    }
    if !endpoints.groups.iter().any(|group| group.id.is_none())
        || !models.groups.iter().any(|group| group.id.is_none())
    {
        return Err("OpenAPI descriptors omit the core group".into());
    }
    for group in &endpoints.groups {
        for endpoint in &group.endpoints {
            let _ = endpoint.methods().map_err(|error| error.to_string())?;
        }
    }
    Ok(Catalog {
        endpoints: endpoints.groups,
        models: models.groups,
    })
}

pub(super) fn catalog() -> AuthResult<&'static Catalog> {
    static CATALOG: OnceLock<Result<Catalog, String>> = OnceLock::new();
    CATALOG
        .get_or_init(parse)
        .as_ref()
        .map_err(|message| AuthError::config(message.clone()))
}
