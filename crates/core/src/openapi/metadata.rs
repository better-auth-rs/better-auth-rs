use indexmap::IndexMap;
use serde_json::{Map, Value};

use crate::store::schema::EntityRole;
use crate::{AuthError, AuthResult, AuthRoute, HttpMethod, user_fields::UserConfig};

use super::{
    OpenApiRouteMetadata,
    catalog::{Endpoint, Field, catalog},
};

pub(super) type ModelFields = IndexMap<String, Field>;

/// Ordered documentation for one configured plugin. Field policies are projected without executing callbacks.
#[derive(Clone)]
pub struct OpenApiPluginMetadata {
    pub(super) id: String,
    pub(super) endpoints: Vec<Endpoint>,
    pub(super) models: IndexMap<String, ModelFields>,
    pub(super) registered_field_names: Vec<(EntityRole, String)>,
}

impl OpenApiPluginMetadata {
    /// Select the pinned builtin descriptor or document the supplied custom routes.
    pub fn from_routes(id: impl Into<String>, routes: Vec<AuthRoute>) -> AuthResult<Self> {
        let id = id.into();
        let catalog = catalog()?;
        let core_plugin = matches!(
            id.as_str(),
            "email-password"
                | "session-management"
                | "oauth"
                | "account-management"
                | "password-management"
                | "email-verification"
                | "user-management"
        );
        let builtin = catalog
            .endpoints
            .iter()
            .any(|group| group.id.as_deref() == Some(id.as_str()));
        let mut endpoints = Vec::new();
        if builtin {
            for source in catalog.endpoints(Some(id.as_str())) {
                let Some(path) = source.path.as_deref() else {
                    continue;
                };
                let methods = source.methods()?;
                let mut matching: Vec<_> = routes
                    .iter()
                    .filter(|route| same_path(path, &route.path) && methods.contains(&route.method))
                    .collect();
                let mut endpoint = source.clone();
                if matching.is_empty()
                    && let Some(operation_id) = source.metadata.operation_id.as_deref()
                {
                    matching = routes
                        .iter()
                        .filter(|route| {
                            route.operation_id == operation_id && methods.contains(&route.method)
                        })
                        .collect();
                    if let Some(route) = matching.first() {
                        endpoint.path = Some(route.path.clone());
                    }
                }
                if matching.is_empty() {
                    continue;
                }
                endpoint.document_method_order.retain(|method| {
                    matching
                        .iter()
                        .any(|route| method_name(&route.method) == method)
                });
                endpoints.push(endpoint);
            }
        }
        let teams = routes
            .iter()
            .any(|route| route.path == "/organization/create-team");
        let roles = routes
            .iter()
            .any(|route| route.path == "/organization/create-role");
        for route in routes {
            if builtin && route.openapi.is_none() && route.endpoint_key.is_none() {
                continue;
            }
            if core_plugin && route.openapi.is_none() && route.endpoint_key.is_none() {
                continue;
            }
            let metadata = route.openapi.unwrap_or_else(|| OpenApiRouteMetadata {
                operation_id: Some(route.operation_id.clone()),
                ..Default::default()
            });
            let endpoint = Endpoint {
                key: route.endpoint_key.unwrap_or(route.operation_id),
                path: Some(
                    route
                        .path
                        .split('/')
                        .map(|part| {
                            part.strip_prefix('{')
                                .and_then(|part| part.strip_suffix('}'))
                                .map_or_else(
                                    || part.to_owned(),
                                    |parameter| format!(":{parameter}"),
                                )
                        })
                        .collect::<Vec<_>>()
                        .join("/"),
                ),
                document_method_order: vec![method_name(&route.method).to_owned()],
                metadata,
            };
            if let Some(existing) = endpoints
                .iter_mut()
                .find(|existing| existing.key == endpoint.key)
            {
                if existing.path == endpoint.path {
                    for method in endpoint.document_method_order {
                        if !existing.document_method_order.contains(&method) {
                            existing.document_method_order.push(method);
                        }
                    }
                    existing
                        .document_method_order
                        .sort_by_key(|method| match method.as_str() {
                            "GET" | "DELETE" => 0,
                            _ => 1,
                        });
                    existing.metadata = endpoint.metadata;
                } else {
                    *existing = endpoint;
                }
            } else {
                endpoints.push(endpoint);
            }
        }
        let enabled = |condition: Option<&str>| match condition {
            Some("organization-teams") => teams,
            Some("organization-roles") => roles,
            _ => true,
        };
        let models = catalog
            .models(Some(id.as_str()))
            .iter()
            .filter(|model| enabled(model.condition.as_deref()))
            .map(|model| {
                (
                    model.key.clone(),
                    model
                        .fields
                        .iter()
                        .filter(|field| enabled(field.condition.as_deref()))
                        .map(|field| (field.key.clone(), field.clone()))
                        .collect(),
                )
            })
            .collect();
        Ok(Self {
            id,
            endpoints,
            models,
            registered_field_names: Vec::new(),
        })
    }

    /// Attach successful declarations from this plugin's initialization without replacing policies.
    /// The registry uses these names only to preserve model field insertion order.
    #[doc(hidden)]
    pub fn registered_field_names(mut self, fields: Vec<(EntityRole, String)>) -> Self {
        self.registered_field_names = fields;
        self
    }

    /// Add or replace declared fields. Physical table and column names do not change document names.
    /// Final registered adapter policies replace metadata for the same model field.
    /// This metadata supplies unregistered fields and models without changing runtime policies.
    pub fn model(mut self, name: impl Into<String>, fields: &UserConfig) -> Self {
        let name = name.into();
        let target = self.models.entry(name.clone()).or_default();
        for (key, config) in fields.fields() {
            let _ = target.insert(key.clone(), project_field(key, config, name == "user"));
        }
        self
    }

    pub fn remove_model(mut self, name: &str) -> Self {
        let _ = self.models.shift_remove(name);
        self
    }

    pub fn remove_field(mut self, model: &str, field: &str) -> Self {
        if let Some(fields) = self.models.get_mut(model) {
            let _ = fields.shift_remove(field);
        }
        self
    }

    /// Change a configured builtin default without constructing a runtime value factory.
    pub fn model_default(mut self, model: &str, field: &str, value: Value) -> AuthResult<Self> {
        let property = self
            .models
            .get_mut(model)
            .and_then(|fields| fields.get_mut(field))
            .and_then(|field| field.property.as_object_mut())
            .ok_or_else(|| AuthError::config(format!("OpenAPI field {model}.{field} is absent")))?;
        let _ = property.insert("default".into(), value);
        Ok(self)
    }

    pub(super) fn endpoint_mut(&mut self, key: &str) -> Option<&mut Endpoint> {
        self.endpoints
            .iter_mut()
            .find(|endpoint| endpoint.key == key)
    }
}

pub(super) fn project_field(
    key: &str,
    field: &crate::user_fields::UserFieldConfig,
    user: bool,
) -> Field {
    Field {
        key: key.to_owned(),
        property: super::field_schema::component_property(field),
        required: field.required == Some(true) && field.returned(),
        condition: None,
        input_property: (user && field.input()).then(|| super::field_schema::input_property(field)),
        input_required: user
            && field.input()
            && field.required == Some(true)
            && field.default_value.is_none()
            && field.default_value_fn.is_none(),
    }
}

pub(super) fn model_projection(fields: &ModelFields) -> (Map<String, Value>, Vec<String>) {
    (
        fields
            .iter()
            .map(|(key, field)| (key.clone(), field.property.clone()))
            .collect(),
        fields
            .iter()
            .filter(|(_, field)| field.required)
            .map(|(key, _)| key.clone())
            .collect(),
    )
}

pub(super) fn method_name(method: &HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Post => "POST",
        HttpMethod::Put => "PUT",
        HttpMethod::Delete => "DELETE",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Head => "HEAD",
        HttpMethod::Options => "OPTIONS",
    }
}

fn same_path(left: &str, right: &str) -> bool {
    let normalize = |path: &str| {
        path.split('/')
            .map(|part| {
                if part.starts_with(':') || (part.starts_with('{') && part.ends_with('}')) {
                    ":parameter"
                } else {
                    part
                }
            })
            .collect::<Vec<_>>()
            .join("/")
    };
    normalize(left) == normalize(right)
}
