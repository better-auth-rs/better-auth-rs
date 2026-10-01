use indexmap::IndexMap;
use serde_json::{Map, Value};

use crate::{AuthConfig, AuthResult, HttpMethod, user_fields::UserConfig};

use super::{
    OpenApiBuilder, OpenApiPluginMetadata, OpenApiRouteMetadata, OpenApiSpec,
    catalog::{Endpoint, catalog},
    metadata::{ModelFields, model_projection, project_field},
};

struct Route {
    plugin: Option<String>,
    path: String,
    methods: Vec<HttpMethod>,
    metadata: OpenApiRouteMetadata,
}

/// Immutable documentation for a configured authentication instance.
/// Request-specific base URLs are supplied when the document is generated.
pub struct OpenApiRegistry {
    models: IndexMap<String, ModelFields>,
    input_properties: Map<String, Value>,
    input_required: Vec<String>,
    routes: Vec<Route>,
}

impl OpenApiRegistry {
    pub fn new(
        adapter_config: &AuthConfig,
        endpoint_user_fields: &UserConfig,
        plugins: impl IntoIterator<Item = OpenApiPluginMetadata>,
        secondary_storage: bool,
        database_rate_limit: bool,
    ) -> AuthResult<Self> {
        let catalog = catalog()?;
        let mut models: IndexMap<String, ModelFields> = IndexMap::new();
        for model in catalog
            .models(None)
            .iter()
            .filter(|model| model.placement.is_none())
        {
            if model.condition.as_deref() == Some("verification-database")
                && secondary_storage
                && !adapter_config.verification.store_in_database
            {
                continue;
            }
            let _ = models.insert(
                model.key.clone(),
                model
                    .fields
                    .iter()
                    .map(|field| (field.key.clone(), field.clone()))
                    .collect(),
            );
        }
        let mut input_fields: ModelFields = endpoint_user_fields
            .additional_fields
            .iter()
            .map(|(key, field)| (key.clone(), project_field(key, field, true)))
            .collect();
        let mut routes = Vec::new();
        let disabled = &adapter_config.disabled_paths;
        for endpoint in catalog.endpoints(None) {
            if let Some(route) = prepare_route(endpoint, None, disabled)? {
                routes.push(route);
            }
        }
        for plugin in plugins {
            for (model, fields) in plugin.models {
                if model == "user" {
                    input_fields.extend(fields.clone());
                }
                models.entry(model).or_default().extend(fields);
            }
            if plugin.id == "open-api" {
                continue;
            }
            for endpoint in plugin.endpoints {
                // Core endpoint keys are documented by the unconditional core catalog.
                if catalog
                    .endpoints(None)
                    .iter()
                    .any(|core| core.key == endpoint.key)
                {
                    continue;
                }
                if let Some(route) = prepare_route(&endpoint, Some(&plugin.id), disabled)? {
                    routes.push(route);
                }
            }
        }
        for (key, field) in &adapter_config.user.additional_fields {
            let _ = models
                .entry("user".into())
                .or_default()
                .insert(key.clone(), project_field(key, field, true));
        }
        for (key, field) in &adapter_config.session.additional_fields {
            let _ = models
                .entry("session".into())
                .or_default()
                .insert(key.clone(), project_field(key, field, false));
        }
        for (model, fields) in [
            ("account", &adapter_config.account.additional_fields),
            (
                "verification",
                &adapter_config.verification.additional_fields,
            ),
        ] {
            // Preserve the omitted verification component for secondary-only storage.
            if let Some(model) = models.get_mut(model) {
                model.extend(
                    fields
                        .iter()
                        .map(|(key, field)| (key.clone(), project_field(key, field, false))),
                );
            }
        }
        if database_rate_limit {
            for model in catalog
                .models(None)
                .iter()
                .filter(|model| model.placement.as_deref() == Some("after-plugin-models"))
            {
                models.entry(model.key.clone()).or_default().extend(
                    model
                        .fields
                        .iter()
                        .map(|field| (field.key.clone(), field.clone())),
                );
            }
        }
        let input_properties = input_fields
            .iter()
            .filter_map(|(key, field)| {
                field
                    .input_property
                    .clone()
                    .map(|property| (key.clone(), property))
            })
            .collect();
        let input_required = input_fields
            .iter()
            .filter(|(_, field)| field.input_property.is_some() && field.input_required)
            .map(|(key, _)| key.clone())
            .collect();
        Ok(Self {
            models,
            input_properties,
            input_required,
            routes,
        })
    }

    pub fn generate(&self, base_url: &str) -> OpenApiSpec {
        let mut builder = OpenApiBuilder::new("Better Auth", "1.1.0")
            .description("API Reference for your Better Auth Instance")
            .base_url(base_url)
            .user_input_properties(self.input_properties.clone(), self.input_required.clone());
        for (name, fields) in &self.models {
            let (properties, required) = model_projection(fields);
            builder = builder.model_properties(name, properties, required);
        }
        for route in &self.routes {
            for method in &route.methods {
                builder = builder.documented_route(
                    method,
                    &route.path,
                    route.plugin.as_deref(),
                    &route.metadata,
                );
            }
        }
        builder.build()
    }
}

fn prepare_route(
    endpoint: &Endpoint,
    plugin: Option<&str>,
    disabled: &[String],
) -> AuthResult<Option<Route>> {
    let Some(path) = endpoint.path.as_deref() else {
        return Ok(None);
    };
    if endpoint.metadata.server_only || disabled.iter().any(|disabled| disabled == path) {
        return Ok(None);
    }
    Ok(Some(Route {
        plugin: plugin.map(str::to_owned),
        path: path.to_owned(),
        methods: endpoint.methods()?,
        metadata: endpoint.metadata.clone(),
    }))
}
