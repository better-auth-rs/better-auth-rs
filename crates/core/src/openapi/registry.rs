use indexmap::{IndexMap, IndexSet};
use serde_json::{Map, Value};

use crate::{AuthConfig, AuthResult, HttpMethod, user_fields::UserConfig};
use crate::{plugin_runtime::ModelFields as RegisteredFields, store::schema::EntityRole};

use super::{
    OpenApiBuilder, OpenApiPluginMetadata, OpenApiRouteMetadata, OpenApiSpec,
    catalog::{Endpoint, catalog},
    metadata::{ModelFields, model_projection, project_field, property_key_order},
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
    /// Build documentation from configured metadata and policies returned by `ModelFields::resolve`.
    /// Registered non-core fields replace metadata through the existing field projection.
    pub fn new(
        adapter_config: &AuthConfig,
        endpoint_user_fields: &UserConfig,
        plugins: impl IntoIterator<Item = OpenApiPluginMetadata>,
        secondary_storage: bool,
        database_rate_limit: bool,
        registered_fields: &RegisteredFields,
    ) -> AuthResult<Self> {
        let catalog = catalog()?;
        let mut models: IndexMap<String, ModelFields> = IndexMap::new();
        let mut declaration_order: IndexMap<String, IndexSet<String>> = IndexMap::new();
        for model in catalog
            .models(None)
            .iter()
            .filter(|model| model.placement.is_none())
        {
            let _ = declaration_order.insert(
                model.key.clone(),
                model.fields.iter().map(|field| field.key.clone()).collect(),
            );
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
            .fields()
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
                declaration_order
                    .entry(model.clone())
                    .or_default()
                    .extend(fields.keys().cloned());
                if model == "user" {
                    input_fields.extend(fields.clone());
                }
                models.entry(model).or_default().extend(fields);
            }
            for (role, fields) in plugin.registered_field_names {
                if let Some(model) = registered_model_name(role) {
                    let _ = models.entry(model.into()).or_default();
                    declaration_order
                        .entry(model.into())
                        .or_default()
                        .extend(fields);
                }
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
        let organization = registered_fields.organization_fields(Default::default());
        for (role, fields) in registered_fields.iter() {
            let (name, fields) = match role {
                EntityRole::Organization => ("organization", &organization.organization),
                EntityRole::Member => ("member", &organization.member),
                EntityRole::Invitation => ("invitation", &organization.invitation),
                EntityRole::Team => ("team", &organization.team),
                EntityRole::OrganizationRole => {
                    ("organizationRole", &organization.organization_role)
                }
                _ => match registered_model_name(role) {
                    Some(name) => (name, fields),
                    None => continue,
                },
            };
            if fields.fields().is_empty() && !models.contains_key(name) {
                continue;
            }
            // Dynamic-role configuration remains present when the model is disabled.
            if role == EntityRole::OrganizationRole && !models.contains_key(name) {
                continue;
            }
            let model = models.entry(name.into()).or_default();
            model.extend(
                fields
                    .fields()
                    .iter()
                    .map(|(key, field)| (key.clone(), project_field(key, field, false))),
            );
            let order = if matches!(
                role,
                EntityRole::Organization
                    | EntityRole::Member
                    | EntityRole::Invitation
                    | EntityRole::Team
                    | EntityRole::OrganizationRole
            ) {
                Some(registered_fields.organization_output_field_names(role, fields))
            } else {
                declaration_order
                    .get(name)
                    .map(|names| names.iter().cloned().collect())
            };
            if let Some(order) = order {
                let position = |name: &str| {
                    order
                        .iter()
                        .position(|field| field == name)
                        .unwrap_or(usize::MAX)
                };
                model.sort_by(|left, _, right, _| position(left).cmp(&position(right)));
            }
        }
        for (key, field) in adapter_config.user.fields() {
            let _ = models
                .entry("user".into())
                .or_default()
                .insert(key.clone(), project_field(key, field, true));
        }
        for (key, field) in adapter_config.session.fields() {
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
                let _ = models.insert(
                    model.key.clone(),
                    model
                        .fields
                        .iter()
                        .map(|field| (field.key.clone(), field.clone()))
                        .collect(),
                );
            }
        }
        for name in ["user", "session", "account", "verification"] {
            if let Some(model) = models.get_mut(name)
                && let Some(order) = declaration_order.get(name)
            {
                model.sort_by(|left, _, right, _| {
                    order
                        .get_index_of(left)
                        .unwrap_or(usize::MAX)
                        .cmp(&order.get_index_of(right).unwrap_or(usize::MAX))
                });
            }
        }
        if secondary_storage && !adapter_config.verification.store_in_database {
            let _ = models.shift_remove("verification");
        }
        input_fields
            .sort_by(|left, _, right, _| property_key_order(left).cmp(&property_key_order(right)));
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

fn registered_model_name(role: EntityRole) -> Option<&'static str> {
    match role {
        EntityRole::User => Some("user"),
        EntityRole::Session => Some("session"),
        EntityRole::Account => Some("account"),
        EntityRole::Verification => Some("verification"),
        EntityRole::ApiKey => Some("apikey"),
        EntityRole::DeviceCode => Some("deviceCode"),
        EntityRole::Passkey => Some("passkey"),
        EntityRole::Jwk => Some("jwks"),
        EntityRole::WalletAddress => Some("walletAddress"),
        EntityRole::Organization
        | EntityRole::Member
        | EntityRole::Invitation
        | EntityRole::Team
        | EntityRole::OrganizationRole
        | EntityRole::TeamMember
        | EntityRole::TwoFactor
        | EntityRole::RateLimit => None,
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
