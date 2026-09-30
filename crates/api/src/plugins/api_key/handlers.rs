use std::collections::HashMap;

use better_auth_core::{AuthContext, AuthResult, CreateApiKey, UpdateApiKey};

use super::ApiKeyPlugin;
use super::types::*;
use crate::plugins::helpers;

// ---------------------------------------------------------------------------
// Permissions verification helper (RBAC)
// ---------------------------------------------------------------------------

/// Check whether `key_permissions` (JSON object mapping role->actions) covers
/// all of the `required_permissions`.
///
/// Mirrors the TypeScript `role(apiKeyPermissions).authorize(permissions)`
/// implementation. Required actions must be a subset of the API key's actions
/// for each resource/role.
pub(super) fn check_permissions(key_permissions_json: &str, required: &serde_json::Value) -> bool {
    let required_map = match required.as_object() {
        Some(m) => m,
        None => return false,
    };

    let key_map: HashMap<String, Vec<String>> = match serde_json::from_str(key_permissions_json) {
        Ok(v) => v,
        Err(_) => return false,
    };

    for (resource, requested_actions) in required_map {
        // Look up the allowed actions for this resource
        let allowed_actions = match key_map.get(resource) {
            Some(a) => a,
            // Resource not found in key permissions -> fail (matches TS behavior)
            None => return false,
        };

        // The request value can be:
        // 1. An array of action strings -> all must be allowed (AND)
        // 2. An object { actions: [...], connector: "OR"|"AND" }
        if let Some(actions_array) = requested_actions.as_array() {
            // Simple array -> every requested action must exist in allowed actions
            for action_val in actions_array {
                let action = match action_val.as_str() {
                    Some(s) => s,
                    None => return false,
                };
                if !allowed_actions.iter().any(|a| a == action) {
                    return false;
                }
            }
        } else if let Some(obj) = requested_actions.as_object() {
            // Object form: { actions: [...], connector: "OR" | "AND" }
            let actions = match obj.get("actions").and_then(|v| v.as_array()) {
                Some(a) => a,
                None => return false,
            };
            let connector = obj
                .get("connector")
                .and_then(|v| v.as_str())
                .unwrap_or("AND");

            if connector == "OR" {
                // At least one requested action must be allowed
                let any_allowed = actions.iter().any(|action_val| {
                    action_val
                        .as_str()
                        .is_some_and(|action| allowed_actions.iter().any(|a| a == action))
                });
                if !any_allowed {
                    return false;
                }
            } else {
                // AND (default): every requested action must be allowed
                for action_val in actions {
                    let action = match action_val.as_str() {
                        Some(s) => s,
                        None => return false,
                    };
                    if !allowed_actions.iter().any(|a| a == action) {
                        return false;
                    }
                }
            }
        } else {
            // Invalid format
            return false;
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Core functions -- framework-agnostic business logic
// ---------------------------------------------------------------------------

impl ApiKeyPlugin {
    /// Create a key on behalf of `body.user_id` from trusted server code.
    /// Organization configurations still require the user's organization permission.
    pub async fn create_key(
        &self,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
        body: &CreateKeyRequest,
    ) -> AuthResult<CreateKeyResponse> {
        use validator::Validate as _;
        let callback_body = serde_json::to_value(body)?;
        let session = self
            .authenticate_api_key(
                super::ApiKeyEndpoint::new(ctx, None, Some("/api-key/create"), &callback_body),
                ctx,
            )
            .await?;
        body.validate().map_err(|error| {
            better_auth_core::AuthError::from(better_auth_core::validation_error_response(&error))
        })?;
        let config = self.resolve_configuration(body.config_id.as_deref())?;
        if config.references == super::ApiKeyReferences::User
            && let Some((session, _)) = &session
            && body
                .user_id
                .as_ref()
                .is_some_and(|user_id| !user_id.is_empty() && *user_id != session.user_id)
        {
            return Err(super::api_key_error(
                super::ApiKeyErrorCode::UnauthorizedSession,
            ));
        }
        let user_id = session
            .as_ref()
            .map(|(session, _)| session.user_id.as_str())
            .or(body.user_id.as_deref().filter(|id| !id.is_empty()))
            .ok_or_else(|| super::api_key_error(super::ApiKeyErrorCode::UnauthorizedSession))?;
        create_key_for_user(body, user_id, self, ctx, None).await
    }

    /// Update a key on behalf of `body.user_id` from trusted server code.
    /// The caller must authorize access before invoking this server-only method.
    pub async fn update_key(
        &self,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
        body: &UpdateKeyRequest,
    ) -> AuthResult<ApiKeyView> {
        use validator::Validate as _;
        let callback_body = serde_json::to_value(body)?;
        let session = self
            .authenticate_api_key(
                super::ApiKeyEndpoint::new(ctx, None, Some("/api-key/update"), &callback_body),
                ctx,
            )
            .await?;
        body.validate().map_err(|error| {
            better_auth_core::AuthError::from(better_auth_core::validation_error_response(&error))
        })?;
        if let Some((session, _)) = &session
            && body
                .user_id
                .as_ref()
                .is_some_and(|user_id| !user_id.is_empty() && *user_id != session.user_id)
        {
            return Err(super::api_key_error(
                super::ApiKeyErrorCode::UnauthorizedSession,
            ));
        }
        let user_id = session
            .as_ref()
            .map(|(session, _)| session.user_id.as_str())
            .or(body.user_id.as_deref().filter(|id| !id.is_empty()))
            .ok_or_else(|| super::api_key_error(super::ApiKeyErrorCode::UnauthorizedSession))?;
        update_key_for_user(body, user_id, self, ctx).await
    }
}

pub(crate) async fn create_key_core(
    body: &CreateKeyRequest,
    user_id: impl AsRef<str>,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    request: Option<&better_auth_core::AuthRequest>,
) -> AuthResult<CreateKeyResponse> {
    let _ = plugin.resolve_configuration(body.config_id.as_deref())?;
    if body.refill_amount.is_some()
        || body.refill_interval.is_some()
        || body.rate_limit_max.is_some()
        || body.rate_limit_time_window.is_some()
        || body.rate_limit_enabled.is_some()
        || body.permissions.is_some()
        || body.remaining.is_some()
    {
        return Err(super::api_key_error(
            super::ApiKeyErrorCode::ServerOnlyProperty,
        ));
    }
    if body.user_id.is_some() {
        return Err(super::api_key_error(
            super::ApiKeyErrorCode::UnauthorizedSession,
        ));
    }
    create_key_for_user(body, user_id.as_ref(), plugin, ctx, request).await
}

async fn create_key_for_user(
    body: &CreateKeyRequest,
    user_id: &str,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    request: Option<&better_auth_core::AuthRequest>,
) -> AuthResult<CreateKeyResponse> {
    let config = plugin.resolve_configuration(body.config_id.as_deref())?;
    let reference_id = match config.references {
        super::ApiKeyReferences::User => user_id.to_string(),
        super::ApiKeyReferences::Organization => {
            let organization_id = body
                .organization_id
                .as_deref()
                .filter(|id| !id.is_empty())
                .ok_or_else(|| {
                    super::api_key_error(super::ApiKeyErrorCode::OrganizationIdRequired)
                })?;
            helpers::require_org_api_key_permission(ctx, user_id, organization_id, "create")
                .await?;
            organization_id.to_string()
        }
    };

    ApiKeyPlugin::validate_metadata(config, &body.metadata)?;
    ApiKeyPlugin::validate_refill(
        body.refill_interval.filter(|value| *value != 0.0),
        body.refill_amount.filter(|value| *value != 0.0),
    )?;
    let effective_expires_in = ApiKeyPlugin::validate_expires_in(config, body.expires_in)?;
    ApiKeyPlugin::validate_prefix(config, body.prefix.as_deref())?;
    ApiKeyPlugin::validate_name(config, body.name.as_deref(), true)?;

    plugin.maybe_delete_expired(ctx).await;
    let (full_key, hash) = if let Some(generator) = &config.custom_key_generator {
        let key = generator
            .generate(
                config.key_length,
                body.prefix
                    .as_deref()
                    .filter(|prefix| !prefix.is_empty())
                    .or(config.prefix.as_deref()),
            )
            .await
            .map_err(|error| super::callbacks::callback_error(error, request))?;
        let hash = if config.disable_key_hashing {
            key.clone()
        } else {
            ApiKeyPlugin::hash_key(&key)
        };
        (key, hash)
    } else {
        ApiKeyPlugin::generate_key(config, body.prefix.as_deref())
    };
    let start = config.store_starting_characters.then(|| {
        better_auth_core::ApiKeyStart::prefix(&full_key, config.starting_characters_length)
    });
    let dynamic_permissions = if let Some(callback) = &config.default_permissions_callback {
        let mut callback_body: serde_json::Map<String, serde_json::Value> =
            serde_json::from_value(serde_json::to_value(body)?)?;
        let _ = callback_body.insert("remaining".into(), serde_json::to_value(body.remaining)?);
        let _ = callback_body.insert("expiresIn".into(), serde_json::to_value(body.expires_in)?);
        let callback_body = serde_json::Value::Object(callback_body);
        Some(
            callback
                .permissions(
                    &reference_id,
                    super::ApiKeyEndpoint::new(
                        ctx,
                        request,
                        Some("/api-key/create"),
                        &callback_body,
                    ),
                )
                .await
                .map_err(|error| super::callbacks::callback_error(error, request))?,
        )
    } else {
        None
    };
    let input = CreateApiKey {
        reference_id,
        config_id: config.config_id.clone(),
        name: body.name.clone(),
        prefix: body.prefix.clone().or_else(|| config.prefix.clone()),
        key_hash: hash,
        start,
        expires_at: expiration_date(effective_expires_in)?,
        remaining: body.remaining,
        rate_limit_enabled: body.rate_limit_enabled.unwrap_or(config.rate_limit.enabled),
        rate_limit_time_window: body
            .rate_limit_time_window
            .or(Some(config.rate_limit.time_window)),
        rate_limit_max: body.rate_limit_max.or(Some(config.rate_limit.max_requests)),
        refill_interval: body.refill_interval,
        refill_amount: body.refill_amount,
        permissions: body
            .permissions
            .as_ref()
            .or(dynamic_permissions.as_ref())
            .or(config.default_permissions.as_ref())
            .map(serde_json::to_string)
            .transpose()?,
        metadata: body
            .metadata
            .as_ref()
            .filter(|value| json_truthy(value))
            .map(ToString::to_string),
        enabled: true,
    };
    let api_key = super::storage::create(config, ctx, input).await?;
    let mut api_key = ApiKeyView::from(&api_key);
    // Upstream returns supplied falsy metadata at creation, but stores null.
    api_key.metadata = body.metadata.clone();
    Ok(CreateKeyResponse {
        key: full_key,
        api_key,
    })
}

fn json_truthy(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(value) => *value,
        serde_json::Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        serde_json::Value::String(value) => !value.is_empty(),
        _ => true,
    }
}

fn expiration_date(seconds: Option<f64>) -> AuthResult<Option<String>> {
    let Some(seconds) = seconds.filter(|seconds| *seconds != 0.0) else {
        return Ok(None);
    };
    let milliseconds = seconds * 1000.0;
    if !milliseconds.is_finite() || milliseconds.abs() > i64::MAX as f64 {
        return Err(better_auth_core::AuthError::bad_request(
            "expiresIn is out of range",
        ));
    }
    let duration = chrono::Duration::milliseconds(milliseconds as i64);
    let date = chrono::Utc::now()
        .checked_add_signed(duration)
        .ok_or_else(|| better_auth_core::AuthError::bad_request("expiresIn is out of range"))?;
    Ok(Some(
        date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    ))
}

pub(crate) async fn get_key_core(
    id: &str,
    config_id: Option<&str>,
    user_id: impl AsRef<str>,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<ApiKeyView> {
    let config = plugin.resolve_configuration(config_id)?;
    let api_key = helpers::get_owned_api_key(ctx, config, id, user_id.as_ref(), "read").await?;
    plugin.maybe_delete_expired(ctx).await;
    Ok(ApiKeyView::from(&api_key))
}

pub(crate) async fn list_keys_core(
    user_id: impl AsRef<str>,
    query: &ListKeysQuery,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<ListKeysResponse> {
    let organization_id = query.organization_id.as_deref().filter(|id| !id.is_empty());
    if let Some(organization_id) = organization_id {
        helpers::require_org_api_key_permission(ctx, user_id.as_ref(), organization_id, "read")
            .await?;
    }
    let reference_id = query.organization_id.as_deref().unwrap_or(user_id.as_ref());
    let references = if organization_id.is_some() {
        super::ApiKeyReferences::Organization
    } else {
        super::ApiKeyReferences::User
    };
    let config_id = query.config_id.as_deref().filter(|id| !id.is_empty());
    if config_id.is_some() {
        let _ = plugin.resolve_configuration(config_id)?;
    }

    let configurations = if let Some(id) = config_id {
        vec![plugin.resolve_configuration(Some(id))?]
    } else {
        let mut groups = std::collections::HashSet::new();
        plugin
            .configurations
            .iter()
            .filter(|config| groups.insert(super::storage::group(config)))
            .collect()
    };
    let mut keys = Vec::new();
    for config in configurations {
        let group = super::storage::list(config, ctx, reference_id).await?;
        let mut group_views: Vec<_> = group.iter().map(ApiKeyView::from).collect();
        if let Some(sort_by) = query.sort_by.as_deref() {
            sort_views(&mut group_views, sort_by, query.sort_direction.as_deref());
        }
        let mut group: std::collections::HashMap<_, _> =
            group.into_iter().map(|key| (key.id.clone(), key)).collect();
        keys.extend(
            group_views
                .into_iter()
                .filter_map(|view| group.remove(&view.id)),
        );
    }
    super::storage::deduplicate(&mut keys);
    let mut views: Vec<ApiKeyView> = keys
        .iter()
        .filter(|key| {
            let key_references = plugin
                .configurations
                .iter()
                .find(|config| super::config_id_matches(&key.config_id, &config.config_id))
                .map(|config| config.references)
                .unwrap_or_default();
            key_references == references
                && key.reference_id == reference_id
                && config_id.is_none_or(|id| super::config_id_matches(&key.config_id, id))
        })
        .map(ApiKeyView::from)
        .collect();

    let total = views.len();
    if let Some(offset) = query.offset {
        views = views.split_off(offset.min(views.len()));
    }
    if let Some(limit) = query.limit {
        views.truncate(limit);
    }
    plugin.maybe_delete_expired(ctx).await;
    Ok(ListKeysResponse {
        api_keys: views,
        total,
        limit: query.limit,
        offset: query.offset,
    })
}

fn compare_numbers(left: Option<f64>, right: Option<f64>) -> std::cmp::Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.total_cmp(&right),
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Less,
        (Some(_), None) => std::cmp::Ordering::Greater,
    }
}

fn sort_views(views: &mut [ApiKeyView], sort_by: &str, direction: Option<&str>) {
    views.sort_by(|a, b| {
        let ordering = match sort_by {
            "id" => a.id.cmp(&b.id),
            "name" => a.name.cmp(&b.name),
            "start" => a.start.cmp(&b.start),
            "prefix" => a.prefix.cmp(&b.prefix),
            "referenceId" => a.reference_id.cmp(&b.reference_id),
            "configId" => a.config_id.cmp(&b.config_id),
            "enabled" => a.enabled.cmp(&b.enabled),
            "rateLimitEnabled" => a.rate_limit_enabled.cmp(&b.rate_limit_enabled),
            "createdAt" => a.created_at.cmp(&b.created_at),
            "updatedAt" => a.updated_at.cmp(&b.updated_at),
            "expiresAt" => a.expires_at.cmp(&b.expires_at),
            "lastRequest" => a.last_request.cmp(&b.last_request),
            "lastRefillAt" => a.last_refill_at.cmp(&b.last_refill_at),
            "remaining" => compare_numbers(a.remaining, b.remaining),
            "requestCount" => compare_numbers(a.request_count, b.request_count),
            "rateLimitMax" => compare_numbers(a.rate_limit_max, b.rate_limit_max),
            "rateLimitTimeWindow" => {
                compare_numbers(a.rate_limit_time_window, b.rate_limit_time_window)
            }
            "refillAmount" => compare_numbers(a.refill_amount, b.refill_amount),
            "refillInterval" => compare_numbers(a.refill_interval, b.refill_interval),
            _ => std::cmp::Ordering::Equal,
        };
        if direction == Some("desc") {
            ordering.reverse()
        } else {
            ordering
        }
    });
}

pub(crate) async fn update_key_core(
    body: &UpdateKeyRequest,
    user_id: impl AsRef<str>,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<ApiKeyView> {
    if body
        .user_id
        .as_deref()
        .is_some_and(|id| !id.is_empty() && id != user_id.as_ref())
    {
        return Err(super::api_key_error(
            super::ApiKeyErrorCode::UnauthorizedSession,
        ));
    }
    if body.refill_amount.is_some()
        || body.refill_interval.is_some()
        || body.rate_limit_max.is_some()
        || body.rate_limit_time_window.is_some()
        || body.rate_limit_enabled.is_some()
        || body.remaining.is_some()
        || body.permissions.is_some()
    {
        return Err(super::api_key_error(
            super::ApiKeyErrorCode::ServerOnlyProperty,
        ));
    }
    update_key_for_user(body, user_id.as_ref(), plugin, ctx).await
}

async fn update_key_for_user(
    body: &UpdateKeyRequest,
    user_id: &str,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<ApiKeyView> {
    let config = plugin.resolve_configuration(body.config_id.as_deref())?;
    let api_key = helpers::get_owned_api_key(ctx, config, &body.key_id, user_id, "update").await?;
    ApiKeyPlugin::validate_name(config, body.name.as_deref(), false)?;

    let expires_at = match body.expires_in {
        None => None,
        Some(_) if config.key_expiration.disable_custom_expires_time => {
            return Err(super::api_key_error(
                super::ApiKeyErrorCode::KeyDisabledExpiration,
            ));
        }
        Some(None) => Some(None),
        Some(Some(seconds)) => {
            let validated = ApiKeyPlugin::validate_expires_in(config, Some(seconds))?;
            Some(expiration_date(validated)?)
        }
    };
    let metadata = body.metadata.as_ref().filter(|_| config.enable_metadata);
    if let Some(metadata) = metadata
        && !(metadata.is_null() || metadata.is_object() || metadata.is_array())
    {
        return Err(super::api_key_error(
            super::ApiKeyErrorCode::InvalidMetadataType,
        ));
    }
    ApiKeyPlugin::validate_refill(body.refill_interval, body.refill_amount)?;
    if body.name.is_none()
        && body.enabled.is_none()
        && expires_at.is_none()
        && metadata.is_none()
        && body.remaining.is_none()
        && body.refill_amount.is_none()
        && body.refill_interval.is_none()
        && body.rate_limit_enabled.is_none()
        && body.rate_limit_time_window.is_none()
        && body.rate_limit_max.is_none()
        && body.permissions.is_none()
    {
        return Err(super::api_key_error(
            super::ApiKeyErrorCode::NoValuesToUpdate,
        ));
    }
    let update = UpdateApiKey {
        name: body.name.clone(),
        enabled: body.enabled,
        remaining: body.remaining,
        rate_limit_enabled: body.rate_limit_enabled,
        rate_limit_time_window: body.rate_limit_time_window,
        rate_limit_max: body.rate_limit_max,
        refill_interval: body.refill_interval,
        refill_amount: body.refill_amount,
        permissions: body
            .permissions
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?,
        metadata: metadata.map(ToString::to_string),
        expires_at,
        ..Default::default()
    };
    let updated = super::storage::update(config, ctx, api_key, update).await?;
    plugin.maybe_delete_expired(ctx).await;
    Ok(ApiKeyView::from(&updated))
}

pub(crate) async fn delete_key_core(
    body: &DeleteKeyRequest,
    user_id: impl AsRef<str>,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<serde_json::Value> {
    let config = plugin.resolve_configuration(body.config_id.as_deref())?;
    let api_key =
        helpers::get_owned_api_key(ctx, config, &body.key_id, user_id.as_ref(), "delete").await?;
    super::storage::delete(config, ctx, &api_key).await?;
    plugin.maybe_delete_expired(ctx).await;
    Ok(serde_json::json!({ "success": true }))
}
