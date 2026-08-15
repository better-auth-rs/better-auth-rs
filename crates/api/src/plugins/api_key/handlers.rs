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

pub(crate) async fn create_key_core(
    body: &CreateKeyRequest,
    user_id: impl AsRef<str>,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<CreateKeyResponse> {
    // Reject server-only properties from HTTP clients (matches TS behavior).
    // In the TS implementation, these fields can only be set from the server
    // auth instance; HTTP requests always count as "client" calls.
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

    let config = plugin.resolve_configuration(body.config_id.as_deref())?;

    // Validations
    ApiKeyPlugin::validate_prefix(config, body.prefix.as_deref())?;
    ApiKeyPlugin::validate_name(config, body.name.as_deref(), true)?;
    ApiKeyPlugin::validate_metadata(config, &body.metadata)?;
    ApiKeyPlugin::validate_refill(body.refill_interval, body.refill_amount)?;

    let effective_expires_in = ApiKeyPlugin::validate_expires_in(config, body.expires_in)?;

    // Who the key belongs to: the caller, or the organization they named when
    // this configuration references organizations.
    let reference_id = match config.references {
        super::ApiKeyReferences::User => user_id.as_ref().to_string(),
        super::ApiKeyReferences::Organization => {
            let organization_id = body.organization_id.as_deref().ok_or_else(|| {
                super::api_key_error(super::ApiKeyErrorCode::OrganizationIdRequired)
            })?;
            helpers::require_org_api_key_permission(
                ctx,
                user_id.as_ref(),
                organization_id,
                "create",
            )
            .await?;
            organization_id.to_string()
        }
    };

    let (full_key, hash, start) = ApiKeyPlugin::generate_key(config, body.prefix.as_deref());

    let expires_at = helpers::expires_in_to_at(effective_expires_in)?;

    let remaining = body.remaining.or(config.default_remaining);

    let store_start = if config.store_starting_characters {
        Some(start)
    } else {
        None
    };

    let input = CreateApiKey {
        reference_id,
        config_id: config.config_id.clone(),
        name: body.name.clone(),
        prefix: body.prefix.clone().or_else(|| config.prefix.clone()),
        key_hash: hash,
        start: store_start,
        expires_at,
        remaining,
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
            .map(|v| serde_json::to_string(v).unwrap_or_default()),
        metadata: body
            .metadata
            .as_ref()
            .map(|v| serde_json::to_string(v).unwrap_or_default()),
        enabled: true,
    };

    let api_key = ctx.database.create_api_key(input).await?;

    // Throttled cleanup
    plugin.maybe_delete_expired(ctx).await;

    Ok(CreateKeyResponse {
        key: full_key,
        api_key: ApiKeyView::from(&api_key),
    })
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
    let config = plugin.resolve_configuration(query.config_id.as_deref())?;

    // Organization-referencing configurations list the organization's keys, and
    // only for a member who may read them.
    let reference_id = match config.references {
        super::ApiKeyReferences::User => user_id.as_ref().to_string(),
        super::ApiKeyReferences::Organization => {
            let organization_id = query.organization_id.as_deref().ok_or_else(|| {
                super::api_key_error(super::ApiKeyErrorCode::OrganizationIdRequired)
            })?;
            helpers::require_org_api_key_permission(ctx, user_id.as_ref(), organization_id, "read")
                .await?;
            organization_id.to_string()
        }
    };

    let keys = ctx
        .database
        .list_api_keys_by_reference(&reference_id)
        .await?;
    let mut views: Vec<ApiKeyView> = keys
        .iter()
        .map(ApiKeyView::from)
        .filter(|view| super::config_id_matches(&view.config_id, &config.config_id))
        .collect();

    if let Some(sort_by) = query.sort_by.as_deref() {
        sort_views(&mut views, sort_by, query.sort_direction.as_deref());
    }

    // `total` counts the filtered set, before the window is applied.
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

/// Sort in place by a client-supplied field name, ignoring unknown fields the
/// way a permissive query layer would.
fn sort_views(views: &mut [ApiKeyView], sort_by: &str, direction: Option<&str>) {
    match sort_by {
        "createdAt" => views.sort_by(|a, b| a.created_at.cmp(&b.created_at)),
        "updatedAt" => views.sort_by(|a, b| a.updated_at.cmp(&b.updated_at)),
        "name" => views.sort_by(|a, b| a.name.cmp(&b.name)),
        "expiresAt" => views.sort_by(|a, b| a.expires_at.cmp(&b.expires_at)),
        _ => return,
    }
    if direction == Some("desc") {
        views.reverse();
    }
}

pub(crate) async fn update_key_core(
    body: &UpdateKeyRequest,
    user_id: impl AsRef<str>,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<ApiKeyView> {
    // Reject server-only properties from HTTP clients (matches TS behavior).
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

    // Check that at least one client-allowed field is provided.
    // expires_in is Option<Option<i64>>: None = not sent.
    if body.name.is_none()
        && body.enabled.is_none()
        && body.expires_in.is_none()
        && body.metadata.is_none()
    {
        return Err(super::api_key_error(
            super::ApiKeyErrorCode::NoValuesToUpdate,
        ));
    }

    // Validations
    let config = plugin.resolve_configuration(body.config_id.as_deref())?;
    ApiKeyPlugin::validate_name(config, body.name.as_deref(), false)?;
    ApiKeyPlugin::validate_metadata(config, &body.metadata)?;

    // Ownership check via shared helper
    let _existing =
        helpers::get_owned_api_key(ctx, config, &body.key_id, user_id.as_ref(), "update").await?;

    // Build expires_at from expiresIn:
    //   None         = not sent → don't touch expires_at
    //   Some(None)   = sent as null → clear expires_at
    //   Some(Some(n)) = sent with value → set expires_at
    //
    // TS checks disableCustomExpiresTime before distinguishing null vs
    // value, so any expiresIn (including null) is rejected when custom
    // expiration is disabled.
    let expires_at = match body.expires_in {
        None => None,
        Some(_) if config.key_expiration.disable_custom_expires_time => {
            return Err(super::api_key_error(
                super::ApiKeyErrorCode::KeyDisabledExpiration,
            ));
        }
        Some(None) => Some(None),
        Some(Some(secs)) => {
            let validated = ApiKeyPlugin::validate_expires_in(config, Some(secs))?;
            helpers::expires_in_to_at(validated)?.map(Some)
        }
    };

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
            .map(|v| serde_json::to_string(v).unwrap_or_default()),
        metadata: body
            .metadata
            .as_ref()
            .map(|v| serde_json::to_string(v).unwrap_or_default()),
        expires_at,
        last_request: None,
        request_count: None,
        last_refill_at: None,
    };

    let updated = ctx.database.update_api_key(&body.key_id, update).await?;

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
    // Ownership check via shared helper
    let _existing =
        helpers::get_owned_api_key(ctx, config, &body.key_id, user_id.as_ref(), "delete").await?;

    ctx.database.delete_api_key(&body.key_id).await?;

    Ok(serde_json::json!({ "success": true }))
}
