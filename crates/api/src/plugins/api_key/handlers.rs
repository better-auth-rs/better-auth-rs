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

    // Validations
    plugin.validate_prefix(body.prefix.as_deref())?;
    plugin.validate_name(body.name.as_deref(), true)?;
    plugin.validate_metadata(&body.metadata)?;
    ApiKeyPlugin::validate_refill(body.refill_interval, body.refill_amount)?;

    let effective_expires_in = plugin.validate_expires_in(body.expires_in)?;

    let (full_key, hash, start) = plugin.generate_key(body.prefix.as_deref());

    let expires_at = helpers::expires_in_to_at(effective_expires_in)?;

    let remaining = body.remaining.or(plugin.config.default_remaining);

    let store_start = if plugin.config.store_starting_characters {
        Some(start)
    } else {
        None
    };

    let input = CreateApiKey {
        user_id: user_id.as_ref().to_string(),
        name: body.name.clone(),
        prefix: body.prefix.clone().or_else(|| plugin.config.prefix.clone()),
        key_hash: hash,
        start: store_start,
        expires_at,
        remaining,
        rate_limit_enabled: body
            .rate_limit_enabled
            .unwrap_or(plugin.config.rate_limit.enabled),
        rate_limit_time_window: body
            .rate_limit_time_window
            .or(Some(plugin.config.rate_limit.time_window)),
        rate_limit_max: body
            .rate_limit_max
            .or(Some(plugin.config.rate_limit.max_requests)),
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
    user_id: impl AsRef<str>,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<ApiKeyView> {
    let api_key = helpers::get_owned_api_key(ctx, id, user_id).await?;
    plugin.maybe_delete_expired(ctx).await;
    Ok(ApiKeyView::from(&api_key))
}

pub(crate) async fn list_keys_core(
    user_id: impl AsRef<str>,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Vec<ApiKeyView>> {
    let keys = ctx.database.list_api_keys_by_user(user_id.as_ref()).await?;
    let views: Vec<ApiKeyView> = keys.iter().map(ApiKeyView::from).collect();
    plugin.maybe_delete_expired(ctx).await;
    Ok(views)
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
    plugin.validate_name(body.name.as_deref(), false)?;
    plugin.validate_metadata(&body.metadata)?;

    // Ownership check via shared helper
    let _existing = helpers::get_owned_api_key(ctx, &body.key_id, user_id).await?;

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
        Some(_) if plugin.config.key_expiration.disable_custom_expires_time => {
            return Err(super::api_key_error(
                super::ApiKeyErrorCode::KeyDisabledExpiration,
            ));
        }
        Some(None) => Some(None),
        Some(Some(secs)) => {
            let validated = plugin.validate_expires_in(Some(secs))?;
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
    _plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<serde_json::Value> {
    // Ownership check via shared helper
    let _existing = helpers::get_owned_api_key(ctx, &body.key_id, user_id).await?;

    ctx.database.delete_api_key(&body.key_id).await?;

    Ok(serde_json::json!({ "success": true }))
}
