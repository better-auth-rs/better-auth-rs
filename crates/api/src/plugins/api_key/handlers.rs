use better_auth_core::{
    AuthContext, AuthResult, CreateApiKey, FieldValue, SchemaValue, UpdateApiKey,
};

use super::ApiKeyPlugin;
use super::types::*;
use crate::plugins::helpers;

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
        let callback_body = serde_json::to_value(body)?;
        let session = self
            .authenticate_api_key(
                super::ApiKeyEndpoint::new(ctx, None, Some("/api-key/create"), &callback_body),
                ctx,
            )
            .await?;
        let validated = super::request::validate_numbers(
            "/api-key/create",
            Some(&callback_body),
            &[
                ("expiresIn", body.expires_in),
                ("remaining", body.remaining),
                ("refillAmount", body.refill_amount),
                ("refillInterval", body.refill_interval),
                ("rateLimitTimeWindow", body.rate_limit_time_window),
                ("rateLimitMax", body.rate_limit_max),
            ],
        )?;
        let body = validated.get::<CreateKeyRequest>().ok_or_else(|| {
            better_auth_core::AuthError::internal(
                "API key body validator returned a different input type",
            )
        })?;
        let config = self.resolve_configuration(body.config_id.as_deref())?;
        let user_id = create_key_actor(
            body,
            config.references,
            session.as_ref().map(|(_, user)| user.id.field_value()),
            false,
        )?;
        create_key_for_user(body, &user_id, self, ctx, None).await
    }

    /// Update a key on behalf of `body.user_id` from trusted server code.
    /// The caller must authorize access before invoking this server-only method.
    pub async fn update_key(
        &self,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
        body: &UpdateKeyRequest,
    ) -> AuthResult<ApiKeyView> {
        let callback_body = serde_json::to_value(body)?;
        let session = self
            .authenticate_api_key(
                super::ApiKeyEndpoint::new(ctx, None, Some("/api-key/update"), &callback_body),
                ctx,
            )
            .await?;
        let validated = super::request::validate_numbers(
            "/api-key/update",
            Some(&callback_body),
            &[
                ("expiresIn", body.expires_in.flatten()),
                ("remaining", body.remaining),
                ("refillAmount", body.refill_amount),
                ("refillInterval", body.refill_interval),
                ("rateLimitTimeWindow", body.rate_limit_time_window),
                ("rateLimitMax", body.rate_limit_max),
            ],
        )?;
        let body = validated.get::<UpdateKeyRequest>().ok_or_else(|| {
            better_auth_core::AuthError::internal(
                "API key body validator returned a different input type",
            )
        })?;
        if let Some((_, user)) = &session
            && body.user_id.as_ref().is_some_and(|user_id| {
                !user_id.is_empty()
                    && !user
                        .id
                        .field_value()
                        .strict_equals(&user_id.as_str().into())
            })
        {
            return Err(super::api_key_error(
                super::ApiKeyErrorCode::UnauthorizedSession,
            ));
        }
        let user_id = session
            .as_ref()
            .map(|(_, user)| user.id.field_value())
            .or_else(|| body.user_id.as_deref().map(Into::into))
            .filter(FieldValue::is_truthy)
            .ok_or_else(|| super::api_key_error(super::ApiKeyErrorCode::UnauthorizedSession))?;
        update_key_for_user(body, &user_id, self, ctx).await
    }
}

pub(super) fn create_key_actor(
    body: &CreateKeyRequest,
    references: super::ApiKeyReferences,
    session_actor: Option<FieldValue>,
    client: bool,
) -> AuthResult<FieldValue> {
    if references == super::ApiKeyReferences::Organization
        && body.organization_id.as_deref().is_none_or(str::is_empty)
    {
        return Err(super::api_key_error(
            super::ApiKeyErrorCode::OrganizationIdRequired,
        ));
    }
    if references == super::ApiKeyReferences::User
        && !client
        && let Some(actor) = &session_actor
        && body
            .user_id
            .as_deref()
            .filter(|id| !id.is_empty())
            .is_some_and(|id| !actor.strict_equals(&id.into()))
    {
        return Err(super::api_key_error(
            super::ApiKeyErrorCode::UnauthorizedSession,
        ));
    }
    session_actor
        .filter(FieldValue::is_truthy)
        .or_else(|| {
            (!client || references == super::ApiKeyReferences::Organization)
                .then_some(body.user_id.as_deref())
                .flatten()
                .map(FieldValue::from)
        })
        .filter(FieldValue::is_truthy)
        .ok_or_else(|| super::api_key_error(super::ApiKeyErrorCode::UnauthorizedSession))
}

pub(super) fn validate_client_create(body: &CreateKeyRequest) -> AuthResult<()> {
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
    Ok(())
}

pub(super) async fn create_key_for_user(
    body: &CreateKeyRequest,
    user_id: &FieldValue,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    request: Option<&better_auth_core::AuthRequest>,
) -> AuthResult<CreateKeyResponse> {
    let config = plugin.resolve_configuration(body.config_id.as_deref())?;
    let reference_id = match config.references {
        super::ApiKeyReferences::User => user_id.clone(),
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
            organization_id.into()
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
        additional_fields: Default::default(),
        reference_id: SchemaValue::from_field(reference_id),
        config_id: config.config_id.clone(),
        name: body.name.clone().into(),
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
            .transpose()?
            .map(|permissions| SchemaValue::Typed(Some(permissions)))
            .unwrap_or_default(),
        metadata: Some(
            body.metadata
                .as_ref()
                .filter(|value| json_truthy(value))
                .unwrap_or(&serde_json::Value::Null)
                .to_string(),
        ),
        enabled: true.into(),
    };
    let api_key = super::storage::create(config, ctx, input.into_adapter_fields()?)
        .await?
        .ok_or_else(|| {
            better_auth_core::AuthError::internal(
                "Cannot read properties of null (reading 'permissions')",
            )
        })?;
    let mut api_key = ApiKeyView::from(&api_key);
    // Upstream returns supplied falsy metadata at creation, but stores null.
    api_key.metadata = better_auth_core::FieldValue::from_json(
        body.metadata.clone().unwrap_or(serde_json::Value::Null),
    )?;
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

fn expiration_date(seconds: Option<f64>) -> AuthResult<Option<better_auth_core::FieldDate>> {
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
    Ok(Some(date.into()))
}

pub(crate) async fn get_key_core(
    id: &str,
    config_id: Option<&str>,
    user_id: impl Into<FieldValue>,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<ApiKeyView> {
    let config = plugin.resolve_configuration(config_id)?;
    let api_key = helpers::get_owned_api_key(ctx, config, id, &user_id.into(), "read").await?;
    plugin.maybe_delete_expired(ctx).await;
    super::metadata::single(ApiKeyView::from(&api_key), config, ctx).await
}

pub(crate) async fn list_keys_core(
    user_id: impl Into<FieldValue>,
    query: &ListKeysQuery,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<ListKeysResponse> {
    let user_id = user_id.into();
    let organization_id = query.organization_id.as_deref().filter(|id| !id.is_empty());
    if let Some(organization_id) = organization_id {
        helpers::require_org_api_key_permission(ctx, &user_id, organization_id, "read").await?;
    }
    let reference_id = query
        .organization_id
        .as_deref()
        .map(FieldValue::from)
        .unwrap_or(user_id);
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
    let sort = query
        .sort_by
        .as_deref()
        .filter(|field| !field.is_empty())
        .map(|field| (field, query.sort_direction.as_deref().unwrap_or("asc")));
    let mut keys = super::storage::list_groups(&configurations, ctx, &reference_id, sort).await?;
    if config_id.is_none() {
        super::storage::deduplicate(&mut keys)?;
    }
    let mut views: Vec<ApiKeyView> = keys
        .iter()
        // Primitive results can consume a deduplication slot, but cannot name an owner.
        .filter_map(FieldValue::as_object)
        .map(|fields| fields.snapshot_fields())
        .collect::<AuthResult<Vec<_>>>()?
        .into_iter()
        .filter(|fields| {
            let key_config_id = SchemaValue::<String>::from_field(
                fields.get("configId").cloned().unwrap_or_default(),
            );
            let key_references = plugin
                .configurations
                .iter()
                .find(|config| super::config_id_matches(&key_config_id, &config.config_id))
                .map(|config| config.references)
                .unwrap_or_default();
            key_references == references
                && fields
                    .get("referenceId")
                    .unwrap_or(&FieldValue::Undefined)
                    .strict_equals(&reference_id)
                && config_id.is_none_or(|id| super::config_id_matches(&key_config_id, id))
        })
        .map(ApiKeyView::from_api_key_fields)
        .collect::<AuthResult<_>>()?;

    let total = views.len();
    if let Some(offset) = query.offset {
        views = views.split_off(offset.min(views.len() as u64) as usize);
    }
    if let Some(limit) = query.limit {
        views.truncate(limit.min(views.len() as u64) as usize);
    }
    plugin.maybe_delete_expired(ctx).await;
    super::metadata::batch(&mut views, &plugin.configurations, ctx).await?;
    Ok(ListKeysResponse {
        api_keys: views,
        total,
        limit: query.limit,
        offset: query.offset,
    })
}

pub(crate) async fn update_key_core(
    body: &UpdateKeyRequest,
    user_id: impl Into<FieldValue>,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<ApiKeyView> {
    let user_id = user_id.into();
    if body
        .user_id
        .as_deref()
        .is_some_and(|id| !id.is_empty() && !user_id.strict_equals(&id.into()))
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
    update_key_for_user(body, &user_id, plugin, ctx).await
}

pub(super) async fn update_key_for_user(
    body: &UpdateKeyRequest,
    user_id: &FieldValue,
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
        name: body.name.clone().map(|value| Some(value).into()),
        enabled: body.enabled.map(Into::into),
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
    super::metadata::single(ApiKeyView::from(&updated), config, ctx).await
}

pub(crate) async fn delete_key_core(
    body: &DeleteKeyRequest,
    user_id: impl Into<FieldValue>,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<serde_json::Value> {
    let config = plugin.resolve_configuration(body.config_id.as_deref())?;
    let api_key =
        helpers::get_owned_api_key(ctx, config, &body.key_id, &user_id.into(), "delete").await?;
    super::storage::delete(config, ctx, &api_key).await?;
    plugin.maybe_delete_expired(ctx).await;
    Ok(serde_json::json!({ "success": true }))
}
