use super::json_body::is_truthy;
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema, FieldMap,
    FromFieldMap,
};
use serde_json::Value;

#[cfg(test)]
mod native_session_tests;

pub(super) async fn handle(
    req: &AuthRequest,
    ctx: &AuthContext<impl AuthSchema>,
) -> AuthResult<AuthResponse> {
    let body = better_auth_core::endpoint_input::record_input(req)?;
    let mut data = ctx
        .require_native_session(req)
        .await
        .map_err(|error| match error {
            AuthError::Unauthenticated => AuthError::Upstream {
                status: 401,
                code: "UNAUTHORIZED",
                message: "Unauthorized",
            },
            error => error,
        })?;
    // Plugin schemas override application fields in the upstream input schema.
    let protected_fields: Vec<_> = [
        ("organization.enabled", "activeOrganizationId"),
        ("organization.teams_enabled", "activeTeamId"),
        ("admin.enabled", "impersonatedBy"),
    ]
    .into_iter()
    .filter_map(|(plugin, field)| {
        (ctx.get_metadata(plugin).and_then(Value::as_bool) == Some(true)).then_some(field)
    })
    .collect();
    for name in &protected_fields {
        if body.get(*name).is_some_and(is_truthy) {
            return field_not_allowed(name);
        }
    }
    let mut schema = ctx.config.session.field_schema();
    schema
        .fields_mut()
        .retain(|name, _| !protected_fields.contains(&name.as_str()));
    let fields = schema.parse_input(&better_auth_core::FieldMap::from_json(body)?, false)?;
    if fields.is_empty() {
        return Err(AuthResponse::json(
            400,
            &serde_json::json!({ "message": "No fields to update" }),
        )?
        .into());
    }
    let updated = ctx
        .database
        .update_session_fields_by_token_value(&data.session.token.field_value(), fields.clone())
        .await?;
    if updated.is_none() && ctx.store_capabilities().server_sessions() {
        ctx.session_manager().clear_cookies(req)?;
        return Err(AuthError::Upstream {
            status: 401,
            code: "FAILED_TO_GET_SESSION",
            message: "Failed to get session",
        });
    }
    let manager = ctx.session_manager();
    data.session = match updated {
        Some(updated) => manager.internal_session_view(&updated).await?,
        None => {
            let mut merged = FieldMap::from(data.session.clone());
            merged.extend(fields);
            let _ = merged.insert(
                "updatedAt".into(),
                better_auth_core::FieldDate::from(chrono::Utc::now()).into(),
            );
            better_auth_core::wire::SessionView::from_field_values(merged)?
        }
    };
    manager
        .set_native_session_cookie(req, data.clone(), None)
        .await?;
    data.session.filter_returned_fields(&ctx.config.session)?;
    AuthResponse::json(None, &serde_json::json!({ "session": data.session }))
}

fn field_not_allowed(name: &str) -> AuthResult<AuthResponse> {
    Err(AuthResponse::json(
        400,
        &serde_json::json!({
            "code": "FIELD_NOT_ALLOWED", "message": format!("{name} is not allowed to be set"),
        }),
    )?
    .into())
}
