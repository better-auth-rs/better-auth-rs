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
    let data = ctx
        .require_native_session(req)
        .await
        .map_err(|error| match error.original() {
            AuthError::Unauthenticated => {
                AuthError::from_code("UNAUTHORIZED", "UNAUTHORIZED", "Unauthorized")
            }
            _ => error,
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
        return Err(AuthError::from_status(
            "BAD_REQUEST",
            FieldMap::from([("message".into(), "No fields to update".into())]).into(),
        ));
    }
    let updated = ctx
        .database
        .update_session_fields_by_token_value(&data.session_property("token")?, fields.clone())
        .await?;
    if updated.is_none() && ctx.store_capabilities().server_sessions() {
        ctx.session_manager().clear_cookies(req)?;
        return Err(AuthError::from_code(
            "UNAUTHORIZED",
            "FAILED_TO_GET_SESSION",
            "Failed to get session",
        ));
    }
    let manager = ctx.session_manager();
    let session = match updated {
        Some(updated) => manager.internal_session_view(&updated).await?,
        None => {
            let mut merged = data.session_value()?.enumerable_fields()?;
            merged.extend(fields);
            let _ = merged.insert(
                "updatedAt".into(),
                better_auth_core::FieldDate::from(chrono::Utc::now()).into(),
            );
            better_auth_core::wire::SessionView::from_field_values(merged)?
        }
    };
    let issued = data.with_session(session)?;
    manager
        .set_native_session_cookie(req, issued.clone(), None)
        .await?;
    Ok(AuthResponse::native(
        None,
        FieldMap::from([(
            "session".into(),
            issued.public_session(&ctx.config.session)?,
        )])
        .into(),
    ))
}

fn field_not_allowed(name: &str) -> AuthResult<AuthResponse> {
    Err(AuthError::from_code(
        "BAD_REQUEST",
        "FIELD_NOT_ALLOWED",
        format!("{name} is not allowed to be set"),
    ))
}
