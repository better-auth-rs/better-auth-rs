use super::json_body;
use super::json_body::is_truthy;
use better_auth_core::session::SessionData;
use better_auth_core::utils::cookie_utils::create_session_cookie_with_max_age;
use better_auth_core::{AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema};
use serde_json::Value;

pub(super) async fn handle(
    req: &AuthRequest,
    ctx: &AuthContext<impl AuthSchema>,
) -> AuthResult<AuthResponse> {
    let body = match json_body::parse(req) {
        Ok(body) => body,
        Err(response) => return Ok(response),
    };
    let body = match body {
        Some(Value::Object(body)) => body,
        body => {
            return Ok(json_body::validation_error(&json_body::invalid_type(
                "body",
                "record",
                body.as_ref(),
            )));
        }
    };
    let (user, session) = ctx
        .require_session(req)
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
        .additional_fields
        .retain(|name, _| !protected_fields.contains(&name.as_str()));
    let fields = schema.parse_input(&body, false)?;
    if fields.is_empty() {
        return Ok(AuthResponse::json(
            400,
            &serde_json::json!({ "message": "No fields to update" }),
        )?);
    }
    let Some(updated) = ctx
        .database
        .update_session_fields(&session.token, fields)
        .await?
    else {
        ctx.session_manager().clear_cookies(req)?;
        return Err(AuthError::Upstream {
            status: 401,
            code: "FAILED_TO_GET_SESSION",
            message: "Failed to get session",
        });
    };
    let data = SessionData {
        session: ctx.session_view(&updated).await?,
        user,
    };
    let manager = ctx.session_manager();
    let dont_remember = manager.dont_remember(req);
    req.append_response_header(
        "Set-Cookie",
        create_session_cookie_with_max_age(
            Some(&data.session.token),
            (!dont_remember).then_some(ctx.config.session.expires_in.num_seconds()),
            &ctx.config,
        ),
    )?;
    manager.write_cache(req, &data, dont_remember).await?;
    Ok(AuthResponse::json(
        200,
        &serde_json::json!({ "session": data.session }),
    )?)
}

fn field_not_allowed(name: &str) -> AuthResult<AuthResponse> {
    Ok(AuthResponse::json(
        400,
        &serde_json::json!({
            "code": "FIELD_NOT_ALLOWED", "message": format!("{name} is not allowed to be set"),
        }),
    )?)
}
