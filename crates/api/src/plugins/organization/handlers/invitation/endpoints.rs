use super::*;

pub async fn handle_invite_member(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let session = require_native_session(req, ctx).await?;
    let body: InviteMemberRequest =
        crate::plugins::organization::request::read(req, &config.schema)?;
    let invitation = invite_member_core(&body, &session, config, ctx, Some(req)).await?;
    Ok(AuthResponse::native(
        None,
        invitation.field_values()?.into(),
    ))
}

pub async fn handle_get_invitation(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let session =
        ctx.require_native_session(req)
            .await
            .map_err(|error| match error.original() {
                AuthError::Unauthenticated => AuthError::from_status(
                    "UNAUTHORIZED",
                    better_auth_core::FieldMap::from([(
                        "message".into(),
                        "Not authenticated".into(),
                    )])
                    .into(),
                ),
                _ => error,
            })?;
    let query = crate::plugins::query_input::parse::<GetInvitationQuery>(req)?;
    match get_invitation_core(&query, &session, config, ctx).await? {
        Some(response) => Ok(AuthResponse::native(None, response.field_values()?.into())),
        None => Err(AuthError::from_status(
            "BAD_REQUEST",
            better_auth_core::FieldMap::from([("message".into(), "Invitation not found!".into())])
                .into(),
        )),
    }
}

pub async fn handle_list_invitations(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let _ = require_native_session(req, ctx).await?;
    let session = ctx
        .native_session(req, better_auth_core::session::SessionRead::Cached)
        .await?
        .ok_or_else(|| {
            AuthError::from_status(
                "UNAUTHORIZED",
                better_auth_core::FieldMap::from([("message".into(), "Not authenticated".into())])
                    .into(),
            )
        })?;
    let query = crate::plugins::query_input::parse::<ListInvitationsQuery>(req)?;
    let invitations = list_invitations_core(&query, &session, ctx).await?;
    let invitations = invitations
        .iter()
        .map(|invitation| {
            invitation
                .field_values()
                .map(better_auth_core::FieldValue::from)
        })
        .collect::<AuthResult<Vec<_>>>()?;
    Ok(AuthResponse::native(None, invitations.into()))
}

pub async fn handle_list_user_invitations(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let session = ctx
        .native_session(req, better_auth_core::session::SessionRead::Cached)
        .await?;
    let email = req.query_string("email")?;
    let endpoint = crate::plugins::endpoint_context::EndpointContext::new(
        Some(req),
        better_auth_core::FieldValue::Null,
        ctx,
    );
    if endpoint.request.is_some() && email.as_ref().is_some_and(|email| !email.is_empty()) {
        return Err(AuthError::from_status(
            "BAD_REQUEST",
            better_auth_core::FieldMap::from([(
                "message".into(),
                "User email cannot be passed for client side API calls.".into(),
            )])
            .into(),
        ));
    }
    let invitations = list_user_invitations_core(session.as_ref(), email.as_deref(), ctx).await?;
    let invitations = invitations
        .iter()
        .map(|invitation| {
            invitation
                .field_values()
                .map(better_auth_core::FieldValue::from)
        })
        .collect::<AuthResult<Vec<_>>>()?;
    Ok(AuthResponse::native(None, invitations.into()))
}

pub async fn handle_accept_invitation(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let session = require_native_session(req, ctx).await?;
    let body: AcceptInvitationRequest =
        crate::plugins::organization::request::read(req, &config.schema)?;
    let response = accept_invitation_core(&body, &session, config, ctx, req).await?;
    Ok(AuthResponse::native(None, response.field_values()?.into()))
}

pub async fn handle_reject_invitation(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let session = require_native_session(req, ctx).await?;
    let body: RejectInvitationRequest =
        crate::plugins::organization::request::read(req, &config.schema)?;
    let response = reject_invitation_core(&body, &session, config, ctx).await?;
    Ok(AuthResponse::native(None, response.field_values()?.into()))
}

pub async fn handle_cancel_invitation(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let session = require_native_session(req, ctx).await?;
    let body: CancelInvitationRequest =
        crate::plugins::organization::request::read(req, &config.schema)?;
    let response = cancel_invitation_core(&body, &session, config, ctx)
        .await?
        .as_ref()
        .map(AuthRecordFields::field_values)
        .transpose()?;
    Ok(AuthResponse::native(
        None,
        response.map(FieldValue::from).unwrap_or(FieldValue::Null),
    ))
}
