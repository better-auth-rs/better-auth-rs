use super::*;

impl TwoFactorPlugin {
    pub(super) async fn after_sign_in<S: better_auth_core::AuthSchema>(
        &self,
        req: &AuthRequest,
        response: &mut AuthResponse,
        ctx: &AuthContext<S>,
    ) -> AuthResult<()> {
        if !matches!(
            req.path(),
            "/sign-in/email" | "/sign-in/username" | "/sign-in/phone-number"
        ) {
            return Ok(());
        }
        let Some(data) = req
            .new_session()?
            .filter(|data| data.user_field("twoFactorEnabled").as_bool() == Some(true))
        else {
            return Ok(());
        };
        let fields = data
            .user
            .as_object()
            .ok_or_else(|| AuthError::internal("A two-factor challenge requires a User object"))?;
        let user = better_auth_core::UserView::try_from(fields.clone())?;
        let trusted = inspect_trusted_device(req, &user, ctx).await?;
        for cookie in trusted.set_cookie_headers {
            response.headers.append("Set-Cookie", cookie);
        }
        if trusted.trusted {
            return Ok(());
        }

        delete_session_cookies(req, &ctx.config, true, Some(&mut response.headers))?;
        ctx.database.delete_session(&data.session.token).await?;
        req.clear_new_session()?;
        let challenge = begin_sign_in_challenge(&user, ctx, &mut response.headers).await?;
        response.replace_returned(AuthResponse::json(200, &challenge)?);
        Ok(())
    }
}
