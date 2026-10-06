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
            .filter(|data| data.user.two_factor_enabled == Some(true))
        else {
            return Ok(());
        };
        let trusted = inspect_trusted_device(req, &data.user, ctx).await?;
        for cookie in trusted.set_cookie_headers {
            response.headers.append("Set-Cookie", cookie);
        }
        if trusted.trusted {
            return Ok(());
        }

        delete_session_cookies(req, &ctx.config, true, Some(&mut response.headers))?;
        ctx.database.delete_session(&data.session.token).await?;
        req.clear_new_session()?;
        let challenge = begin_sign_in_challenge(&data.user, ctx, &mut response.headers).await?;
        response.replace_returned(AuthResponse::json(200, &challenge)?);
        Ok(())
    }
}
