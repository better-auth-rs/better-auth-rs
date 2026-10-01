use super::SessionManager;
use crate::{AuthRequest, AuthResponse, AuthResult, AuthSchema};

impl<S: AuthSchema> SessionManager<S> {
    /// Finalize session cookies and Bearer response headers.
    pub fn finish_response(
        &self,
        req: &AuthRequest,
        response: &mut AuthResponse,
    ) -> AuthResult<()> {
        let endpoint_headers = std::mem::take(&mut response.headers);
        response.headers = req.take_response_headers()?;
        response.headers.merge(endpoint_headers);
        let session_cookie = response
            .headers
            .get_all("set-cookie")
            .filter_map(|value| cookie::Cookie::parse(value.as_str()).ok())
            .filter(|cookie| {
                cookie.name()
                    == self
                        .config
                        .auth_cookie("session_token", Default::default())
                        .name
            })
            .last()
            .filter(|cookie| {
                !cookie.value().is_empty()
                    && cookie.max_age().is_none_or(|age| age.whole_seconds() != 0)
            })
            .map(|cookie| cookie.value().to_string());
        if let Some(signed_token) = session_cookie
            && self.config.session.bearer.is_some()
        {
            let signed_token = percent_encoding::percent_decode_str(&signed_token)
                .decode_utf8()
                .map_err(|error| {
                    crate::AuthError::internal(format!("Decoding session cookie: {error}"))
                })?;
            let _ = response
                .headers
                .insert("set-auth-token", signed_token.into_owned());
            let mut exposed: Vec<_> = response
                .headers
                .get("access-control-expose-headers")
                .map(|header| {
                    header
                        .split(',')
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            if !exposed
                .iter()
                .any(|name| name.eq_ignore_ascii_case("set-auth-token"))
            {
                exposed.push("set-auth-token".into());
            }
            let _ = response
                .headers
                .insert("access-control-expose-headers", exposed.join(", "));
        }
        if req.path().ends_with("/get-session") {
            let _ = response.headers.insert("Cache-Control", "no-store");
            let _ = response.headers.insert("Pragma", "no-cache");
        }
        Ok(())
    }
}
