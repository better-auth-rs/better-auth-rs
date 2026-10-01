use super::SessionManager;
use crate::{AuthRequest, AuthResponse, AuthResult, AuthSchema};

impl<S: AuthSchema> SessionManager<S> {
    /// Finalize session cookies and Bearer response headers.
    pub fn finish_response(
        &self,
        req: &AuthRequest,
        response: &mut AuthResponse,
    ) -> AuthResult<()> {
        use crate::utils::cookie_utils::related_cookie_name;
        let cache_name = related_cookie_name(&self.config, "session_data");
        let endpoint_sets_session = response.headers.get_all("set-cookie").any(|value| {
            value.split_once('=').is_some_and(|(name, _)| {
                name == self
                    .config
                    .auth_cookie("session_token", Default::default())
                    .name
            })
        });
        let endpoint_headers = std::mem::take(&mut response.headers);
        // Endpoint rotation or revocation supersedes credentials queued while
        // authenticating the request, including the previous session's cache.
        let pending_headers = req
            .take_response_headers()?
            .into_iter()
            .filter(|(name, value)| {
                !(endpoint_sets_session
                    && name.eq_ignore_ascii_case("set-cookie")
                    && value.split_once('=').is_some_and(|(cookie, _)| {
                        cookie
                            == self
                                .config
                                .auth_cookie("session_token", Default::default())
                                .name
                            || cookie == cache_name
                            || cookie.starts_with(&format!("{cache_name}."))
                    }))
            });
        for (name, value) in pending_headers.chain(endpoint_headers) {
            if name.eq_ignore_ascii_case("set-cookie") {
                response.headers.append(name, value);
            } else {
                let _ = response.headers.insert(name, value);
            }
        }
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
        // Send only the final value for each cookie. A 2FA redirect must never expose
        // an earlier credential cookie that the same response subsequently expires.
        let mut cookies = Vec::<(String, String)>::new();
        for value in response.headers.get_all("set-cookie") {
            let Some((name, _)) = value.split_once('=') else {
                continue;
            };
            cookies.retain(|(existing, _)| existing != name);
            cookies.push((name.to_string(), value.clone()));
        }
        response.headers.remove("set-cookie");
        for (_, value) in cookies {
            response.headers.append("Set-Cookie", value);
        }
        if req.path().ends_with("/get-session") {
            let _ = response.headers.insert("Cache-Control", "no-store");
            let _ = response.headers.insert("Pragma", "no-cache");
        }
        Ok(())
    }
}
