use super::SessionManager;
use crate::entity::AuthSession;
use crate::{AuthRequest, AuthResponse, AuthResult, AuthSchema};

impl<S: AuthSchema> SessionManager<S> {
    /// Finalize session cookies and Bearer response headers.
    pub async fn finish_response(
        &self,
        req: &AuthRequest,
        response: &mut AuthResponse,
    ) -> AuthResult<()> {
        use crate::utils::cookie_utils::{
            create_session_like_cookie, related_cookie_name, sign_cookie_value, verify_cookie_value,
        };
        let cache_name = related_cookie_name(&self.config, "session_data");
        let endpoint_sets_session = response.headers.get_all("set-cookie").any(|value| {
            value
                .split_once('=')
                .is_some_and(|(name, _)| name == self.config.session.cookie_name)
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
                        cookie == self.config.session.cookie_name
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
            .filter(|cookie| cookie.name() == self.config.session.cookie_name)
            .last()
            .filter(|cookie| {
                !cookie.value().is_empty()
                    && cookie.max_age().is_none_or(|age| age.whole_seconds() != 0)
            })
            .map(|cookie| (cookie.value().to_string(), cookie.max_age().is_none()));
        if let Some((signed_token, dont_remember)) = session_cookie {
            let dont_remember_name = related_cookie_name(&self.config, "dont_remember");
            let remember_choice_pending = response.headers.get_all("set-cookie").any(|value| {
                value
                    .split_once('=')
                    .is_some_and(|(name, _)| name == dont_remember_name)
            });
            if dont_remember && !remember_choice_pending {
                response.headers.append(
                    "Set-Cookie",
                    create_session_like_cookie(
                        &dont_remember_name,
                        &sign_cookie_value("true", &self.config.secret),
                        None,
                        &self.config,
                    ),
                );
            }
            let cache_pending = response.headers.get_all("set-cookie").any(|value| {
                value.starts_with(&format!("{cache_name}="))
                    || value.starts_with(&format!("{cache_name}."))
            });
            if !cache_pending
                && self
                    .config
                    .session
                    .cookie_cache
                    .as_ref()
                    .is_some_and(|cache| cache.enabled)
                && let Some(token) = verify_cookie_value(&signed_token, &self.config.secret)
                && let Some(session) = self.database.get_session(&token).await?
                && let Some(user) = self.database.get_user_by_id(&session.user_id()).await?
            {
                let data = crate::session::SessionData {
                    session: crate::wire::SessionView::with_fields(&session, &self.config.session)?,
                    user: crate::wire::UserView::from(&user),
                };
                self.write_cache(req, &data, dont_remember)?;
                for (name, value) in req.take_response_headers()? {
                    response.headers.append(name, value);
                }
            }
            if self.config.session.bearer.is_some() {
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
        }
        // Send only the final value for each cookie. A 2FA redirect must never expose
        // an earlier credential cookie that the same response subsequently expires.
        // An identical repeat stays where it is, as upstream sends it (sign-out expires
        // `session_data` once unconditionally and again as a received cache cookie).
        let mut cookies = Vec::<(String, String)>::new();
        for value in response.headers.get_all("set-cookie") {
            let Some((name, _)) = value.split_once('=') else {
                continue;
            };
            cookies.retain(|(existing, earlier)| existing != name || earlier == value);
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
