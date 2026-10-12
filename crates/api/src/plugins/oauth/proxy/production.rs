use super::{OAuthProxyPlugin, handlers};
use crate::plugins::{json_body, symmetric};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema, FieldMap,
    FieldValue,
    observability::LogArgument,
    utils::{defu::defu, json::parse_client_json},
};

impl OAuthProxyPlugin {
    pub(super) async fn production_callback<S: AuthSchema>(
        &self,
        provider_id: &str,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        let params = defu(&[req.input_query_field_value()?, req.input_field_value()?])?;
        let state = params.model_property("state")?;
        if !state.is_truthy() || !state.is_string() {
            return Ok(None);
        }
        let package = match self.decrypt_state(&state, ctx) {
            Ok(package) => package,
            Err(_) => {
                ctx.logger().debug("OAuth proxy: could not decrypt state package, falling back to regular callback", &[])?;
                return Ok(None);
            }
        };
        if !package.model_property("isOAuthProxy")?.is_truthy()
            || !package.model_property("state")?.is_truthy()
            || !package.model_property("stateCookie")?.is_truthy()
        {
            ctx.logger()
                .warn("Invalid OAuth proxy state package", &[])?;
            return Ok(None);
        }
        let params = match callback_params(&params)? {
            Ok(params) => params,
            Err(error) => {
                ctx.logger().warn(
                    "Invalid OAuth callback query",
                    &[LogArgument::Error(&error)],
                )?;
                return Ok(None);
            }
        };
        let state = match self.decrypt_state(&package.model_property("stateCookie")?, ctx) {
            Ok(state) => state,
            Err(error) => {
                ctx.logger().error(
                    "Failed to decrypt OAuth proxy state cookie:",
                    &[LogArgument::Error(&error)],
                )?;
                return Ok(None);
            }
        };
        let error_url = state.model_property("errorURL")?;
        let error_url = if error_url.is_truthy() {
            error_url
        } else {
            ctx.config
                .api_error
                .error_url
                .clone()
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| format!("{}/error", handlers::auth_base_url(ctx)))
                .into()
        };
        if !state.model_property("oauthState")?.is_undefined()
            && !state
                .model_property("oauthState")?
                .strict_equals(&package.model_property("state")?)
        {
            ctx.logger()
                .error("OAuth proxy state binding mismatch", &[])?;
            return Err(redirect_error(req, &error_url, "state_mismatch")?);
        }
        let error = params.model_property("error")?;
        if error.is_truthy() {
            let error = super::super::providers::token_http::form_string(&error)?;
            return Err(redirect_error(req, &error_url, &error)?);
        }
        let code = params.model_property("code")?;
        if !code.is_truthy() {
            ctx.logger()
                .warn("OAuth callback missing authorization code", &[])?;
            return Err(redirect_error(req, &error_url, "no_code")?);
        }
        let Some(provider) = ctx
            .extensions
            .get::<std::sync::Arc<super::super::resolved::ResolvedOAuthConfig>>()
            .and_then(|config| config.providers.get(provider_id))
        else {
            let argument = FieldMap::from([("providerId".into(), provider_id.into())]).into();
            ctx.logger().warn(
                "OAuth provider not found",
                &[LogArgument::Native(&argument)],
            )?;
            return Err(redirect_error(req, &error_url, "oauth_provider_not_found")?);
        };
        let tokens = match async {
            let input = FieldMap::from([
                ("code".into(), code),
                ("codeVerifier".into(), state.model_property("codeVerifier")?),
                (
                    "redirectURI".into(),
                    format!("{}/callback/{provider_id}", handlers::auth_base_url(ctx)).into(),
                ),
            ])
            .into();
            super::super::provider_tokens::validate_authorization_code_native_via_provider(
                provider, &input,
            )
            .await
        }
        .await
        {
            Ok(tokens) => tokens,
            Err(error) => {
                ctx.logger().error(
                    "Failed to validate authorization code",
                    &[LogArgument::Error(&error)],
                )?;
                return Err(redirect_error(req, &error_url, "invalid_code")?);
            }
        };
        if !tokens.is_truthy() {
            return Err(redirect_error(req, &error_url, "invalid_code")?);
        }
        let info = handlers::fetch_user_info_for_code(
            provider,
            handlers::callback_user_request(&tokens, &params.model_property("user")?, None)?,
            None,
        )
        .await?;
        let user = if info.value.is_null() || info.value.is_undefined() {
            FieldValue::Undefined
        } else {
            info.value.model_property("user")?
        };
        if !user.is_truthy() {
            ctx.logger()
                .error("Unable to get user info from provider", &[])?;
            return Err(redirect_error(req, &error_url, "unable_to_get_user_info")?);
        }
        if !user.model_property("email")?.is_truthy() {
            ctx.logger().error("Provider did not return email", &[])?;
            return Err(redirect_error(req, &error_url, "email_not_found")?);
        }
        let account_id = match async {
            let data = info.value.model_property("data")?;
            super::super::social_profile::resolve_account_subject(
                provider,
                &tokens,
                &data,
                info.legacy_subject.as_ref(),
            )
            .await
        }
        .await
        {
            Ok(account_id) => account_id,
            Err(error) => {
                let argument = FieldMap::from([
                    ("providerId".into(), provider_id.into()),
                    ("error".into(), error.into_thrown_value()?),
                ])
                .into();
                ctx.logger().error(
                    "Unable to derive provider account identity",
                    &[LogArgument::Native(&argument)],
                )?;
                return Err(redirect_error(req, &error_url, "unable_to_get_user_info")?);
            }
        };
        let profile = info.value.model_property("data")?;
        let callback_url = state.model_property("callbackURL")?;
        let mut callback = url::Url::parse(&super::super::providers::token_http::form_string(
            &callback_url,
        )?)
        .map_err(|_| AuthError::type_error("Invalid URL"))?;
        let final_url = callback
            .query_pairs()
            .find(|(name, _)| name == "callbackURL")
            .map(|(_, value)| value.into_owned())
            .filter(|value| !value.is_empty())
            .map(FieldValue::from)
            .unwrap_or(callback_url);
        let email = user.model_property("email")?;
        let name = user.model_property("name")?;
        let user_info = FieldMap::from([
            ("id".into(), account_id.clone()),
            ("email".into(), email),
            (
                "name".into(),
                if name.is_truthy() { name } else { "".into() },
            ),
            ("image".into(), user.model_property("image")?),
            (
                "emailVerified".into(),
                user.model_property("emailVerified")?,
            ),
        ])
        .into();
        let scopes = tokens.model_property("scopes")?;
        let account = FieldMap::from([
            ("providerId".into(), provider_id.into()),
            ("accountId".into(), account_id),
            ("accessToken".into(), tokens.model_property("accessToken")?),
            (
                "refreshToken".into(),
                tokens.model_property("refreshToken")?,
            ),
            ("idToken".into(), tokens.model_property("idToken")?),
            (
                "accessTokenExpiresAt".into(),
                tokens.model_property("accessTokenExpiresAt")?,
            ),
            (
                "refreshTokenExpiresAt".into(),
                tokens.model_property("refreshTokenExpiresAt")?,
            ),
            (
                "scope".into(),
                super::super::providers::joined_scopes(&tokens.model_property("scopes")?)?,
            ),
        ])
        .into();
        let state_id = package.model_property("state")?;
        let new_user_url = state.model_property("newUserURL")?;
        let state_error_url = state.model_property("errorURL")?;
        let disable_sign_up = if provider.config.disable_implicit_sign_up()
            && !state.model_property("requestSignUp")?.is_truthy()
        {
            true.into()
        } else {
            provider
                .config
                .disable_sign_up
                .map(FieldValue::from)
                .unwrap_or_default()
        };
        let payload: FieldValue = FieldMap::from([
            ("userInfo".into(), user_info),
            ("profile".into(), profile),
            ("scopes".into(), scopes),
            ("account".into(), account),
            ("state".into(), state_id),
            ("callbackURL".into(), final_url),
            ("newUserURL".into(), new_user_url),
            ("errorURL".into(), state_error_url),
            ("disableSignUp".into(), disable_sign_up),
            (
                "timestamp".into(),
                (chrono::Utc::now().timestamp_millis() as f64).into(),
            ),
        ])
        .into();
        let serialized = payload.stringify()?.ok_or_else(|| {
            AuthError::internal("OAuth proxy payload serialization returned undefined")
        })?;
        let encrypted = symmetric::encrypt(self.encryption_key(ctx), &serialized)?;
        let mut pairs: Vec<(String, String)> = callback
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        if let Some((_, value)) = pairs.iter_mut().find(|(key, _)| key == "profile") {
            *value = encrypted;
            let mut seen = false;
            pairs.retain(|(key, _)| {
                if key != "profile" {
                    return true;
                }
                let keep = !seen;
                seen = true;
                keep
            });
        } else {
            pairs.push(("profile".into(), encrypted));
        }
        let _ = callback.query_pairs_mut().clear().extend_pairs(pairs);
        Err(req.redirect(callback.as_str())?)
    }

    fn decrypt_state<S: AuthSchema>(
        &self,
        value: &FieldValue,
        ctx: &AuthContext<S>,
    ) -> AuthResult<FieldValue> {
        parse_client_json(symmetric::decrypt_field(self.encryption_key(ctx), value)?.into())
    }
}

fn redirect_error(req: &AuthRequest, target: &FieldValue, error: &str) -> AuthResult<AuthError> {
    if !target.is_string() {
        return Err(AuthError::type_error("input.startsWith is not a function"));
    }
    let target = super::super::providers::token_http::form_string(target)?;
    req.redirect(super::error_location(&target, error, None)?)
}

fn callback_params(value: &FieldValue) -> AuthResult<Result<FieldValue, AuthError>> {
    let mut output = FieldMap::new();
    let mut issues = Vec::new();
    for name in ["code", "error", "user"] {
        let field = value.model_property(name)?;
        if field.is_string() || field.is_undefined() && value.has_property(name)? {
            let _ = output.insert(name.into(), field);
        } else if !field.is_undefined() {
            issues.push(serde_json::json!({
                "expected": "string", "code": "invalid_type", "path": [name],
                "message": format!("Invalid input: expected string, received {}", json_body::native_type_name(Some(&field))),
            }));
        }
    }
    if issues.is_empty() {
        return Ok(Ok(output.into()));
    }
    let message = serde_json::to_string_pretty(&issues)?;
    let error = FieldMap::from([
        ("name".into(), "ZodError".into()),
        ("issues".into(), serde_json::Value::Array(issues).into()),
        ("message".into(), message.into()),
    ])
    .into();
    Ok(Err(AuthError::from_thrown(error)))
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]
mod tests {
    use super::*;

    #[test]
    fn callback_schema_retains_present_undefined_without_adding_missing_fields() -> AuthResult<()> {
        let input = FieldMap::from([
            ("state".into(), "state".into()),
            ("user".into(), FieldValue::Undefined),
            ("code".into(), "code".into()),
        ])
        .into();
        let parsed = callback_params(&input)??;
        assert_eq!(
            parsed
                .enumerable_fields()?
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["code", "user"]
        );
        assert!(parsed.has_property("user")?);
        assert!(parsed.model_property("user")?.is_undefined());
        assert!(!parsed.has_property("error")?);
        assert!(!parsed.has_property("state")?);
        Ok(())
    }
}
