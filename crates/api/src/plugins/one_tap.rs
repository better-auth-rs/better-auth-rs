//! Google One Tap sign-in with verified Google ID tokens.

use better_auth_core::{AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema};
use serde_json::Value;

use super::{
    json_body,
    oauth::{OAuthConfig, OAuthProvider, OAuthTokenSet, OAuthUserInfo},
};

/// Google One Tap options.
#[derive(Clone, better_auth_core::PluginConfig)]
#[plugin(name = "OneTapPlugin")]
pub struct OneTapConfig {
    /// Accepted client IDs; defaults to the Google OAuth provider client ID.
    #[config(default = None)]
    pub client_id: Option<Vec<String>>,
    /// Reject registration of new accounts.
    #[config(default = false)]
    pub disable_signup: bool,
    /// Google public key endpoint. Override only with a trusted Google key mirror.
    #[config(default = "https://www.googleapis.com/oauth2/v3/certs".to_owned())]
    pub google_jwks_url: String,
}

/// Verify Google ID tokens and use the shared OAuth account-linking flow.
pub struct OneTapPlugin {
    config: OneTapConfig,
}

better_auth_core::impl_auth_plugin! {
    OneTapPlugin, "one-tap";
    routes { post "/one-tap/callback" => callback, "oneTapCallback", body = request_body; }
}

impl OneTapPlugin {
    async fn callback<S: AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let body = match req.validated_body::<CallbackBody>() {
            Some(body) => body.clone(),
            None => parse_body(req)?.0,
        };
        let token = body.id_token.as_str();
        if let Some(callback) = body.callback_url.as_deref() {
            super::oauth::validate_redirect_target(callback, ctx, "Invalid callbackURL")?;
        }
        let provider = ctx
            .extensions
            .get::<OAuthConfig>()
            .and_then(|config| config.providers.get("google"));
        let audience = self.config.client_id.clone().unwrap_or_else(|| {
            provider
                .filter(|provider| !provider.client_id.is_empty())
                .map(|provider| vec![provider.client_id.clone()])
                .unwrap_or_default()
        });
        let Some(first_audience) = audience.first() else {
            return Err(AuthError::bad_request(
                "Google client ID is required for One Tap. Set it on the oneTap plugin (clientId) or on socialProviders.google.",
            ));
        };
        let payload =
            super::oauth::google::verify(token, &audience, None, &self.config.google_jwks_url)
                .await
                .ok_or_else(|| AuthError::bad_request("invalid id token"))?
                .into_value();
        let claim = |name| payload.get(name).unwrap_or(&Value::Null);
        if !json_body::is_truthy(claim("sub")) {
            return Err(AuthError::bad_request("invalid id token"));
        }
        let hosted_domain = provider
            .and_then(|provider| {
                provider
                    .authorization_params
                    .iter()
                    .find(|(name, _)| name == "hd")
                    .map(|(_, value)| value.as_str())
            })
            .filter(|value| !value.is_empty());
        if !super::oauth::google::hosted_domain_allowed(hosted_domain, &payload) {
            return Err(AuthError::bad_request("invalid id token"));
        }
        let email = claim("email")
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AuthError::bad_request("Email not available in token"))?;
        let Some(subject) = claim("sub").as_str().filter(|value| !value.is_empty()) else {
            return Err(AuthError::bad_request("invalid id token"));
        };
        let user = OAuthUserInfo {
            additional_fields: Default::default(),
            id: subject.to_owned(),
            email: Some(email.to_lowercase()).into(),
            email_verified: Some(
                claim("email_verified").as_bool() == Some(true)
                    || claim("email_verified").as_str() == Some("true"),
            )
            .into(),
            name: Some(claim("name").as_str().unwrap_or_default().to_owned()),
            image: claim("picture")
                .as_str()
                .map(|value| Some(value.to_owned())),
        };
        let fallback = OAuthProvider::google(first_audience, "");
        let provider = provider.unwrap_or(&fallback);
        super::oauth::sign_in_verified_profile(
            "google",
            provider,
            super::oauth::OAuthUserInfoResponse {
                user,
                data: payload,
            },
            OAuthTokenSet {
                id_token: Some(token.to_owned()),
                scopes: vec!["openid".into(), "profile".into(), "email".into()],
                ..Default::default()
            },
            self.config.disable_signup || provider.disable_sign_up(),
            req,
            ctx,
        )
        .await
    }
}

#[derive(Clone, serde::Deserialize)]
struct CallbackBody {
    #[serde(rename = "idToken")]
    id_token: String,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
}
fn parse_body(req: &AuthRequest) -> AuthResult<(CallbackBody, Value)> {
    json_body::string_input(req, &[("idToken", true), ("callbackURL", false)])
}
fn request_body(req: &AuthRequest) -> AuthResult<better_auth_core::endpoint_input::ValidatedBody> {
    let (body, projection) = parse_body(req)?;
    Ok(better_auth_core::endpoint_input::ValidatedBody::new(
        Some(projection),
        body,
    ))
}
