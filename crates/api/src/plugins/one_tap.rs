//! Google One Tap sign-in with verified Google ID tokens.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema};
use jsonwebtoken::{Algorithm, DecodingKey, crypto};
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
        let payload = self
            .verify(token, &audience)
            .await
            .ok_or_else(|| AuthError::bad_request("invalid id token"))?;
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
        if let Some(domain) = hosted_domain {
            let token_domain = claim("hd").as_str().filter(|value| !value.is_empty());
            if token_domain.is_none_or(|value| domain != "*" && domain != value) {
                return Err(AuthError::bad_request("invalid id token"));
            }
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
            email: email.to_lowercase(),
            email_verified: claim("email_verified").as_bool() == Some(true)
                || claim("email_verified").as_str() == Some("true"),
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
            self.config.disable_signup || provider.disable_sign_up,
            req,
            ctx,
        )
        .await
    }

    async fn verify(&self, token: &str, audience: &[String]) -> Option<Value> {
        let (signed, signature) = token.rsplit_once('.')?;
        let (protected, payload) = signed.split_once('.')?;
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(protected).ok()?).ok()?;
        if header.get("alg").and_then(Value::as_str) != Some("RS256") {
            return None;
        }
        if let Some(critical) = header.get("crit") {
            let extensions = critical.as_array()?;
            if extensions.is_empty()
                || extensions.iter().any(|value| value.as_str() != Some("b64"))
                || header.get("b64").and_then(Value::as_bool) != Some(true)
            {
                return None;
            }
        }
        let kid = header
            .get("kid")
            .filter(|value| json_body::is_truthy(value));
        let keys: Value = reqwest::Client::new()
            .get(&self.config.google_jwks_url)
            .send()
            .await
            .ok()?
            .error_for_status()
            .ok()?
            .json()
            .await
            .ok()?;
        let keys = keys.get("keys")?.as_array()?;
        let keys = keys
            .iter()
            .filter(|key| kid.is_none_or(|kid| key.get("kid") == Some(kid)))
            .map(import_google_key)
            .collect::<Option<Vec<_>>>()?;
        for (key, modulus_bits) in keys {
            if modulus_bits < 2048 {
                continue;
            }
            if crypto::verify(signature, signed.as_bytes(), &key, Algorithm::RS256).ok()
                != Some(true)
            {
                continue;
            }
            let claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
            return valid_claims(&claims, audience).then_some(claims);
        }
        None
    }
}

fn import_google_key(key: &Value) -> Option<(DecodingKey, usize)> {
    if key.get("kty").and_then(Value::as_str) != Some("RSA")
        || key.get("ext").is_some_and(|value| !value.is_boolean())
        || key.get("d").is_some()
    {
        return None;
    }
    if let Some(operations) = key.get("key_ops") {
        let operations = operations.as_array()?;
        if operations.len() != 1 || operations.first().and_then(Value::as_str) != Some("verify") {
            return None;
        }
    }
    // Google's importJWK(jwk, "RS256") ignores alg/use, but WebCrypto enforces key_ops and ext.
    let modulus = key.get("n")?.as_str()?;
    let exponent = key.get("e")?.as_str()?;
    let bytes = URL_SAFE_NO_PAD.decode(modulus).ok()?;
    let (first, byte) = bytes.iter().enumerate().find(|(_, byte)| **byte != 0)?;
    let modulus_bits = (bytes.len() - first) * 8 - byte.leading_zeros() as usize;
    Some((
        DecodingKey::from_rsa_components(modulus, exponent).ok()?,
        modulus_bits,
    ))
}

// jose accepts fractional NumericDates; jsonwebtoken's JWT decoder rounds these to integers.
fn valid_claims(claims: &Value, audience: &[String]) -> bool {
    if !matches!(
        claims.get("iss").and_then(Value::as_str),
        Some("https://accounts.google.com" | "accounts.google.com")
    ) {
        return false;
    }
    let audience_matches = match claims.get("aud") {
        Some(Value::String(value)) => audience.contains(value),
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .any(|value| audience.iter().any(|expected| expected == value)),
        _ => false,
    };
    if !audience_matches {
        return false;
    }
    let now = chrono::Utc::now().timestamp() as f64;
    let Some(issued) = claims.get("iat").and_then(Value::as_f64) else {
        return false;
    };
    issued <= now
        && now - issued <= 3600.0
        && claims
            .get("exp")
            .is_none_or(|value| value.as_f64().is_some_and(|expiry| expiry > now))
        && claims
            .get("nbf")
            .is_none_or(|value| value.as_f64().is_some_and(|start| start <= now))
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
