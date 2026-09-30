use std::collections::HashMap;
use std::sync::Arc;

use better_auth::plugins::oauth::{
    GenericOAuthConfig, OAuthAccountSubject, OAuthProfile, OAuthProfileMapper,
    OAuthUserInfoRequest, TokenEndpointAuth, TokenEndpointSecretAuthentication,
};
use better_auth::plugins::OAuthPlugin;
use better_auth::{AuthError, AuthResult};
use serde_json::Value;

struct MappedIdentity;

#[async_trait::async_trait]
impl OAuthAccountSubject for MappedIdentity {
    async fn resolve_subject(
        &self,
        _tokens: &OAuthUserInfoRequest,
        profile: &Value,
    ) -> AuthResult<String> {
        profile["external_subject"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| AuthError::bad_request("Missing external subject"))
    }
}

#[async_trait::async_trait]
impl OAuthProfileMapper for MappedIdentity {
    async fn map_profile(&self, profile: &Value) -> AuthResult<OAuthProfile> {
        Ok(OAuthProfile {
            additional_fields: serde_json::from_value(serde_json::json!({"department": "identity", "alias": if profile.get("picture").is_some() { "picture" } else { "plain" }, "internalCode": "untrusted", "secretNote": "provider-private" }))?,
            name: Some(Some("Mapped OIDC User".to_owned())),
            image: Some(None),
            email_verified: Some(false),
            ..Default::default()
        })
    }
}

pub fn configure(mut plugin: OAuthPlugin) -> OAuthPlugin {
    let Ok(base) = std::env::var("COMPAT_OIDC_URL") else {
        return plugin;
    };
    for name in [
        "oidc",
        "oidc-rotation",
        "oidc-no-nonce",
        "oidc-idp",
        "oidc-basic",
        "oidc-public",
        "oidc-no-signup",
        "oidc-email-required",
        "oidc-mapped",
        "oidc-parameters",
        "oidc-unavailable",
        "oidc-missing-jwks",
        "oidc-invalid-issuer",
        "oauth-fallback",
    ] {
        let discovery = match name {
            "oidc-unavailable" | "oauth-fallback" => "unavailable",
            "oidc-missing-jwks" => "missing-jwks",
            "oidc-invalid-issuer" => "invalid-issuer",
            "oidc-parameters" => "headers",
            _ => "valid",
        };
        let mut config = GenericOAuthConfig {
            client_id: "oidc-client".to_owned(),
            client_secret: Some("oidc-secret".to_owned()),
            discovery_url: Some(format!("{base}/discovery/{discovery}")),
            require_id_token_verification: true,
            scopes: vec!["email".to_owned(), "profile".to_owned()],
            ..Default::default()
        };
        if std::env::var("COMPAT_PROFILE").is_ok_and(|profile| profile.starts_with("oauth-proxy")) {
            config.redirect_uri = Some(format!("https://production.example.com/api/auth/callback/{name}"));
        }
        match name {
            "oidc-no-nonce" => config.disable_id_token_nonce_binding = true,
            "oidc-idp" => config.allow_idp_initiated = true,
            "oidc-basic" => config.authentication = Some(TokenEndpointSecretAuthentication::Basic),
            "oidc-public" => {
                config.client_secret = None;
                config.token_endpoint_auth = Some(TokenEndpointAuth::None);
            }
            "oidc-mapped" | "oidc-email-required" => {
                config.account_subject = Some(Arc::new(MappedIdentity));
                config.map_profile_to_user = Some(Arc::new(MappedIdentity));
                config.require_email_verification = name == "oidc-email-required";
                config.override_user_info = std::env::var("COMPAT_PROFILE").is_ok_and(|profile| profile == "organization-jwt");
            }
            "oidc-no-signup" => config.disable_sign_up = true,
            "oidc-parameters" => {
                config.discovery_headers.insert(
                    "x-compat-discovery",
                    "allowed".parse().expect("static header value is valid"),
                );
                config.pkce = false;
                config.prompt = Some("login".to_owned());
                config.access_type = Some("offline".to_owned());
                config.response_mode = Some("query".to_owned());
                config.authorization_url_params = [
                    ("prompt".to_owned(), "consent".to_owned()),
                    ("tenant".to_owned(), "configured".to_owned()),
                    ("state".to_owned(), "ignored".to_owned()),
                    ("nonce".to_owned(), "ignored".to_owned()),
                ].into_iter().collect();
                config.token_url_params =
                    HashMap::from([("audience".to_owned(), "fleet-api".to_owned())]);
            }
            "oauth-fallback" => {
                config.authorization_url = Some(format!("{base}/authorize"));
                config.token_url = Some(format!("{base}/token"));
                config.user_info_url = Some(format!("{base}/userinfo"));
                config.require_id_token_verification = false;
            }
            _ => {}
        }
        plugin = plugin.add_generic_provider(name, config);
    }
    plugin
}
