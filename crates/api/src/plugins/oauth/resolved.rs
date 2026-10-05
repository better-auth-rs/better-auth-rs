use std::{collections::HashMap, sync::Arc};

use better_auth_core::{AuthError, AuthResult};
use url::Url;

use super::generic::GenericOAuthConfig;
use super::oidc::{OidcVerifier, fetch_discovery};
use super::providers::{OAuthConfig, OAuthProvider};
use super::token::{TokenEndpointAuth, TokenEndpointSecretAuthentication};

pub(super) struct ResolvedOAuthConfig {
    pub providers: HashMap<String, ResolvedProvider>,
    pub email_verification:
        Option<Arc<crate::plugins::email_verification::EmailVerificationPlugin>>,
}

pub(super) struct ResolvedProvider {
    pub config: OAuthProvider,
    pub generic: Option<ResolvedGenericOAuth>,
}

pub(super) struct ResolvedGenericOAuth {
    pub config: GenericOAuthConfig,
    pub issuer: Option<String>,
    pub is_oidc: bool,
    pub verifier: Option<Arc<OidcVerifier>>,
}

impl ResolvedProvider {
    pub(super) fn uses_pkce(&self) -> bool {
        self.generic
            .as_ref()
            .map_or_else(|| self.config.uses_pkce(), |generic| generic.config.pkce)
    }

    pub(super) fn forwards_code_verifier(&self) -> bool {
        self.generic.as_ref().map_or_else(
            || self.config.forwards_code_verifier(),
            |generic| generic.config.pkce,
        )
    }

    pub(super) fn requires_nonce(&self) -> bool {
        self.generic.as_ref().is_some_and(|generic| {
            generic.verifier.is_some() && !generic.config.disable_id_token_nonce_binding
        })
    }

    pub(super) fn issuer(&self) -> Option<&str> {
        self.generic
            .as_ref()?
            .issuer
            .as_deref()
            .filter(|issuer| !issuer.is_empty())
    }
}

impl ResolvedOAuthConfig {
    pub(super) async fn new(
        config: &OAuthConfig,
        generic: &HashMap<String, GenericOAuthConfig>,
        email_verification: Option<
            Arc<crate::plugins::email_verification::EmailVerificationPlugin>,
        >,
    ) -> AuthResult<Self> {
        let mut providers: HashMap<_, _> = config
            .providers
            .iter()
            .map(|(name, config)| {
                (
                    name.clone(),
                    ResolvedProvider {
                        config: config.resolve(),
                        generic: None,
                    },
                )
            })
            .collect();
        for (name, config) in generic {
            if let Some(provider) = resolve_generic(name, config.clone()).await?
                && providers.insert(name.clone(), provider).is_some()
            {
                better_auth_core::observability::logger::current().warn(
                    "Generic OAuth provider shadows a built-in provider",
                    &[better_auth_core::observability::LogArgument::Value(
                        &serde_json::json!(name),
                    )],
                );
            }
        }
        Ok(Self {
            providers,
            email_verification,
        })
    }
}

async fn resolve_generic(
    name: &str,
    mut config: GenericOAuthConfig,
) -> AuthResult<Option<ResolvedProvider>> {
    let mut issuer = None;
    let mut is_oidc = false;
    let mut verifier = None;
    if let Some(discovery_url) = config
        .discovery_url
        .as_deref()
        .filter(|url| !url.is_empty())
    {
        match fetch_discovery(discovery_url, &config.discovery_headers).await {
            Ok(document) => {
                config.authorization_url =
                    config.authorization_url.or(document.authorization_endpoint);
                config.token_url = config.token_url.or(document.token_endpoint);
                config.user_info_url = config.user_info_url.or(document.userinfo_endpoint);
                config.end_session_endpoint = config
                    .end_session_endpoint
                    .or(document.end_session_endpoint);
                issuer = document.issuer;
                is_oidc = document
                    .id_token_signing_alg_values_supported
                    .as_ref()
                    .is_some_and(|values| !values.is_empty());
                if let (Some(jwks), Some(issuer)) = (
                    document.jwks_uri.filter(|url| !url.is_empty()),
                    issuer.as_ref().filter(|issuer| !issuer.is_empty()),
                ) {
                    let jwks_url = Url::parse(discovery_url).and_then(|base| base.join(&jwks));
                    let jwks_url = match jwks_url {
                        Ok(url) => url,
                        Err(error) => {
                            better_auth_core::observability::logger::current().error(
                                "Invalid discovery JWKS URL; provider skipped",
                                &[
                                    better_auth_core::observability::LogArgument::Value(
                                        &serde_json::json!(name),
                                    ),
                                    better_auth_core::observability::LogArgument::Error(&error),
                                ],
                            );
                            return Ok(None);
                        }
                    };
                    let algorithms = is_oidc
                        .then_some(document.id_token_signing_alg_values_supported)
                        .flatten();
                    verifier = Some(Arc::new(
                        OidcVerifier::new(
                            jwks_url,
                            issuer.clone(),
                            config.client_id.clone(),
                            algorithms,
                        )
                        .map_err(|error| AuthError::config(error.to_string()))?,
                    ));
                }
            }
            Err(error) => {
                // Upstream retains explicit endpoints after discovery failure unless verification is required.
                better_auth_core::observability::logger::current().error(
                    "OIDC discovery failed",
                    &[
                        better_auth_core::observability::LogArgument::Value(&serde_json::json!(
                            name
                        )),
                        better_auth_core::observability::LogArgument::Error(&error),
                    ],
                );
            }
        }
        if config
            .authorization_url
            .as_deref()
            .is_none_or(str::is_empty)
            || (config.token_url.as_deref().is_none_or(str::is_empty) && config.get_token.is_none())
        {
            better_auth_core::observability::logger::current().error(
                "Discovery left no usable authorization or token endpoint; provider skipped",
                &[better_auth_core::observability::LogArgument::Value(
                    &serde_json::json!(name),
                )],
            );
            return Ok(None);
        }
    }
    if config.require_id_token_verification && verifier.is_none() {
        let message = format!(
            "Provider {name} requires a discovery issuer and JWKS URI for ID-token verification"
        );
        if config
            .discovery_url
            .as_ref()
            .is_some_and(|url| !url.is_empty())
        {
            better_auth_core::observability::logger::current()
                .error(&format!("{message}; provider skipped"), &[]);
            return Ok(None);
        }
        return Err(AuthError::config(message));
    }
    let has_secret = config
        .client_secret
        .as_ref()
        .is_some_and(|secret| !secret.is_empty());
    match &config.token_endpoint_auth {
        Some(TokenEndpointAuth::None | TokenEndpointAuth::PrivateKeyJwt(_)) if has_secret => {
            return Err(AuthError::config(
                "Secretless token authentication cannot be combined with client_secret",
            ));
        }
        Some(TokenEndpointAuth::ClientSecretBasic | TokenEndpointAuth::ClientSecretPost)
            if !has_secret =>
        {
            return Err(AuthError::config(
                "Client-secret token authentication requires client_secret",
            ));
        }
        None if config.authentication == Some(TokenEndpointSecretAuthentication::Basic)
            && !has_secret =>
        {
            return Err(AuthError::config(
                "Basic token authentication requires client_secret",
            ));
        }
        _ => {}
    }
    let mut provider = OAuthProvider::custom(
        &config.client_id,
        config.client_secret.as_deref().unwrap_or_default(),
        config.authorization_url.as_deref().unwrap_or_default(),
        config.token_url.as_deref().unwrap_or_default(),
    );
    provider.user_info_url = config.user_info_url.clone();
    provider.redirect_uri = config.redirect_uri.clone();
    provider.end_session_endpoint = if config.disable_provider_logout {
        None
    } else {
        config.end_session_endpoint.clone()
    };
    provider.post_logout_redirect_uri = config.post_logout_redirect_uri.clone();
    provider.scopes = Some(config.scopes.clone());
    provider.authorization_params = config
        .authorization_url_params
        .clone()
        .into_iter()
        .collect();
    provider.disable_implicit_sign_up = Some(config.disable_implicit_sign_up);
    provider.disable_sign_up = Some(config.disable_sign_up);
    provider.require_email_verification = Some(config.require_email_verification);
    provider.override_user_info_on_sign_in = config.override_user_info;

    Ok(Some(ResolvedProvider {
        config: provider,
        generic: Some(ResolvedGenericOAuth {
            config,
            issuer,
            is_oidc,
            verifier,
        }),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn invalid_static_provider_configuration_fails_initialization() {
        let required = GenericOAuthConfig {
            require_id_token_verification: true,
            ..Default::default()
        };
        let cases = [
            (required.clone(), "requires a discovery issuer"),
            (
                GenericOAuthConfig {
                    discovery_url: Some(String::new()),
                    ..required
                },
                "requires a discovery issuer",
            ),
            (
                GenericOAuthConfig {
                    client_secret: Some("secret".into()),
                    token_endpoint_auth: Some(TokenEndpointAuth::None),
                    ..Default::default()
                },
                "Secretless token authentication",
            ),
            (
                GenericOAuthConfig {
                    token_endpoint_auth: Some(TokenEndpointAuth::ClientSecretBasic),
                    ..Default::default()
                },
                "Client-secret token authentication",
            ),
            (
                GenericOAuthConfig {
                    token_endpoint_auth: Some(TokenEndpointAuth::ClientSecretPost),
                    ..Default::default()
                },
                "Client-secret token authentication",
            ),
            (
                GenericOAuthConfig {
                    authentication: Some(TokenEndpointSecretAuthentication::Basic),
                    ..Default::default()
                },
                "Basic token authentication",
            ),
        ];
        for (config, expected) in cases {
            let providers = HashMap::from([("provider".to_owned(), config)]);
            let Err(error) =
                ResolvedOAuthConfig::new(&OAuthConfig::default(), &providers, None).await
            else {
                panic!("invalid configuration was accepted: {expected}");
            };
            assert!(error.to_string().contains(expected), "{error}");
        }
        let providers = HashMap::from([(
            "provider".to_owned(),
            GenericOAuthConfig {
                client_id: "client".into(),
                token_endpoint_auth: Some(TokenEndpointAuth::None),
                ..Default::default()
            },
        )]);
        assert!(
            ResolvedOAuthConfig::new(&OAuthConfig::default(), &providers, None)
                .await
                .is_ok()
        );
    }
}
