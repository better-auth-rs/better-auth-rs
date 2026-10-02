use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use better_auth_core::{AuthError, AuthResult};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};

const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Grant for which a token endpoint request is authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenGrantType {
    /// Exchange an authorization code for tokens.
    AuthorizationCode,
    /// Exchange a refresh token for new tokens.
    RefreshToken,
}

impl TokenGrantType {
    /// Return the OAuth grant identifier.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::RefreshToken => "refresh_token",
        }
    }
}

/// Values used to create an RFC 7523 client assertion for one request.
#[derive(Debug, Clone, Copy)]
pub struct ClientAssertionContext<'a> {
    /// OAuth client identifier.
    pub client_id: &'a str,
    /// Final token endpoint URL, used as the assertion audience.
    pub token_endpoint: &'a str,
    /// Grant carried by this request.
    pub grant_type: TokenGrantType,
}

/// Creates a fresh, signed client assertion for each token request.
#[async_trait]
pub trait ClientAssertion: Send + Sync {
    /// Return an RFC 7523 JWT assertion signed by the client's private key.
    async fn get_client_assertion(&self, context: ClientAssertionContext<'_>)
    -> AuthResult<String>;
}

/// Mutable request passed to a custom token endpoint authentication strategy.
pub struct TokenEndpointRequestContext<'a> {
    /// Form parameters, including any repeated resource parameters.
    pub body: &'a mut Vec<(String, String)>,
    /// HTTP headers sent to the token endpoint.
    pub headers: &'a mut HeaderMap,
    /// OAuth client identifier.
    pub client_id: &'a str,
    /// Optional configured client secret.
    pub client_secret: Option<&'a str>,
    /// Final token endpoint URL.
    pub token_endpoint: &'a str,
    /// Grant carried by this request.
    pub grant_type: TokenGrantType,
}

/// Applies custom authentication after standard grant parameters are set.
#[async_trait]
pub trait TokenRequestHook: Send + Sync {
    /// Update the request body and headers, or reject the request.
    async fn customize_request(&self, context: TokenEndpointRequestContext<'_>) -> AuthResult<()>;
}

/// Authentication method used for authorization-code exchange and token refresh.
#[derive(Clone)]
pub enum TokenEndpointAuth {
    /// Send the client identifier and secret in the request body.
    ClientSecretPost,
    /// Send form-encoded credentials in the HTTP Basic authorization header.
    ClientSecretBasic,
    /// Authenticate a public client with its identifier and no secret.
    None,
    /// Obtain a signed RFC 7523 assertion for each request.
    PrivateKeyJwt(Arc<dyn ClientAssertion>),
    /// Apply a provider-specific authentication strategy.
    Custom(Arc<dyn TokenRequestHook>),
}

/// Legacy OAuth client-secret authentication selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenEndpointSecretAuthentication {
    /// Send form-encoded credentials in the HTTP Basic authorization header.
    Basic,
    /// Send credentials in the request body.
    Post,
}

pub(super) struct TokenAuthentication<'a> {
    pub client_id: &'a str,
    pub client_secret: Option<&'a str>,
    pub token_endpoint: &'a str,
    pub grant_type: TokenGrantType,
    pub token_endpoint_auth: Option<&'a TokenEndpointAuth>,
    pub authentication: Option<TokenEndpointSecretAuthentication>,
}

pub(super) struct AuthorizationCodeRequest<'a> {
    pub code: &'a str,
    pub redirect_uri: &'a str,
    pub code_verifier: Option<&'a str>,
    pub client_key: Option<&'a str>,
    pub device_id: Option<&'a str>,
    pub headers: &'a HeaderMap,
    pub additional_params: &'a HashMap<String, String>,
    pub resources: &'a [String],
}

pub(super) struct TokenRequest {
    pub body: Vec<(String, String)>,
    pub headers: HeaderMap,
}

impl TokenRequest {
    fn new(grant_type: TokenGrantType) -> Self {
        let mut headers = HeaderMap::new();
        let _ = headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        let _ = headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        Self {
            body: vec![("grant_type".to_string(), grant_type.as_str().to_string())],
            headers,
        }
    }

    pub(super) fn authorization_code(input: AuthorizationCodeRequest<'_>) -> Self {
        let mut request = Self::new(TokenGrantType::AuthorizationCode);
        request.headers.extend(input.headers.clone());
        request.set("code", input.code);
        for (key, value) in [
            ("code_verifier", input.code_verifier),
            ("client_key", input.client_key),
            ("device_id", input.device_id),
        ] {
            if let Some(value) = value.filter(|value| !value.is_empty()) {
                request.set(key, value);
            }
        }
        request.set("redirect_uri", input.redirect_uri);
        request.add_resources(input.resources);
        for (key, value) in input.additional_params {
            if !request.has(key) {
                request.set(key, value);
            }
        }
        request
    }

    pub(super) fn refresh_token(
        refresh_token: &str,
        extra_params: &HashMap<String, String>,
        resources: &[String],
    ) -> Self {
        let mut request = Self::new(TokenGrantType::RefreshToken);
        request.set("refresh_token", refresh_token);
        request.add_resources(resources);
        for (key, value) in extra_params {
            if !matches!(
                key.as_str(),
                "grant_type" | "refresh_token" | "__proto__" | "constructor" | "prototype"
            ) {
                request.set(key, value);
            }
        }
        request
    }

    pub(super) async fn authenticate(&mut self, input: TokenAuthentication<'_>) -> AuthResult<()> {
        self.assert_complete_assertion()?;
        if self.has("client_assertion") {
            if input.token_endpoint_auth.is_some() {
                return Err(AuthError::internal(
                    "client_assertion body parameters cannot be combined with tokenEndpointAuth",
                ));
            }
            self.assert_no_client_secret("private_key_jwt", input.client_secret)?;
            if !input.client_id.is_empty() {
                self.set("client_id", input.client_id);
            }
            return Ok(());
        }

        let default_auth = match input.authentication {
            Some(TokenEndpointSecretAuthentication::Basic) => TokenEndpointAuth::ClientSecretBasic,
            _ if input.client_secret.is_some_and(|secret| !secret.is_empty()) => {
                TokenEndpointAuth::ClientSecretPost
            }
            _ => TokenEndpointAuth::None,
        };
        match input.token_endpoint_auth.unwrap_or(&default_auth) {
            TokenEndpointAuth::Custom(hook) => {
                hook.customize_request(TokenEndpointRequestContext {
                    body: &mut self.body,
                    headers: &mut self.headers,
                    client_id: input.client_id,
                    client_secret: input.client_secret,
                    token_endpoint: input.token_endpoint,
                    grant_type: input.grant_type,
                })
                .await?;
                self.assert_complete_assertion()?;
            }
            TokenEndpointAuth::PrivateKeyJwt(assertion) => {
                self.assert_no_client_secret("private_key_jwt", input.client_secret)?;
                require_client_id("private_key_jwt", input.client_id)?;
                if input.token_endpoint.is_empty() {
                    return Err(AuthError::internal(
                        "private_key_jwt token endpoint authentication requires tokenEndpoint",
                    ));
                }
                let assertion = assertion
                    .get_client_assertion(ClientAssertionContext {
                        client_id: input.client_id,
                        token_endpoint: input.token_endpoint,
                        grant_type: input.grant_type,
                    })
                    .await?;
                self.set("client_id", input.client_id);
                self.set("client_assertion", &assertion);
                self.set("client_assertion_type", CLIENT_ASSERTION_TYPE);
            }
            TokenEndpointAuth::None => {
                self.assert_no_client_secret("none", input.client_secret)?;
                require_client_id("none", input.client_id)?;
                self.set("client_id", input.client_id);
            }
            TokenEndpointAuth::ClientSecretBasic => {
                if self.has("client_secret") {
                    return Err(AuthError::internal(
                        "client_secret_basic token endpoint authentication cannot be combined with client_secret body parameters",
                    ));
                }
                let secret = require_client_secret("client_secret_basic", input.client_secret)?;
                require_client_id("client_secret_basic", input.client_id)?;
                let credentials =
                    format!("{}:{}", form_encode(input.client_id), form_encode(secret));
                let authorization = format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(credentials)
                );
                let _ = self.headers.insert(
                    AUTHORIZATION,
                    HeaderValue::from_str(&authorization).map_err(|error| {
                        AuthError::internal(format!("Invalid client authorization header: {error}"))
                    })?,
                );
            }
            TokenEndpointAuth::ClientSecretPost => {
                let secret = require_client_secret("client_secret_post", input.client_secret)?;
                require_client_id("client_secret_post", input.client_id)?;
                self.set("client_id", input.client_id);
                self.set("client_secret", secret);
            }
        }
        Ok(())
    }

    pub(super) async fn send(self, token_endpoint: &str) -> AuthResult<serde_json::Value> {
        send_request(
            client()?
                .post(token_endpoint)
                .headers(self.headers)
                .form(&self.body),
            token_endpoint,
        )
        .await
    }

    pub(super) async fn send_query(
        token_endpoint: &str,
        params: &[(&str, &str)],
    ) -> AuthResult<serde_json::Value> {
        send_request(client()?.get(token_endpoint).query(params), token_endpoint).await
    }

    fn has(&self, name: &str) -> bool {
        self.body.iter().any(|(key, _)| key == name)
    }

    fn set(&mut self, name: &str, value: &str) {
        let mut updated = false;
        self.body.retain_mut(|(key, current)| {
            if key != name {
                return true;
            }
            if updated {
                return false;
            }
            *current = value.to_string();
            updated = true;
            true
        });
        if !updated {
            self.body.push((name.to_string(), value.to_string()));
        }
    }

    fn add_resources(&mut self, resources: &[String]) {
        self.body.extend(
            resources
                .iter()
                .map(|value| ("resource".to_string(), value.clone())),
        );
    }

    fn assert_complete_assertion(&self) -> AuthResult<()> {
        if self.has("client_assertion") != self.has("client_assertion_type") {
            return Err(AuthError::internal(
                "client_assertion and client_assertion_type must both be provided",
            ));
        }
        Ok(())
    }

    fn assert_no_client_secret(&self, method: &str, client_secret: Option<&str>) -> AuthResult<()> {
        if client_secret.is_some_and(|secret| !secret.is_empty()) || self.has("client_secret") {
            return Err(AuthError::internal(format!(
                "{method} token endpoint authentication cannot be combined with clientSecret"
            )));
        }
        Ok(())
    }
}

fn require_client_id(method: &str, client_id: &str) -> AuthResult<()> {
    if client_id.is_empty() {
        return Err(AuthError::internal(format!(
            "{method} token endpoint authentication requires clientId"
        )));
    }
    Ok(())
}

fn require_client_secret<'a>(method: &str, client_secret: Option<&'a str>) -> AuthResult<&'a str> {
    client_secret
        .filter(|secret| !secret.is_empty())
        .ok_or_else(|| {
            AuthError::internal(format!(
                "{method} token endpoint authentication requires clientSecret"
            ))
        })
}

fn form_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn client() -> AuthResult<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| AuthError::internal(format!("OAuth HTTP client failed: {error}")))
}

async fn send_request(
    request: reqwest::RequestBuilder,
    token_endpoint: &str,
) -> AuthResult<serde_json::Value> {
    // GET grants carry credentials in the query. Keep request URLs out of errors.
    let response = request.send().await.map_err(|error| {
        AuthError::internal(format!("Token request failed: {}", error.without_url()))
    })?;
    if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
        return Err(AuthError::internal(format!(
            "The OAuth endpoint \"{token_endpoint}\" returned an HTTP redirect. Server-side OAuth fetches refuse redirects to prevent SSRF; configure the final endpoint URL."
        )));
    }
    let response = response.error_for_status().map_err(|error| {
        AuthError::internal(format!("Token request failed: {}", error.without_url()))
    })?;
    response.json().await.map_err(|error| {
        AuthError::internal(format!(
            "Failed to parse token response: {}",
            error.without_url()
        ))
    })
}

#[cfg(test)]
#[path = "token_tests.rs"]
mod tests;
