use better_auth_core::{AuthError, AuthResult, NativeRequest};
use std::sync::Arc;

use super::OAuthCallbacks;
use super::google::{self, AcceptedIdToken, VerifiedGoogleClaims};
use super::resolved::ResolvedProvider;
use super::types::OAuthIdTokenRequest;
use crate::plugins::endpoint_context::EndpointContext;

pub(super) enum VerifiedIdToken {
    Apple(serde_json::Value),
    Google(VerifiedGoogleClaims),
    Generic(serde_json::Value),
    Cognito(serde_json::Value),
    Microsoft(serde_json::Value),
    Paybin(serde_json::Value),
    PayPal(serde_json::Value),
    Facebook(serde_json::Value),
}

pub(super) async fn verify_in_endpoint<S: better_auth_core::AuthSchema>(
    provider_name: &str,
    provider: &ResolvedProvider,
    request: &OAuthIdTokenRequest,
    endpoint: &EndpointContext<'_, S>,
) -> AuthResult<Option<VerifiedIdToken>> {
    if let Some(verifier) = endpoint
        .auth
        .extensions
        .get::<Arc<OAuthCallbacks<S>>>()
        .and_then(|callbacks| callbacks.verifiers.get(provider_name))
    {
        if provider.config.disable_id_token_sign_in {
            return Err(unsupported());
        }
        let result = verifier(&request.token, request.nonce.as_deref(), endpoint).await;
        let accepted = AcceptedIdToken::from_result(&request.token, result).ok_or_else(invalid)?;
        return accepted_claims(provider, accepted, &request.token);
    }
    verify(
        provider,
        request,
        Some(NativeRequest {
            request: endpoint
                .input_request()
                .and_then(better_auth_core::AuthRequest::original_request),
            headers: endpoint.headers(),
        }),
    )
    .await
}

pub(super) async fn verify(
    provider: &ResolvedProvider,
    request: &OAuthIdTokenRequest,
    context: Option<NativeRequest<'_>>,
) -> AuthResult<Option<VerifiedIdToken>> {
    if provider.config.disable_id_token_sign_in {
        return Err(unsupported());
    }
    let token = &request.token;
    let nonce = request.nonce.as_deref();
    if let Some(verifier) = &provider.config.verify_id_token {
        let accepted = AcceptedIdToken::verify(verifier.as_ref(), token, nonce, context)
            .await
            .ok_or_else(invalid)?;
        return accepted_claims(provider, accepted, token);
    }
    if let Some(verifier) = provider
        .generic
        .as_ref()
        .and_then(|generic| generic.verifier.as_ref())
    {
        let claims = verifier.verify(token, nonce).await.map_err(|_| invalid())?;
        return Ok(Some(VerifiedIdToken::Generic(claims)));
    }
    if let Some(endpoint) = provider.config.line_verify_url() {
        super::providers::line::verify(endpoint, &provider.config.client_id, token, nonce).await?;
        return Ok(None);
    }
    if let Some(options) = provider.config.facebook_options() {
        if token.split('.').count() != 3 {
            // Opaque tokens supply no claims. The default profile must inspect its access token.
            return Ok(None);
        }
        return options
            .verify(&provider.config.client_id, token, nonce)
            .await
            .map(VerifiedIdToken::Facebook)
            .map(Some);
    }
    if let Some(options) = provider.config.microsoft_options() {
        return options
            .verify(&provider.config.client_id, token, nonce)
            .await
            .map(VerifiedIdToken::Microsoft)
            .map(Some);
    }
    if let Some(options) = provider.config.apple_options() {
        return options
            .verify(&provider.config.client_id, token, nonce)
            .await
            .map(VerifiedIdToken::Apple)
            .map(Some);
    }
    if let Some(options) = provider.config.cognito_options() {
        return options
            .verify(&provider.config.client_id, token, nonce)
            .await
            .map(VerifiedIdToken::Cognito)
            .map(Some);
    }
    if let Some(jwks_url) = provider.config.google_jwks_url() {
        let claims = google::verify(token, &provider.config.google_client_ids(), nonce, jwks_url)
            .await
            .ok_or_else(invalid)?;
        if !claims.matches_hosted_domain(provider.config.google_hosted_domain()) {
            return Err(invalid());
        }
        return Ok(Some(VerifiedIdToken::Google(claims)));
    }
    Err(unsupported())
}

fn accepted_claims(
    provider: &ResolvedProvider,
    accepted: AcceptedIdToken,
    token: &str,
) -> AuthResult<Option<VerifiedIdToken>> {
    if provider.config.get_user_info.is_some() {
        return Ok(None);
    }
    if provider.config.google_jwks_url().is_some() {
        accepted.claims().map(VerifiedIdToken::Google).map(Some)
    } else if provider.config.microsoft_options().is_some() {
        accepted.value().map(VerifiedIdToken::Microsoft).map(Some)
    } else if provider.config.apple_options().is_some() {
        accepted.value().map(VerifiedIdToken::Apple).map(Some)
    } else if provider.config.cognito_options().is_some() {
        accepted.value().map(VerifiedIdToken::Cognito).map(Some)
    } else if provider.config.paybin_issuer().is_some() {
        accepted.value().map(VerifiedIdToken::Paybin).map(Some)
    } else if provider.config.is_paypal() {
        accepted.value().map(VerifiedIdToken::PayPal).map(Some)
    } else if provider.config.facebook_options().is_some() && token.split('.').count() == 3 {
        accepted.value().map(VerifiedIdToken::Facebook).map(Some)
    } else {
        Ok(None)
    }
}

fn unsupported() -> AuthError {
    AuthError::Upstream {
        status: 404,
        code: "ID_TOKEN_NOT_SUPPORTED",
        message: "id_token not supported",
    }
}

pub(super) fn invalid() -> AuthError {
    AuthError::Upstream {
        status: 401,
        code: "INVALID_TOKEN",
        message: "Invalid token",
    }
}
