use better_auth_core::{AuthError, AuthResult};

use super::google::{self, AcceptedIdToken, VerifiedGoogleClaims};
use super::resolved::ResolvedProvider;
use super::types::OAuthIdTokenRequest;

pub(super) enum VerifiedIdToken {
    Google(VerifiedGoogleClaims),
    Generic(serde_json::Value),
    Cognito(serde_json::Value),
    Paybin(serde_json::Value),
    PayPal(serde_json::Value),
    Facebook(serde_json::Value),
}

pub(super) async fn verify(
    provider: &ResolvedProvider,
    request: &OAuthIdTokenRequest,
) -> AuthResult<Option<VerifiedIdToken>> {
    if provider.config.disable_id_token_sign_in {
        return Err(unsupported());
    }
    let token = &request.token;
    let nonce = request.nonce.as_deref();
    if let Some(verifier) = &provider.config.verify_id_token {
        let accepted = AcceptedIdToken::verify(verifier.as_ref(), token, nonce)
            .await
            .ok_or_else(invalid)?;
        return if provider.config.google_jwks_url().is_some()
            && provider.config.get_user_info.is_none()
        {
            accepted.claims().map(VerifiedIdToken::Google).map(Some)
        } else if provider.config.cognito_options().is_some()
            && provider.config.get_user_info.is_none()
        {
            accepted.value().map(VerifiedIdToken::Cognito).map(Some)
        } else if provider.config.paybin_issuer().is_some()
            && provider.config.get_user_info.is_none()
        {
            accepted.value().map(VerifiedIdToken::Paybin).map(Some)
        } else if provider.config.is_paypal() && provider.config.get_user_info.is_none() {
            accepted.value().map(VerifiedIdToken::PayPal).map(Some)
        } else if provider.config.facebook_options().is_some()
            && provider.config.get_user_info.is_none()
            && token.split('.').count() == 3
        {
            accepted.value().map(VerifiedIdToken::Facebook).map(Some)
        } else {
            Ok(None)
        };
    }
    if let Some(verifier) = provider
        .generic
        .as_ref()
        .and_then(|generic| generic.verifier.as_ref())
    {
        let claims = verifier.verify(token, nonce).await.map_err(|_| invalid())?;
        return Ok(Some(VerifiedIdToken::Generic(claims)));
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
    if let Some(options) = provider.config.cognito_options() {
        return options
            .verify(&provider.config.client_id, token, nonce)
            .await
            .map(VerifiedIdToken::Cognito)
            .map(Some);
    }
    if let Some(jwks_url) = provider.config.google_jwks_url() {
        let claims = google::verify(
            token,
            std::slice::from_ref(&provider.config.client_id),
            nonce,
            jwks_url,
        )
        .await
        .ok_or_else(invalid)?;
        if !claims.matches_hosted_domain(provider.config.google_hosted_domain()) {
            return Err(invalid());
        }
        return Ok(Some(VerifiedIdToken::Google(claims)));
    }
    Err(unsupported())
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
