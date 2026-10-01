use better_auth_core::{AuthError, AuthResult};

use super::google::{self, AcceptedGoogleToken, VerifiedGoogleClaims};
use super::resolved::ResolvedProvider;
use super::types::OAuthIdTokenRequest;

pub(super) async fn verify(
    provider: &ResolvedProvider,
    request: &OAuthIdTokenRequest,
) -> AuthResult<Option<VerifiedGoogleClaims>> {
    if provider.config.disable_id_token_sign_in {
        return Err(unsupported());
    }
    let token = &request.token;
    let nonce = request.nonce.as_deref();
    if let Some(verifier) = &provider.config.verify_id_token {
        let accepted = AcceptedGoogleToken::verify(verifier.as_ref(), token, nonce)
            .await
            .ok_or_else(invalid)?;
        return if provider.config.google_jwks_url().is_some()
            && provider.config.get_user_info.is_none()
        {
            accepted.claims().map(Some)
        } else {
            Ok(None)
        };
    }
    if let Some(verifier) = provider
        .generic
        .as_ref()
        .and_then(|generic| generic.verifier.as_ref())
    {
        let _ = verifier.verify(token, nonce).await.map_err(|_| invalid())?;
        return Ok(None);
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
        return Ok(Some(claims));
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

fn invalid() -> AuthError {
    AuthError::Upstream {
        status: 401,
        code: "INVALID_TOKEN",
        message: "Invalid token",
    }
}
