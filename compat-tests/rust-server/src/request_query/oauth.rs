use super::BodyTrace;
use better_auth::plugins::oauth::{
    OAuthIdTokenVerifier, OAuthPlugin, OAuthProvider, OAuthUserInfo, OAuthUserInfoHandler,
    OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use better_auth_core::AuthResult;
use serde_json::json;
use std::sync::Arc;

pub(super) fn plugin(profile: &str, trace: BodyTrace) -> OAuthPlugin {
    let plugin = OAuthPlugin::new();
    if !profile.starts_with("request-oauth-") {
        return plugin;
    }
    let trace = Arc::new(trace);
    let mut provider = OAuthProvider::google("fixture-client", "fixture-secret");
    provider.verify_id_token = Some(trace.clone());
    provider.get_user_info = Some(trace);
    plugin.add_provider("google", provider)
}

#[async_trait::async_trait]
impl OAuthIdTokenVerifier for BodyTrace {
    async fn verify_id_token(&self, token: &str, _: Option<&str>) -> Result<bool, String> {
        self.current("oauth.verify", None);
        Ok(token != "rejected-token")
    }
}

#[async_trait::async_trait]
impl OAuthUserInfoHandler for BodyTrace {
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        self.current("oauth.userinfo", None);
        self.1.lock().unwrap().push(json!({
            "kind":"oauth-userinfo", "accessToken":request.access_token,
            "refreshToken":request.refresh_token, "expiresAt":request.access_token_expires_at,
            "scopes":request.scopes, "idToken":request.id_token,
            "userPresent":request.user.is_some(),
            "firstName":request.user.as_ref().and_then(|user|user.name.as_ref()).and_then(|name|name.first_name.as_deref()),
            "lastName":request.user.as_ref().and_then(|user|user.name.as_ref()).and_then(|name|name.last_name.as_deref()),
            "email":request.user.as_ref().and_then(|user|user.email.as_deref()),
        }));
        let email = request
            .access_token
            .ok_or_else(|| better_auth_core::AuthError::internal("Missing fixture access token"))?;
        Ok(Some(OAuthUserInfoResponse {
            data: json!({"sub":email}),
            user: OAuthUserInfo {
                id: email.clone(),
                email: Some(email).into(),
                name: Some("OAuth schema".into()).into(),
                email_verified: Some(true).into(),
                image: None,
                additional_fields: Default::default(),
            },
        }))
    }
}
