use super::*;
use better_auth::plugins::OAuthPlugin;
use better_auth::plugins::oauth::{
    OAuthIdTokenVerifier, OAuthProfile, OAuthProfileMapper, OAuthProvider,
    OAuthRefreshTokenHandler, OAuthTokenSet, OAuthUserInfoHandler, OAuthUserInfoRequest,
    OAuthUserInfoResponse,
};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
struct UnusedCallbacks(AtomicUsize);
impl UnusedCallbacks {
    fn called(&self) -> String {
        let _ = self.0.fetch_add(1, Ordering::SeqCst);
        "provider callback must not run during initialization or disabled sign-in".into()
    }
}
#[async_trait]
impl OAuthProfileMapper for UnusedCallbacks {
    async fn map_profile(&self, _: &Value) -> AuthResult<OAuthProfile> {
        Err(AuthError::internal(self.called()))
    }
}
#[async_trait]
impl OAuthUserInfoHandler for UnusedCallbacks {
    async fn get_user_info(
        &self,
        _: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        Err(better_auth_core::AuthError::internal(self.called()))
    }
}
#[async_trait]
impl OAuthIdTokenVerifier for UnusedCallbacks {
    async fn verify_id_token(&self, _: &str, _: Option<&str>) -> Result<bool, String> {
        Err(self.called())
    }
}
#[async_trait]
impl OAuthRefreshTokenHandler for UnusedCallbacks {
    async fn refresh_access_token(
        &self,
        _: &str,
        _: Option<better_auth_core::NativeRequest<'_>>,
    ) -> Result<OAuthTokenSet, String> {
        Err(self.called())
    }
}

#[tokio::test]
async fn social_inputs_preserve_presence_order_and_callback_metadata() -> AuthResult<()> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/social-provider-options-1.7.6.json"
    ))?;
    let cases = fixture
        .get("initialization")
        .and_then(Value::as_object)
        .ok_or_else(|| AuthError::internal("missing initialization cases"))?;
    for (name, expected) in cases {
        let callbacks = Arc::new(UnusedCallbacks::default());
        let mut plugin = OAuthPlugin::new();
        match name.as_str() {
            "google" => {
                plugin = plugin.add_provider(
                    "google",
                    OAuthProvider::google("client-sentinel", "secret-sentinel"),
                )
            }
            "github" | "mixed" => {
                plugin = plugin.add_provider(
                    "github",
                    OAuthProvider::github("client-sentinel", "secret-sentinel"),
                )
            }
            "discord" => {
                plugin = plugin.add_provider(
                    "discord",
                    OAuthProvider::discord("client-sentinel", "secret-sentinel"),
                )
            }
            "ordered" => {
                plugin = plugin
                    .add_provider("discord", OAuthProvider::discord("client", "secret"))
                    .add_provider("google", OAuthProvider::google("client", "secret"))
                    .add_provider("github", OAuthProvider::github("client", "secret"))
            }
            "overwritten" => {
                let mut replacement = OAuthProvider::google("client", "secret");
                replacement.prompt = Some("consent".into());
                plugin = plugin
                    .add_provider("google", OAuthProvider::google("client", "secret"))
                    .add_provider("github", OAuthProvider::github("client", "secret"))
                    .add_provider("google", replacement);
            }
            "explicitDefaults" | "configured" => {
                let configured = name == "configured";
                let mut provider = OAuthProvider::google("client", "secret");
                provider.disable_default_scope = configured;
                provider.disable_id_token_sign_in = configured;
                provider.disable_implicit_sign_up = Some(configured);
                provider.disable_sign_up = Some(configured);
                provider.override_user_info_on_sign_in = configured;
                provider.prompt = Some(if configured { "consent" } else { "" }.into());
                provider.scopes = Some(if configured {
                    vec!["calendar".into(), "email".into()]
                } else {
                    vec![]
                });
                if configured {
                    provider.map_profile_to_user = Some(callbacks.clone());
                    provider.get_user_info = Some(callbacks.clone());
                    provider.verify_id_token = Some(callbacks.clone());
                    provider.refresh_access_token = Some(callbacks.clone());
                }
                plugin = plugin.add_provider("google", provider);
            }
            _ => {}
        }
        if name == "genericOnly" || name == "mixed" {
            plugin = plugin.add_generic_provider("generic", super::plugins::generic());
        }
        let (config, reports) = configuration();
        let builder = BetterAuth::stateless(config);
        let _auth = if name == "omitted" {
            builder.build().await?
        } else {
            builder.plugin(plugin).build().await?
        };
        let actual = reports.config()?;
        for key in ["socialProviders", "plugins"] {
            assert_eq!(actual.get(key), expected.get(key), "{name}: {key}");
        }
        assert_eq!(callbacks.0.load(Ordering::SeqCst), 0, "{name}");
        let serialized = actual.to_string();
        assert!(!serialized.contains("secret-sentinel"));
        assert!(!serialized.contains("client-sentinel"));
    }
    Ok(())
}

#[tokio::test]
async fn disabled_id_token_sign_in_rejects_before_callbacks() -> AuthResult<()> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/social-provider-options-1.7.6.json"
    ))?;
    let callbacks = Arc::new(UnusedCallbacks::default());
    let mut provider = OAuthProvider::google("client", "secret");
    provider.disable_id_token_sign_in = true;
    provider.verify_id_token = Some(callbacks.clone());
    provider.get_user_info = Some(callbacks.clone());
    let (config, _) = configuration();
    let auth = BetterAuth::stateless(config)
        .plugin(OAuthPlugin::new().add_provider("google", provider))
        .build()
        .await?;
    let mut request = AuthRequest::new(core::HttpMethod::Post, "/sign-in/social");
    let _ = request
        .headers
        .insert("content-type".into(), "application/json".into());
    request.body =
        Some(br#"{"provider":"google","idToken":{"token":"unused-normal-token"}}"#.to_vec());
    let response = auth.handle_request(request).await?;
    let body: Value = serde_json::from_slice(&response.body)?;
    assert_eq!(
        serde_json::json!(response.status),
        fixture
            .pointer("/idTokenDisabled/status")
            .cloned()
            .ok_or_else(|| AuthError::internal("missing status"))?
    );
    assert_eq!(body.get("code"), fixture.pointer("/idTokenDisabled/code"));
    assert_eq!(callbacks.0.load(Ordering::SeqCst), 0);
    Ok(())
}
