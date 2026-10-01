use super::*;
use better_auth::plugins::oauth::{GenericOAuthConfig, OAuthProvider};
use better_auth::plugins::{AccountManagementPlugin, OAuthPlugin, SessionManagementPlugin};

struct NamedPlugin(&'static str);
#[async_trait]
impl AuthPlugin<S> for NamedPlugin {
    fn name(&self) -> &'static str {
        self.0
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

pub(super) fn generic() -> GenericOAuthConfig {
    GenericOAuthConfig {
        client_id: "telemetry-client".into(),
        client_secret: Some("telemetry-client-secret".into()),
        authorization_url: Some("https://provider.test/authorize".into()),
        token_url: Some("https://provider.test/token".into()),
        user_info_url: Some("https://provider.test/userinfo".into()),
        ..Default::default()
    }
}

#[tokio::test]
async fn plugin_ids_match_real_initialization_and_keep_plugin_order() -> AuthResult<()> {
    let expected: Value =
        serde_json::from_str(include_str!("../fixtures/telemetry-plugin-ids-1.7.6.json"))?;
    for name in [
        "omitted",
        "core",
        "social",
        "generic",
        "multipleGeneric",
        "mixed",
        "customCoreName",
    ] {
        let (config, reports) = configuration();
        let mut builder = BetterAuth::stateless(config);
        builder = match name {
            "core" => builder
                .plugin(EmailPasswordPlugin::new())
                .plugin(EmailVerificationPlugin::new())
                .plugin(PasswordManagementPlugin::new())
                .plugin(AccountManagementPlugin::new())
                .plugin(SessionManagementPlugin::new())
                .plugin(UserManagementPlugin::new())
                .plugin(OAuthPlugin::new()),
            "social" => builder.plugin(
                OAuthPlugin::new()
                    .add_provider("github", OAuthProvider::github("client", "secret")),
            ),
            "generic" => {
                builder.plugin(OAuthPlugin::new().add_generic_provider("provider", generic()))
            }
            "multipleGeneric" => builder.plugin(
                OAuthPlugin::new()
                    .add_generic_provider("first", generic())
                    .add_generic_provider("second", generic()),
            ),
            "mixed" => builder
                .plugin(NamedPlugin("first"))
                .plugin(EmailPasswordPlugin::new())
                .plugin(OAuthPlugin::new().add_generic_provider("provider", generic()))
                .plugin(UserManagementPlugin::new())
                .plugin(NamedPlugin("last")),
            "customCoreName" => builder.plugin(NamedPlugin("email-password")),
            _ => builder,
        };
        let _auth = builder.build().await?;
        assert_eq!(
            reports.config()?.get("plugins"),
            expected.get(name).and_then(|case| case.get("plugins")),
            "{name}"
        );
    }
    Ok(())
}
