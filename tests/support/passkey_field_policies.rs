use crate::ordinary_field_policies as ordinary;

pub(crate) use ordinary::{Trace, take};

use better_auth::__private_core::__private_async_trait::async_trait;
use better_auth::{
    __private_core::{
        AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
        AuthSchema, store::schema::EntityRole, user_fields::UserConfig,
    },
    AuthConfig,
};
use std::sync::{Arc, atomic::AtomicU8};

pub(crate) struct Fields(pub(crate) UserConfig);

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Fields {
    fn name(&self) -> &'static str {
        "ordinary-passkey-additional-fields"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.register_model_fields(EntityRole::Passkey, self.0.clone())
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

pub(crate) fn config() -> AuthConfig {
    let mut config = AuthConfig::new("ordinary-passkey-extra-fields-secret-at-least-32-characters")
        .base_url("http://passkey-fields.test");
    config.telemetry.enabled = false;
    config
}

pub(crate) fn policies(events: Option<Trace>, failure: Arc<AtomicU8>) -> UserConfig {
    ordinary::policies("Passkey", events, failure)
}
