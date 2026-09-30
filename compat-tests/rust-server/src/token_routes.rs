use std::{collections::HashMap, sync::Arc};

use better_auth::{
    AuthBuilder, AuthResult,
    plugins::{
        AnonymousPlugin, JwtAlgorithm, JwtPlugin, MagicLinkMessage, MagicLinkPlugin,
        MultiSessionPlugin, OneTimeTokenPlugin, PhoneNumberPlugin, SendMagicLink, TokenStorage,
    },
};
use tokio::sync::Mutex;

use super::{EmailOutboxRecord, TestSchema};

struct Sender(Arc<Mutex<HashMap<String, EmailOutboxRecord>>>);

#[async_trait::async_trait]
impl SendMagicLink for Sender {
    async fn send(&self, message: &MagicLinkMessage) -> AuthResult<()> {
        self.0.lock().await.insert(
            message.email.clone(),
            EmailOutboxRecord {
                url: message.url.clone(),
                token: message.token.clone(),
                metadata: message.metadata.clone(),
            },
        );
        Ok(())
    }
}

pub(super) fn add_plugins(
    builder: AuthBuilder<TestSchema>,
    profile: &str,
    outbox: Arc<Mutex<HashMap<String, EmailOutboxRecord>>>,
) -> AuthBuilder<TestSchema> {
    match profile {
        "jwt" => builder.plugin(JwtPlugin::new()),
        "jwt-rs256" => builder.plugin(JwtPlugin::new().algorithm(JwtAlgorithm::Rs256)),
        "jwt-es256" => builder.plugin(JwtPlugin::new().algorithm(JwtAlgorithm::Es256)),
        "jwt-identity" => builder
            .plugin(JwtPlugin::new())
            .plugin(AnonymousPlugin::new())
            .plugin(PhoneNumberPlugin::new()),
        "magic-link" | "magic-link-disabled" => builder.plugin(
            MagicLinkPlugin::new()
                .custom_send_magic_link(Arc::new(Sender(outbox)))
                .disable_sign_up(profile == "magic-link-disabled")
                .store_token(if profile == "magic-link-disabled" {
                    TokenStorage::Hashed
                } else {
                    TokenStorage::Plain
                }),
        ),
        "one-time-token" | "one-time-token-options" => builder.plugin(
            OneTimeTokenPlugin::new()
                .store_token(if profile == "one-time-token-options" {
                    TokenStorage::Hashed
                } else {
                    TokenStorage::Plain
                })
                .disable_client_request(profile == "one-time-token-options")
                .set_ott_header_on_new_session(profile == "one-time-token-options")
                .disable_set_session_cookie(profile == "one-time-token-options"),
        ),
        "multi-session" | "multi-session-limit" => builder.plugin(
            MultiSessionPlugin::new().maximum_sessions(if profile == "multi-session-limit" {
                2
            } else {
                5
            }),
        ),
        _ => builder,
    }
}
