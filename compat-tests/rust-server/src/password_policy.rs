use std::sync::Arc;

use better_auth::plugins::EmailPasswordPlugin;
use better_auth_core::{AuthResult, utils::password::PasswordHasher};

struct FixtureHasher;

#[async_trait::async_trait]
impl PasswordHasher for FixtureHasher {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        Ok(format!("fixture:{password}"))
    }

    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
        Ok(hash == format!("fixture:{password}"))
    }
}

pub fn configure(profile: &str, plugin: EmailPasswordPlugin) -> EmailPasswordPlugin {
    if profile == "password-policy" {
        plugin
            .password_hasher(Arc::new(FixtureHasher))
            .password_min_length(12)
            .password_max_length(24)
    } else {
        plugin
    }
}
