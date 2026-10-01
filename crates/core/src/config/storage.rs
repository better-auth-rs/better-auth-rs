use super::{AuthConfig, CookieCacheRefresh, CookieCacheStrategy, OAuthStateStrategy};
use crate::store::StoreCapabilities;
use chrono::Duration;

impl AuthConfig {
    /// Resolve omitted storage-dependent settings before plugin initialization.
    pub fn resolve_storage_defaults(&mut self, capabilities: StoreCapabilities) {
        let _ = self
            .account
            .store_account_cookie
            .get_or_insert(!capabilities.database);
        let _ =
            self.account
                .store_state_strategy
                .get_or_insert(if capabilities.server_sessions() {
                    OAuthStateStrategy::Database
                } else {
                    OAuthStateStrategy::Cookie
                });
        if !capabilities.server_sessions() {
            let cache = self
                .session
                .cookie_cache
                .get_or_insert_with(Default::default);
            let _ = cache.enabled.get_or_insert(true);
            let _ = cache.max_age.get_or_insert(self.session.expires_in);
            let _ = cache.strategy.get_or_insert(CookieCacheStrategy::Jwe);
            let _ = cache.refresh.get_or_insert(CookieCacheRefresh::Enabled);
        }
        if let Some(cache) = &mut self.session.cookie_cache {
            let _ = cache.enabled.get_or_insert(false);
            let _ = cache.max_age.get_or_insert(Duration::minutes(5));
            let _ = cache.strategy.get_or_insert(CookieCacheStrategy::Compact);
            if capabilities.server_sessions() {
                if matches!(
                    cache.refresh,
                    Some(CookieCacheRefresh::Enabled | CookieCacheRefresh::After(_))
                ) {
                    self.logger.warn("session.cookie_cache.refresh is disabled when a database or secondary storage is configured", &[]);
                }
                cache.refresh = Some(CookieCacheRefresh::Disabled);
            } else {
                let _ = cache.refresh.get_or_insert(CookieCacheRefresh::Disabled);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CookieCacheConfig;

    #[test]
    fn stateless_defaults_respect_each_explicit_override() {
        let mut config = AuthConfig::new("test-secret-min-32-chars-123456789");
        config.session.expires_in = Duration::hours(2);
        config.resolve_storage_defaults(StoreCapabilities {
            database: false,
            secondary: false,
        });
        assert!(config.account.store_account_cookie());
        assert_eq!(
            config.account.store_state_strategy(),
            OAuthStateStrategy::Cookie
        );
        let cache = config.session.cookie_cache.as_ref().unwrap();
        assert!(cache.enabled());
        assert_eq!(cache.max_age(), Duration::hours(2));
        assert_eq!(cache.strategy(), CookieCacheStrategy::Jwe);
        assert_eq!(cache.refresh_age(), Some(Duration::seconds(1440)));

        let mut explicit = AuthConfig::new("test-secret-min-32-chars-123456789");
        explicit.account.store_account_cookie = Some(false);
        explicit.account.store_state_strategy = Some(OAuthStateStrategy::Database);
        explicit.session.cookie_cache = Some(CookieCacheConfig {
            enabled: Some(false),
            strategy: Some(CookieCacheStrategy::Compact),
            refresh: Some(CookieCacheRefresh::Disabled),
            ..Default::default()
        });
        explicit.resolve_storage_defaults(StoreCapabilities {
            database: false,
            secondary: false,
        });
        assert!(!explicit.account.store_account_cookie());
        assert_eq!(
            explicit.account.store_state_strategy(),
            OAuthStateStrategy::Database
        );
        let cache = explicit.session.cookie_cache.as_ref().unwrap();
        assert!(!cache.enabled());
        assert_eq!(cache.strategy(), CookieCacheStrategy::Compact);
        assert_eq!(cache.max_age(), explicit.session.expires_in);
        assert_eq!(cache.refresh_age(), None);
    }

    #[test]
    fn secondary_storage_keeps_account_cookie_and_server_session_defaults() {
        let mut config = AuthConfig::new("test-secret-min-32-chars-123456789");
        config.session.cookie_cache = Some(CookieCacheConfig {
            enabled: Some(true),
            refresh: Some(CookieCacheRefresh::After(Duration::seconds(10))),
            ..Default::default()
        });
        config.resolve_storage_defaults(StoreCapabilities {
            database: false,
            secondary: true,
        });
        assert!(config.account.store_account_cookie());
        assert_eq!(
            config.account.store_state_strategy(),
            OAuthStateStrategy::Database
        );
        let cache = config.session.cookie_cache.as_ref().unwrap();
        assert_eq!(cache.strategy(), CookieCacheStrategy::Compact);
        assert_eq!(cache.max_age(), Duration::minutes(5));
        assert_eq!(cache.refresh_age(), None);
    }
}
