use std::sync::Arc;

pub(crate) use crate::store::{EphemeralStore as MemoryStore, StatelessSchema as BundledSchema};
use crate::{AuthConfig, AuthStore};

pub(crate) fn test_config() -> Arc<AuthConfig> {
    let mut config = AuthConfig::new("test-secret-min-32-chars-1234567");
    config.session.bearer = Some(crate::config::BearerConfig::default());
    Arc::new(config)
}

pub(crate) async fn test_database() -> Arc<dyn AuthStore<BundledSchema>> {
    Arc::new(MemoryStore::new(test_config()))
}
