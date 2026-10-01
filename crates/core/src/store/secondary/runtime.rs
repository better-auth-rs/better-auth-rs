use super::*;
use crate::store::{RuntimeStore, database_hooks::DatabaseHooks};

impl<S: AuthSchema> RuntimeStore<S> for SecondaryStore<S> {
    fn with_runtime(
        &self,
        config: Arc<AuthConfig>,
        hooks: Vec<Arc<dyn DatabaseHooks<S>>>,
    ) -> AuthResult<Arc<dyn AuthStore<S>>> {
        Ok(Arc::new(Self {
            inner: self.inner.with_runtime(config.clone(), hooks)?,
            storage: self.storage.clone(),
            config,
            metadata: self.metadata.clone(),
        }))
    }
}
