use super::*;
use crate::store::{AuthStore, RuntimeStore};

impl RuntimeStore<StatelessSchema> for EphemeralStore {
    fn with_runtime(
        &self,
        config: Arc<AuthConfig>,
        mut hooks: Vec<Arc<dyn DatabaseHooks<StatelessSchema>>>,
    ) -> AuthResult<Arc<dyn AuthStore<StatelessSchema>>> {
        hooks.extend(self.hooks.iter().cloned());
        Ok(Arc::new(Self {
            session_config: config.session.clone(),
            config,
            state: self.state.clone(),
            verification_locks: self.verification_locks.clone(),
            organization_fields: Arc::new(RwLock::new(self.organization_fields()?)),
            hooks,
            pending_hooks: None,
        }))
    }
}
