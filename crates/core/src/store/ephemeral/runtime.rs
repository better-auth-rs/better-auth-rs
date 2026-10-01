use super::*;
use crate::store::{AuthStore, RuntimeStore};

impl RuntimeStore<StatelessSchema> for EphemeralStore {
    fn adapter_id(&self) -> &'static str {
        "memory"
    }

    fn database_hook_metadata(&self) -> Vec<crate::observability::database::DatabaseHookMetadata> {
        self.hooks.iter().map(|hook| hook.hook_metadata()).collect()
    }

    fn with_runtime(
        &self,
        config: Arc<AuthConfig>,
        mut hooks: Vec<Arc<dyn DatabaseHooks<StatelessSchema>>>,
        model_fields: crate::plugin_runtime::ModelFields,
    ) -> AuthResult<Arc<dyn AuthStore<StatelessSchema>>> {
        hooks.extend(self.hooks.iter().cloned());
        Ok(Arc::new(Self {
            session_config: config.session.clone(),
            config,
            model_fields,
            state: self.state.clone(),
            verification_locks: self.verification_locks.clone(),
            organization_fields: Arc::new(RwLock::new(self.organization_fields()?)),
            hooks,
            pending_hooks: None,
        }))
    }
}
