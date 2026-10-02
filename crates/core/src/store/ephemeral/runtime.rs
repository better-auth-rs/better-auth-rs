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
        let organization_fields = model_fields.organization_fields(self.organization_fields()?);
        Ok(Arc::new(Self {
            session_config: config.session.clone(),
            config,
            model_fields,
            state: self.state.clone(),
            verification_locks: self.verification_locks.clone(),
            device_code_consumptions: self.device_code_consumptions.clone(),
            organization_fields: Arc::new(RwLock::new(organization_fields)),
            hooks,
            pending_hooks: None,
        }))
    }
}
