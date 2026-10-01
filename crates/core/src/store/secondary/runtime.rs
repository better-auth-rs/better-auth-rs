use super::*;
use crate::store::{RuntimeStore, database_hooks::DatabaseHooks};

impl<S: AuthSchema> RuntimeStore<S> for SecondaryStore<S> {
    fn adapter_id(&self) -> &'static str {
        self.inner.adapter_id()
    }

    fn rate_limit_model_declaration(&self) -> Option<crate::schema::ModelDeclaration> {
        self.inner.rate_limit_model_declaration()
    }

    fn database_hook_metadata(&self) -> Vec<crate::observability::database::DatabaseHookMetadata> {
        self.inner.database_hook_metadata()
    }

    fn schema_check(
        &self,
        config: &crate::store::schema::SchemaConfiguration,
    ) -> AuthResult<Option<Arc<crate::store::schema::SchemaCheck>>> {
        self.inner.schema_check(config)
    }

    fn schema_validation(&self) -> Option<&crate::store::schema::SchemaValidation> {
        self.schema_validation.as_ref()
    }

    fn with_runtime(
        &self,
        config: Arc<AuthConfig>,
        hooks: Vec<Arc<dyn DatabaseHooks<S>>>,
        model_fields: crate::plugin_runtime::ModelFields,
    ) -> AuthResult<Arc<dyn AuthStore<S>>> {
        Ok(Arc::new(Self {
            inner: self
                .inner
                .with_runtime(config.clone(), hooks, model_fields)?,
            storage: self.storage.clone(),
            config,
            metadata: self.metadata.clone(),
            schema_validation: self.schema_validation.clone(),
        }))
    }
}
