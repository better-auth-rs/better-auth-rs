//! Per-instance bindings for plugin database hooks and user-field policies.

use std::sync::{Arc, OnceLock, Weak};

use crate::request_runtime::RuntimeIdentity;
use crate::user_fields::UserConfig;
use crate::{AuthContext, AuthError, AuthResult, AuthSchema};

mod fields;
pub use fields::ModelFields;

struct Binding<S: AuthSchema> {
    identity: RuntimeIdentity,
    context: Weak<AuthContext<S>>,
}

/// A plugin's reference to its own authentication runtime.
pub struct PluginRuntime<S: AuthSchema>(Arc<OnceLock<Binding<S>>>);

impl<S: AuthSchema> Clone for PluginRuntime<S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<S: AuthSchema> Default for PluginRuntime<S> {
    fn default() -> Self {
        Self(Arc::default())
    }
}

impl<S: AuthSchema> PluginRuntime<S> {
    /// Read this instance's active request context or its initialized context.
    pub fn context(&self) -> AuthResult<Arc<AuthContext<S>>> {
        self.0
            .get()
            .and_then(|binding| {
                binding
                    .identity
                    .current()
                    .or_else(|| binding.context.upgrade())
            })
            .ok_or_else(|| {
                AuthError::config("Plugin runtime is not initialized or has been dropped")
            })
    }

    /// Bind once after every plugin and store facade has been initialized.
    pub fn bind(&self, context: &Arc<AuthContext<S>>) -> AuthResult<()> {
        self.0
            .set(Binding {
                identity: context.runtime_identity(),
                context: Arc::downgrade(context),
            })
            .map_err(|_| AuthError::config("Plugin runtime is already initialized"))
    }
}

/// Resolved adapter policy. Endpoint policy remains in `AuthConfig::user`.
#[derive(Clone)]
pub struct AdapterUserFields(pub UserConfig);

/// Application user declarations before plugin field policies are merged.
#[derive(Clone)]
pub struct ApplicationUserFields(pub UserConfig);

pub fn resolve_user_fields(
    application: &UserConfig,
    plugins: UserConfig,
) -> (UserConfig, UserConfig) {
    let mut adapter = plugins.clone();
    if let Some(fields) = &application.additional_fields {
        adapter.fields_mut().extend(fields.clone());
    }
    let mut endpoint = application.clone();
    if let Some(fields) = plugins.additional_fields {
        endpoint.fields_mut().extend(fields);
    }
    (adapter, endpoint)
}
