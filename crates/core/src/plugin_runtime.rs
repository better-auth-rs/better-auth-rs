//! Per-instance bindings for plugin database hooks and user-field policies.

use std::sync::{Arc, OnceLock, Weak};

use crate::user_fields::UserConfig;
use crate::{AuthContext, AuthError, AuthResult, AuthSchema};

/// A plugin's reference to the fully initialized authentication runtime.
/// The weak binding prevents the runtime's store hooks from retaining the runtime itself.
pub struct PluginRuntime<S: AuthSchema>(Arc<OnceLock<Weak<AuthContext<S>>>>);

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
    /// Read the final runtime, including its session and verification storage facade.
    pub fn context(&self) -> AuthResult<Arc<AuthContext<S>>> {
        self.0.get().and_then(Weak::upgrade).ok_or_else(|| {
            AuthError::config("Plugin runtime is not initialized or has been dropped")
        })
    }

    /// Bind once after every plugin and store facade has been initialized.
    pub fn bind(&self, context: &Arc<AuthContext<S>>) -> AuthResult<()> {
        self.0
            .set(Arc::downgrade(context))
            .map_err(|_| AuthError::config("Plugin runtime is already initialized"))
    }
}

/// Resolved adapter policy. Endpoint policy remains in the runtime's `AuthConfig::user`.
#[derive(Clone)]
pub struct AdapterUserFields(pub UserConfig);

/// Resolve the distinct upstream adapter and endpoint precedence rules.
pub fn resolve_user_fields(
    application: &UserConfig,
    plugins: UserConfig,
) -> (UserConfig, UserConfig) {
    let mut adapter = plugins.clone();
    adapter
        .additional_fields
        .extend(application.additional_fields.clone());
    let mut endpoint = application.clone();
    endpoint.additional_fields.extend(plugins.additional_fields);
    (adapter, endpoint)
}
