//! Application policies for WebAuthn ceremonies.

use super::callbacks::{
    PasskeyAuthenticationHook, PasskeyExtensionsResolver, PasskeyRegistrationHook,
    PasskeyUserResolver,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::sync::Arc;

/// Explicit origins, or the request Origin header when no origin is configured.
#[derive(Debug, Clone, Default)]
pub enum PasskeyOrigins {
    #[default]
    Request,
    Explicit(Vec<String>),
}
impl From<String> for PasskeyOrigins {
    fn from(value: String) -> Self {
        if value.is_empty() {
            Self::Request
        } else {
            Self::Explicit(vec![value])
        }
    }
}
impl From<&str> for PasskeyOrigins {
    fn from(value: &str) -> Self {
        value.to_owned().into()
    }
}
impl From<Vec<String>> for PasskeyOrigins {
    fn from(value: Vec<String>) -> Self {
        Self::Explicit(value)
    }
}

/// Browser authenticator attachment preference.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatorAttachment {
    Platform,
    CrossPlatform,
}
/// Browser resident-key and user-verification preferences.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PasskeyRequirement {
    Required,
    Preferred,
    Discouraged,
}
/// Registration options sent to the browser. Verification does not require UV.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorSelection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resident_key: Option<PasskeyRequirement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_resident_key: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<PasskeyRequirement>,
}

/// Static or request-dependent WebAuthn extension input.
#[derive(Clone, Default)]
pub enum PasskeyExtensions {
    #[default]
    None,
    Static(Map<String, Value>),
    Dynamic(Arc<dyn PasskeyExtensionsResolver>),
}
impl std::fmt::Debug for PasskeyExtensions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::Static(value) => f.debug_tuple("Static").field(value).finish(),
            Self::Dynamic(_) => f.write_str("Dynamic(..)"),
        }
    }
}
/// Registration policy and callbacks.
#[derive(Clone)]
pub struct PasskeyRegistrationOptions {
    pub require_session: bool,
    pub resolve_user: Option<Arc<dyn PasskeyUserResolver>>,
    pub after_verification: Option<Arc<dyn PasskeyRegistrationHook>>,
    pub extensions: PasskeyExtensions,
}
impl Default for PasskeyRegistrationOptions {
    fn default() -> Self {
        Self {
            require_session: true,
            resolve_user: None,
            after_verification: None,
            extensions: PasskeyExtensions::None,
        }
    }
}
impl std::fmt::Debug for PasskeyRegistrationOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyRegistrationOptions")
            .field("require_session", &self.require_session)
            .field("resolve_user", &self.resolve_user.is_some())
            .field("after_verification", &self.after_verification.is_some())
            .field("extensions", &self.extensions)
            .finish()
    }
}
/// Authentication policy and callback.
#[derive(Clone, Default)]
pub struct PasskeyAuthenticationOptions {
    pub after_verification: Option<Arc<dyn PasskeyAuthenticationHook>>,
    pub extensions: PasskeyExtensions,
}
impl std::fmt::Debug for PasskeyAuthenticationOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyAuthenticationOptions")
            .field("after_verification", &self.after_verification.is_some())
            .field("extensions", &self.extensions)
            .finish()
    }
}
