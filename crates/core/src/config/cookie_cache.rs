use crate::{AuthResult, session::NativeSessionData};
use std::{future::Future, pin::Pin, sync::Arc};

/// Asynchronous cookie version calculation from the session and user snapshot.
pub type CookieCacheVersionCallback = Arc<
    dyn Fn(NativeSessionData) -> Pin<Box<dyn Future<Output = AuthResult<String>> + Send>>
        + Send
        + Sync,
>;

/// A constant cache version or an application callback evaluated on writes and reads.
#[derive(Clone)]
pub enum CookieCacheVersion {
    /// Invalidate previously issued caches when this value changes.
    Fixed(String),
    /// Calculate a version from the snapshot being written or verified.
    Dynamic(CookieCacheVersionCallback),
}

impl CookieCacheVersion {
    /// Use an asynchronous callback without boxing the returned future at each call site.
    pub fn dynamic<F, Fut>(callback: F) -> Self
    where
        F: Fn(NativeSessionData) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AuthResult<String>> + Send + 'static,
    {
        Self::Dynamic(Arc::new(move |data| Box::pin(callback(data))))
    }

    pub(crate) async fn resolve(&self, data: &NativeSessionData) -> AuthResult<String> {
        match self {
            Self::Fixed(version) if version.is_empty() => Ok("1".into()),
            Self::Fixed(version) => Ok(version.clone()),
            Self::Dynamic(callback) => callback(data.clone()).await,
        }
    }
}

impl From<String> for CookieCacheVersion {
    fn from(version: String) -> Self {
        Self::Fixed(version)
    }
}

impl From<&str> for CookieCacheVersion {
    fn from(version: &str) -> Self {
        Self::Fixed(version.to_owned())
    }
}

impl std::fmt::Debug for CookieCacheVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fixed(version) => formatter.debug_tuple("Fixed").field(version).finish(),
            Self::Dynamic(_) => formatter.write_str("Dynamic(..)"),
        }
    }
}
