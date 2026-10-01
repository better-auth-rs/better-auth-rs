use super::{SpanAttributes, with_span};
use crate::{AuthConfig, AuthResult};
use std::future::Future;

/// Database lifecycle callbacks declared by a hook implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatabaseHook {
    BeforeCreateUser,
    AfterCreateUser,
    BeforeUpdateUser,
    AfterUpdateUser,
    BeforeDeleteUser,
    AfterDeleteUser,
    BeforeCreateAccount,
    AfterCreateAccount,
    BeforeUpdateAccount,
    AfterUpdateAccount,
    BeforeDeleteAccount,
    AfterDeleteAccount,
    BeforeCreateSession,
    AfterCreateSession,
    BeforeUpdateSession,
    AfterUpdateSession,
    BeforeDeleteSession,
    AfterDeleteSession,
    BeforeCreateVerification,
    AfterCreateVerification,
    BeforeUpdateVerification,
    AfterUpdateVerification,
    BeforeDeleteVerification,
    AfterDeleteVerification,
}
impl DatabaseHook {
    fn labels(self) -> (&'static str, &'static str) {
        match self {
            Self::BeforeCreateUser => ("user", "create.before"),
            Self::AfterCreateUser => ("user", "create.after"),
            Self::BeforeUpdateUser => ("user", "update.before"),
            Self::AfterUpdateUser => ("user", "update.after"),
            Self::BeforeDeleteUser => ("user", "delete.before"),
            Self::AfterDeleteUser => ("user", "delete.after"),
            Self::BeforeCreateAccount => ("account", "create.before"),
            Self::AfterCreateAccount => ("account", "create.after"),
            Self::BeforeUpdateAccount => ("account", "update.before"),
            Self::AfterUpdateAccount => ("account", "update.after"),
            Self::BeforeDeleteAccount => ("account", "delete.before"),
            Self::AfterDeleteAccount => ("account", "delete.after"),
            Self::BeforeCreateSession => ("session", "create.before"),
            Self::AfterCreateSession => ("session", "create.after"),
            Self::BeforeUpdateSession => ("session", "update.before"),
            Self::AfterUpdateSession => ("session", "update.after"),
            Self::BeforeDeleteSession => ("session", "delete.before"),
            Self::AfterDeleteSession => ("session", "delete.after"),
            Self::BeforeCreateVerification => ("verification", "create.before"),
            Self::AfterCreateVerification => ("verification", "create.after"),
            Self::BeforeUpdateVerification => ("verification", "update.before"),
            Self::AfterUpdateVerification => ("verification", "update.after"),
            Self::BeforeDeleteVerification => ("verification", "delete.before"),
            Self::AfterDeleteVerification => ("verification", "delete.after"),
        }
    }
}

/// Exact callback presence and source. Generate this with `#[database_hooks]`.
#[derive(Clone, Copy)]
pub struct DatabaseHookMetadata {
    pub methods: &'static [DatabaseHook],
    /// `user` or `plugin:<id>`.
    pub source: &'static str,
}

pub async fn with_database_hook<T>(
    config: &AuthConfig,
    metadata: DatabaseHookMetadata,
    method: DatabaseHook,
    operation: impl Future<Output = AuthResult<T>>,
) -> AuthResult<T> {
    if !metadata.methods.contains(&method) {
        return operation.await;
    }
    let (model, hook_type) = method.labels();
    with_span(
        &config.experimental.instrumentation,
        &format!("db {hook_type} {model}"),
        SpanAttributes {
            collection: Some(model),
            hook_type: Some(hook_type),
            context: Some(metadata.source),
            ..Default::default()
        },
        operation,
    )
    .await
}

pub async fn with_database_operation<T>(
    config: &AuthConfig,
    collection: &str,
    operation_name: &str,
    operation: impl Future<Output = AuthResult<T>>,
) -> AuthResult<T> {
    with_span(
        &config.experimental.instrumentation,
        &format!("db {operation_name} {collection}"),
        SpanAttributes {
            collection: Some(collection),
            database_operation: Some(operation_name),
            ..Default::default()
        },
        operation,
    )
    .await
}
