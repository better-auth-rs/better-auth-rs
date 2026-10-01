//! Schema traits for binding Better Auth to application-owned auth models.

use crate::entity::{AuthSession, AuthUser};
pub use better_auth_schema_registry::EntityRole;

/// Original table and column options used to generate an application model.
#[derive(Clone, Copy, Debug)]
pub struct ModelDeclaration {
    /// Model role associated with these input options.
    pub role: EntityRole,
    /// Explicit model name; omission does not expose the resolved table name.
    pub model_name: Option<&'static str>,
    /// Explicit logical-to-column mappings; `Some(&[])` preserves an empty map.
    pub fields: Option<&'static [(&'static str, &'static str)]>,
}

/// App-owned auth schema declaration.
pub trait AuthSchema: Send + Sync + 'static {
    type User: AuthUser;
    type Session: AuthSession;
    /// Application account model used by a persistence adapter.
    type Account: Send + Sync + 'static;
    /// Application verification model used by a persistence adapter.
    type Verification: Send + Sync + 'static;

    /// Original core model options, emitted from the CLI's schema configuration.
    /// Handwritten and derived schemas omit declarations unless supplied by their source.
    fn model_declarations() -> &'static [ModelDeclaration]
    where
        Self: Sized,
    {
        &[]
    }
}
