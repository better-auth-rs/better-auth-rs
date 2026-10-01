//! Schema traits for binding Better Auth to application-owned auth models.

use crate::entity::{AuthSession, AuthUser};

/// App-owned auth schema declaration.
pub trait AuthSchema: Send + Sync + 'static {
    type User: AuthUser;
    type Session: AuthSession;
    /// Application account model used by a persistence adapter.
    type Account: Send + Sync + 'static;
    /// Application verification model used by a persistence adapter.
    type Verification: Send + Sync + 'static;
}
