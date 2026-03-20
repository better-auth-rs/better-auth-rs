//! Schema traits for binding Better Auth to application-owned auth models.

use crate::entity::{AuthAccount, AuthSession, AuthUser, AuthVerification};

/// App-owned auth schema declaration.
pub trait AuthSchema: Send + Sync + 'static {
    type User: AuthUser;
    type Session: AuthSession;
    type Account: AuthAccount;
    type Verification: AuthVerification;
}
