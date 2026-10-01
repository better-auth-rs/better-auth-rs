//! Runtime projections returned by the core adapter's ordinary joins.

use crate::{
    AuthError, AuthResult, SchemaValue,
    wire::{AccountView, UserView},
};

/// An account and its persisted owner. A missing owner is an orphaned account, not a new identity.
#[derive(Debug, Clone)]
pub struct AccountOwner {
    pub account: AccountView,
    pub user: Option<UserView>,
}

impl AccountOwner {
    /// Check projections against the canonical owner ID captured before output policies run.
    pub fn new(
        account: AccountView,
        user: Option<UserView>,
        stored_owner_id: &SchemaValue<String>,
    ) -> AuthResult<Self> {
        if account.user_id != *stored_owner_id
            || user
                .as_ref()
                .is_some_and(|user| user.id != *stored_owner_id)
        {
            return Err(AuthError::internal(
                "Account projection changed its owner binding",
            ));
        }
        Ok(Self { account, user })
    }
}

/// A user and the adapter-limited account page joined to that user.
#[derive(Debug, Clone)]
pub struct UserAccounts {
    pub user: UserView,
    pub accounts: Vec<AccountView>,
}

impl UserAccounts {
    /// Check a stored user and its account page without trusting projected identity fields.
    pub fn new(
        user: UserView,
        accounts: Vec<AccountView>,
        stored_user_id: &SchemaValue<String>,
    ) -> AuthResult<Self> {
        if user.id != *stored_user_id
            || accounts
                .iter()
                .any(|account| account.user_id != *stored_user_id)
        {
            return Err(AuthError::internal(
                "User projection changed its account binding",
            ));
        }
        Ok(Self { user, accounts })
    }
}

/// An invitation and the organization selected by its persisted foreign key.
#[derive(Debug, Clone)]
pub struct InvitationOrganization {
    pub invitation: crate::Invitation,
    pub organization: Option<crate::Organization>,
}
