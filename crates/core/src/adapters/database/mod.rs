pub use super::traits::{
    AccountOps, ApiKeyOps, InvitationOps, MemberOps, OrganizationOps, PasskeyOps, SessionOps,
    TwoFactorOps, UserOps, VerificationOps,
};

#[cfg(not(any(feature = "sqlx-postgres", feature = "sqlx-sqlite")))]
compile_error!(
    "At least one of 'sqlx-postgres' or 'sqlx-sqlite' must be enabled. \
     Add one of these features to your Cargo.toml."
);

#[cfg(any(feature = "sqlx-postgres", feature = "sqlx-sqlite"))]
pub mod sqlx_adapter;

/// Database adapter trait for persistence.
///
/// Combines all entity-specific operation traits. Any type that implements
/// all sub-traits (`UserOps`, `SessionOps`, etc.) automatically implements
/// `DatabaseAdapter` via the blanket impl.
///
/// Use the sub-traits directly when you only need a subset of operations
/// (e.g., a plugin that only accesses users and sessions).
pub trait DatabaseAdapter:
    UserOps
    + SessionOps
    + AccountOps
    + VerificationOps
    + OrganizationOps
    + MemberOps
    + InvitationOps
    + TwoFactorOps
    + ApiKeyOps
    + PasskeyOps
{
}

impl<T> DatabaseAdapter for T where
    T: UserOps
        + SessionOps
        + AccountOps
        + VerificationOps
        + OrganizationOps
        + MemberOps
        + InvitationOps
        + TwoFactorOps
        + ApiKeyOps
        + PasskeyOps
{
}

#[cfg(feature = "sqlx-postgres")]
pub use sqlx_adapter::{SqlxAdapter, SqlxEntity};
