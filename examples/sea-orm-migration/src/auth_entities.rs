//! Auth entity re-exports and adapter type alias.
//!
//! All entity types live in `crate::entities::*` as Sea-ORM `Model` structs
//! that derive both `DeriveEntityModel` (Sea-ORM) and `Auth*` (better-auth).
//! This module simply re-exports them under convenient `App*` aliases and
//! defines the parameterized `SqlxAdapter` type.

pub use crate::entities::account::Model as AppAccount;
pub use crate::entities::invitation::Model as AppInvitation;
pub use crate::entities::member::Model as AppMember;
pub use crate::entities::organization::Model as AppOrganization;
pub use crate::entities::session::Model as AppSession;
pub use crate::entities::user::Model as AppUser;
pub use crate::entities::verification::Model as AppVerification;

pub type AppAdapter = better_auth::adapters::SqlxAdapter<
    AppUser,
    AppSession,
    AppAccount,
    AppOrganization,
    AppMember,
    AppInvitation,
    AppVerification,
>;
