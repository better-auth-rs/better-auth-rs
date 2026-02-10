//! Sea-ORM entity definitions.
//!
//! Each entity derives both `DeriveEntityModel` (for Sea-ORM queries) and
//! `Auth*` (for better-auth), with a manual `sqlx::FromRow` impl so they
//! can be used directly with `SqlxAdapter`.

pub mod account;
pub mod invitation;
pub mod member;
pub mod organization;
pub mod session;
pub mod user;
pub mod verification;

pub use user::Entity as UserEntity;
