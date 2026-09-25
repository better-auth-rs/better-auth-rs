//! Shared Better Auth response types for Rust servers and WebAssembly clients.
//!
//! This crate contains wire views and invitation status without depending on
//! the authentication runtime, database adapters, or a system/browser clock.
//! Client applications can deserialize responses using [`UserView`] and
//! [`SessionView`] with `serde`, including on `wasm32-unknown-unknown`.
//!
//! The default `entity` feature adds server entity traits and conversions from
//! those entities. Clients can disable it with `default-features = false`
//! to use only the response types. All views, including [`MemberUserView`], remain
//! available without the feature.

#[cfg(feature = "entity")]
pub mod entity;
mod invitation;
pub mod wire;

#[cfg(feature = "entity")]
pub use entity::{
    AuthAccount, AuthApiKey, AuthInvitation, AuthMember, AuthOrganization, AuthPasskey,
    AuthSession, AuthTwoFactor, AuthUser, AuthVerification,
};
pub use invitation::InvitationStatus;
pub use wire::{
    AccountView, ApiKeyView, InvitationView, MemberUserView, OrganizationView, PasskeyView,
    SessionView, UserView, VerificationView,
};
