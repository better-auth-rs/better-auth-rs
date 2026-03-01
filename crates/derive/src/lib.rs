//! Derive macros for better-auth entity traits.
//!
//! Provides `#[derive(AuthUser)]`, `#[derive(AuthSession)]`, etc. to auto-implement
//! the entity traits from `better_auth_core::entity` for custom struct types.
//!
//! # Example
//!
//! ```rust,ignore
//! use better_auth_derive::AuthUser;
//!
//! #[derive(Clone, Debug, Serialize, AuthUser)]
//! pub struct MyUser {
//!     pub id: String,
//!     pub email: Option<String>,
//!     #[auth(field = "name")]
//!     pub display_name: Option<String>,
//!     pub email_verified: bool,
//!     pub image: Option<String>,
//!     pub created_at: DateTime<Utc>,
//!     pub updated_at: DateTime<Utc>,
//!     pub username: Option<String>,
//!     pub display_username: Option<String>,
//!     pub two_factor_enabled: bool,
//!     pub role: Option<String>,
//!     pub banned: bool,
//!     pub ban_reason: Option<String>,
//!     pub ban_expires: Option<DateTime<Utc>>,
//!     pub metadata: serde_json::Value,
//! }
//! ```

mod auth_derive;
mod from_row;
mod helpers;
mod memory_derive;
mod plugin_config;

use proc_macro::TokenStream;
use quote::quote;
use syn::{DeriveInput, parse_macro_input};

use auth_derive::{
    AUTH_ACCOUNT_GETTERS, AUTH_INVITATION_GETTERS, AUTH_MEMBER_GETTERS, AUTH_ORGANIZATION_GETTERS,
    AUTH_PASSKEY_GETTERS, AUTH_SESSION_GETTERS, AUTH_TWO_FACTOR_GETTERS, AUTH_USER_GETTERS,
    AUTH_VERIFICATION_GETTERS, derive_entity_trait, derive_meta_trait,
};
use from_row::maybe_gen_from_row;
use memory_derive::{
    MEMORY_ACCOUNT_DEF, MEMORY_INVITATION_DEF, MEMORY_MEMBER_DEF, MEMORY_ORGANIZATION_DEF,
    MEMORY_SESSION_DEF, MEMORY_USER_DEF, MEMORY_VERIFICATION_DEF, derive_memory_trait,
};

#[proc_macro_derive(AuthUser, attributes(auth))]
pub fn derive_auth_user(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let t = derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthUser },
        "AuthUser",
        AUTH_USER_GETTERS,
    );
    let m = derive_meta_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthUserMeta },
        "AuthUserMeta",
        AUTH_USER_GETTERS,
    );
    let r = maybe_gen_from_row(&input);
    quote! { #t #m #r }.into()
}

#[proc_macro_derive(AuthSession, attributes(auth))]
pub fn derive_auth_session(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let t = derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthSession },
        "AuthSession",
        AUTH_SESSION_GETTERS,
    );
    let m = derive_meta_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthSessionMeta },
        "AuthSessionMeta",
        AUTH_SESSION_GETTERS,
    );
    let r = maybe_gen_from_row(&input);
    quote! { #t #m #r }.into()
}

#[proc_macro_derive(AuthAccount, attributes(auth))]
pub fn derive_auth_account(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let t = derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthAccount },
        "AuthAccount",
        AUTH_ACCOUNT_GETTERS,
    );
    let m = derive_meta_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthAccountMeta },
        "AuthAccountMeta",
        AUTH_ACCOUNT_GETTERS,
    );
    let r = maybe_gen_from_row(&input);
    quote! { #t #m #r }.into()
}

#[proc_macro_derive(AuthOrganization, attributes(auth))]
pub fn derive_auth_organization(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let t = derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthOrganization },
        "AuthOrganization",
        AUTH_ORGANIZATION_GETTERS,
    );
    let m = derive_meta_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthOrganizationMeta },
        "AuthOrganizationMeta",
        AUTH_ORGANIZATION_GETTERS,
    );
    let r = maybe_gen_from_row(&input);
    quote! { #t #m #r }.into()
}

#[proc_macro_derive(AuthMember, attributes(auth))]
pub fn derive_auth_member(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let t = derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthMember },
        "AuthMember",
        AUTH_MEMBER_GETTERS,
    );
    let m = derive_meta_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthMemberMeta },
        "AuthMemberMeta",
        AUTH_MEMBER_GETTERS,
    );
    let r = maybe_gen_from_row(&input);
    quote! { #t #m #r }.into()
}

#[proc_macro_derive(AuthInvitation, attributes(auth))]
pub fn derive_auth_invitation(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let t = derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthInvitation },
        "AuthInvitation",
        AUTH_INVITATION_GETTERS,
    );
    let m = derive_meta_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthInvitationMeta },
        "AuthInvitationMeta",
        AUTH_INVITATION_GETTERS,
    );
    let r = maybe_gen_from_row(&input);
    quote! { #t #m #r }.into()
}

#[proc_macro_derive(AuthVerification, attributes(auth))]
pub fn derive_auth_verification(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let t = derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthVerification },
        "AuthVerification",
        AUTH_VERIFICATION_GETTERS,
    );
    let m = derive_meta_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthVerificationMeta },
        "AuthVerificationMeta",
        AUTH_VERIFICATION_GETTERS,
    );
    let r = maybe_gen_from_row(&input);
    quote! { #t #m #r }.into()
}

#[proc_macro_derive(AuthTwoFactor, attributes(auth))]
pub fn derive_auth_two_factor(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let t = derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthTwoFactor },
        "AuthTwoFactor",
        AUTH_TWO_FACTOR_GETTERS,
    );
    let m = derive_meta_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthTwoFactorMeta },
        "AuthTwoFactorMeta",
        AUTH_TWO_FACTOR_GETTERS,
    );
    let r = maybe_gen_from_row(&input);
    quote! { #t #m #r }.into()
}

#[proc_macro_derive(AuthPasskey, attributes(auth))]
pub fn derive_auth_passkey(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let t = derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthPasskey },
        "AuthPasskey",
        AUTH_PASSKEY_GETTERS,
    );
    let m = derive_meta_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthPasskeyMeta },
        "AuthPasskeyMeta",
        AUTH_PASSKEY_GETTERS,
    );
    let r = maybe_gen_from_row(&input);
    quote! { #t #m #r }.into()
}

#[proc_macro_derive(MemoryUser, attributes(auth))]
pub fn derive_memory_user(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_memory_trait(&input, &MEMORY_USER_DEF).into()
}

#[proc_macro_derive(MemorySession, attributes(auth))]
pub fn derive_memory_session(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_memory_trait(&input, &MEMORY_SESSION_DEF).into()
}

#[proc_macro_derive(MemoryAccount, attributes(auth))]
pub fn derive_memory_account(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_memory_trait(&input, &MEMORY_ACCOUNT_DEF).into()
}

#[proc_macro_derive(MemoryOrganization, attributes(auth))]
pub fn derive_memory_organization(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_memory_trait(&input, &MEMORY_ORGANIZATION_DEF).into()
}

#[proc_macro_derive(MemoryMember, attributes(auth))]
pub fn derive_memory_member(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_memory_trait(&input, &MEMORY_MEMBER_DEF).into()
}

#[proc_macro_derive(MemoryInvitation, attributes(auth))]
pub fn derive_memory_invitation(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_memory_trait(&input, &MEMORY_INVITATION_DEF).into()
}

#[proc_macro_derive(MemoryVerification, attributes(auth))]
pub fn derive_memory_verification(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_memory_trait(&input, &MEMORY_VERIFICATION_DEF).into()
}

#[proc_macro_derive(PluginConfig, attributes(plugin, config))]
pub fn derive_plugin_config(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    plugin_config::derive_plugin_config(&input).into()
}
