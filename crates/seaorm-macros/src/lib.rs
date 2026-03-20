//! Proc macros for the Better Auth SeaORM integration.

mod auth_entity;

use proc_macro::TokenStream;
use syn::{DeriveInput, parse_macro_input};

#[proc_macro_derive(AuthEntity, attributes(auth))]
pub fn derive_auth_entity(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    auth_entity::derive_auth_entity(&input).into()
}
