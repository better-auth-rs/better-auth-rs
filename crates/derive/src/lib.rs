//! Proc macros used by the Better Auth root crates.

mod auth_schema;
mod plugin_config;

use proc_macro::TokenStream;
use syn::{DeriveInput, parse_macro_input};

#[proc_macro_derive(AuthSchema, attributes(auth))]
pub fn derive_auth_schema(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    auth_schema::derive_auth_schema(&input).into()
}

#[proc_macro_derive(PluginConfig, attributes(plugin, config))]
pub fn derive_plugin_config(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    plugin_config::derive_plugin_config(&input).into()
}

mod database_hooks;

/// Generate callback-presence metadata and asynchronous trait adaptation.
#[proc_macro_attribute]
pub fn database_hooks(source: TokenStream, item: TokenStream) -> TokenStream {
    let source = if source.is_empty() {
        None
    } else {
        Some(parse_macro_input!(source as syn::LitStr))
    };
    database_hooks::expand(source, parse_macro_input!(item as syn::ItemImpl)).into()
}
