//! Proc macros used internally by the better-auth workspace.

mod plugin_config;

use proc_macro::TokenStream;
use syn::{DeriveInput, parse_macro_input};

#[proc_macro_derive(PluginConfig, attributes(plugin, config))]
pub fn derive_plugin_config(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    plugin_config::derive_plugin_config(&input).into()
}
