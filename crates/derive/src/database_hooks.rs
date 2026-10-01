use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{ImplItem, ItemImpl, LitStr};

pub(crate) fn expand(source: Option<LitStr>, mut implementation: ItemImpl) -> TokenStream {
    let core = quote!(::better_auth::__private_core);
    let source = source.unwrap_or_else(|| LitStr::new("user", proc_macro2::Span::call_site()));
    let methods: Vec<_> = implementation
        .items
        .iter()
        .filter_map(|item| {
            let ImplItem::Fn(method) = item else {
                return None;
            };
            let name = method.sig.ident.to_string();
            if !(name.starts_with("before_") || name.starts_with("after_")) {
                return None;
            }
            let variant = name
                .split('_')
                .map(|part| {
                    let mut chars = part.chars();
                    chars
                        .next()
                        .into_iter()
                        .flat_map(char::to_uppercase)
                        .chain(chars)
                        .collect::<String>()
                })
                .collect::<String>();
            Some(format_ident!("{variant}"))
        })
        .collect();
    implementation.items.push(syn::parse_quote! {
        fn hook_metadata(&self) -> #core::observability::database::DatabaseHookMetadata {
            #core::observability::database::DatabaseHookMetadata {
                methods: &[#(#core::observability::database::DatabaseHook::#methods),*],
                source: #source,
            }
        }
    });
    quote! { #[#core::__private_async_trait::async_trait] #implementation }
}
