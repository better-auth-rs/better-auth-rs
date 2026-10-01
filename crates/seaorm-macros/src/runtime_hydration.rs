use proc_macro2::TokenStream;
use quote::quote;
use syn::{DeriveInput, Expr, FieldsNamed, Lit, Meta, Token, punctuated::Punctuated};

pub(super) fn generate(
    input: &DeriveInput,
    fields: &FieldsNamed,
    known: &[&str],
    core: &TokenStream,
    session: bool,
) -> syn::Result<TokenStream> {
    let rule = super::serde_serialized_name(&input.attrs, "rename_all")?
        .map(|rule| {
            serde_rename_rule::RenameRule::from_rename_all_str(&rule)
                .map_err(|error| syn::Error::new_spanned(input, error.to_string()))
        })
        .transpose()?;
    let mut values = Vec::new();
    let mut serialized_names = Vec::new();
    for field in &fields.named {
        let Some(ident) = &field.ident else { continue };
        let rust_name = ident.to_string();
        let name = if known.contains(&rust_name.as_str()) {
            serde_rename_rule::RenameRule::CamelCase.apply_to_field(&rust_name)
        } else {
            super::serde_serialized_name(&field.attrs, "rename")?.unwrap_or_else(|| {
                rule.as_ref()
                    .map_or_else(|| rust_name.clone(), |rule| rule.apply_to_field(&rust_name))
            })
        };
        if !known.contains(&rust_name.as_str()) {
            let aliases = field_aliases(&rust_name, &name);
            serialized_names.push(quote!(#(#aliases)|* => #name,));
        }
        let mut default = None;
        for attr in field
            .attrs
            .iter()
            .filter(|attr| attr.path().is_ident("serde"))
        {
            for meta in attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)? {
                match meta {
                    Meta::Path(path) if path.is_ident("default") => {
                        default = Some(quote!(::std::default::Default::default()))
                    }
                    Meta::NameValue(value) if value.path.is_ident("default") => {
                        if let Expr::Lit(value) = value.value
                            && let Lit::Str(path) = value.lit
                        {
                            let path: syn::Path = path.parse()?;
                            default = Some(quote!(#path()));
                        }
                    }
                    _ => {}
                }
            }
        }
        let value = if rust_name == "active" {
            quote!(true)
        } else if let Some(default) = default {
            quote!(match fields.remove(#name) {
                Some(value) => #core::serde_json::from_value(value)?,
                None => #default,
            })
        } else {
            quote!(#core::serde_json::from_value(fields.remove(#name).unwrap_or(#core::serde_json::Value::Null))?)
        };
        values.push(quote!(#ident: #value));
    }
    let serialized_names = session.then(|| {
        quote! {
            fn serialized_field_name(name: &str) -> &str {
                match name { #(#serialized_names)* _ => name }
            }
        }
    });
    Ok(quote! {
        #serialized_names
        const SUPPORTS_RUNTIME_HYDRATION: bool = true;
        fn from_runtime_fields(mut fields: #core::serde_json::Map<String, #core::serde_json::Value>) -> #core::AuthResult<Self> {
            Ok(Self { #(#values,)* })
        }
    })
}

pub(super) fn field_aliases(rust_name: &str, serialized: &str) -> Vec<String> {
    let mut aliases = vec![
        rust_name.to_owned(),
        serialized.to_owned(),
        serde_rename_rule::RenameRule::CamelCase.apply_to_field(rust_name),
    ];
    aliases.sort();
    aliases.dedup();
    aliases
}
