use proc_macro2::TokenStream;
use quote::quote;
use syn::{DeriveInput, FieldsNamed};

pub(super) fn generate(
    input: &DeriveInput,
    fields: &FieldsNamed,
    known: &[&str],
) -> syn::Result<TokenStream> {
    let rule = super::serde_serialized_name(&input.attrs, "rename_all")?
        .map(|rule| {
            serde_rename_rule::RenameRule::from_rename_all_str(&rule)
                .map_err(|error| syn::Error::new_spanned(input, error.to_string()))
        })
        .transpose()?;
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
    }
    Ok(quote! {
        fn serialized_field_name(name: &str) -> &str {
            match name { #(#serialized_names)* _ => name }
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
