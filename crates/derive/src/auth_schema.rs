use proc_macro2::TokenStream;
use quote::quote;
use syn::{DeriveInput, LitStr, Type};

pub(crate) fn derive_auth_schema(input: &DeriveInput) -> TokenStream {
    let user = match parse_type_attr(input, "user") {
        Ok(value) => value,
        Err(err) => return err.to_compile_error(),
    };
    let session = match parse_type_attr(input, "session") {
        Ok(value) => value,
        Err(err) => return err.to_compile_error(),
    };
    let account = match parse_type_attr(input, "account") {
        Ok(value) => value,
        Err(err) => return err.to_compile_error(),
    };
    let verification = match parse_type_attr(input, "verification") {
        Ok(value) => value,
        Err(err) => return err.to_compile_error(),
    };
    let ident = &input.ident;

    quote! {
        impl ::better_auth::__private_core::schema::AuthSchema for #ident {
            type User = #user;
            type Session = #session;
            type Account = #account;
            type Verification = #verification;
        }
    }
}

fn parse_type_attr(input: &DeriveInput, key: &str) -> Result<Type, syn::Error> {
    let mut parsed = None;
    for attr in &input.attrs {
        if !attr.path().is_ident("auth") {
            continue;
        }

        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident(key) {
                let value = meta.value()?;
                let ty: LitStr = value.parse()?;
                parsed = Some(ty.parse()?);
                Ok(())
            } else {
                Ok(())
            }
        })?;
    }

    parsed.ok_or_else(|| {
        syn::Error::new_spanned(
            input,
            format!("missing #[auth({key} = path::to::Model)] attribute for AuthSchema"),
        )
    })
}
