use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::DeriveInput;

use crate::helpers::ReturnKind::*;
use crate::helpers::{ReturnKind, find_field_for_getter, gen_getter_tokens, parse_named_fields};

/// Core function: given a `DeriveInput`, trait path tokens, trait name (for
/// error messages), and a list of `(getter_name, ReturnKind)` pairs, generate
/// the full `impl Trait for Struct { ... }` block.
pub(crate) fn derive_entity_trait(
    input: &DeriveInput,
    trait_path: TokenStream2,
    trait_name: &str,
    getters: &[(&str, ReturnKind)],
) -> TokenStream2 {
    let struct_name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let field_infos = match parse_named_fields(input, trait_name) {
        Ok(fi) => fi,
        Err(err) => return err,
    };

    // Generate each getter method
    let mut methods = Vec::new();
    for &(getter_name, kind) in getters {
        let getter_ident = syn::Ident::new(getter_name, proc_macro2::Span::call_site());

        let field_ident = match find_field_for_getter(&field_infos, getter_name) {
            Some(ident) => ident.clone(),
            None => {
                let msg = format!(
                    "Missing field '{}' for {} derive. \
                     Add a field `{}: <appropriate_type>` or use \
                     `#[auth(field = \"{}\")]` on an existing field.",
                    getter_name, trait_name, getter_name, getter_name,
                );
                return syn::Error::new_spanned(struct_name, msg).to_compile_error();
            }
        };

        let (ret_type, body) = gen_getter_tokens(&field_ident, kind);

        methods.push(quote! {
            fn #getter_ident(&self) -> #ret_type {
                #body
            }
        });
    }

    quote! {
        impl #impl_generics #trait_path for #struct_name #ty_generics #where_clause {
            #(#methods)*
        }
    }
}

pub(crate) const AUTH_USER_GETTERS: &[(&str, ReturnKind)] = &[
    ("id", RefStr),
    ("email", OptionRefStr),
    ("name", OptionRefStr),
    ("email_verified", Bool),
    ("image", OptionRefStr),
    ("created_at", DateTime),
    ("updated_at", DateTime),
    ("username", OptionRefStr),
    ("display_username", OptionRefStr),
    ("two_factor_enabled", Bool),
    ("role", OptionRefStr),
    ("banned", Bool),
    ("ban_reason", OptionRefStr),
    ("ban_expires", OptionDateTime),
    ("metadata", RefValue),
];

pub(crate) const AUTH_SESSION_GETTERS: &[(&str, ReturnKind)] = &[
    ("id", RefStr),
    ("expires_at", DateTime),
    ("token", RefStr),
    ("created_at", DateTime),
    ("updated_at", DateTime),
    ("ip_address", OptionRefStr),
    ("user_agent", OptionRefStr),
    ("user_id", RefStr),
    ("impersonated_by", OptionRefStr),
    ("active_organization_id", OptionRefStr),
    ("active", Bool),
];

pub(crate) const AUTH_ACCOUNT_GETTERS: &[(&str, ReturnKind)] = &[
    ("id", RefStr),
    ("account_id", RefStr),
    ("provider_id", RefStr),
    ("user_id", RefStr),
    ("access_token", OptionRefStr),
    ("refresh_token", OptionRefStr),
    ("id_token", OptionRefStr),
    ("access_token_expires_at", OptionDateTime),
    ("refresh_token_expires_at", OptionDateTime),
    ("scope", OptionRefStr),
    ("password", OptionRefStr),
    ("created_at", DateTime),
    ("updated_at", DateTime),
];

pub(crate) const AUTH_ORGANIZATION_GETTERS: &[(&str, ReturnKind)] = &[
    ("id", RefStr),
    ("name", RefStr),
    ("slug", RefStr),
    ("logo", OptionRefStr),
    ("metadata", OptionRefValue),
    ("created_at", DateTime),
    ("updated_at", DateTime),
];

pub(crate) const AUTH_MEMBER_GETTERS: &[(&str, ReturnKind)] = &[
    ("id", RefStr),
    ("organization_id", RefStr),
    ("user_id", RefStr),
    ("role", RefStr),
    ("created_at", DateTime),
];

pub(crate) const AUTH_INVITATION_GETTERS: &[(&str, ReturnKind)] = &[
    ("id", RefStr),
    ("organization_id", RefStr),
    ("email", RefStr),
    ("role", RefStr),
    ("status", RefStatus),
    ("inviter_id", RefStr),
    ("expires_at", DateTime),
    ("created_at", DateTime),
];

pub(crate) const AUTH_VERIFICATION_GETTERS: &[(&str, ReturnKind)] = &[
    ("id", RefStr),
    ("identifier", RefStr),
    ("value", RefStr),
    ("expires_at", DateTime),
    ("created_at", DateTime),
    ("updated_at", DateTime),
];

pub(crate) const AUTH_TWO_FACTOR_GETTERS: &[(&str, ReturnKind)] = &[
    ("id", RefStr),
    ("secret", RefStr),
    ("backup_codes", OptionRefStr),
    ("user_id", RefStr),
];

pub(crate) const AUTH_PASSKEY_GETTERS: &[(&str, ReturnKind)] = &[
    ("id", RefStr),
    ("name", RefStr),
    ("public_key", RefStr),
    ("user_id", RefStr),
    ("credential_id", RefStr),
    ("counter", U64),
    ("device_type", RefStr),
    ("backed_up", Bool),
];
