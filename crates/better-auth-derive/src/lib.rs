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
//!     pub metadata: HashMap<String, serde_json::Value>,
//! }
//! ```

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{DeriveInput, parse_macro_input};

// ---------------------------------------------------------------------------
// Return-type kinds
// ---------------------------------------------------------------------------

/// Describes how a trait getter returns a value and how the generated code
/// should access the corresponding struct field.
#[derive(Clone, Copy)]
enum ReturnKind {
    /// `fn x(&self) -> &str` — field is `String`
    RefStr,
    /// `fn x(&self) -> Option<&str>` — field is `Option<String>`
    OptionRefStr,
    /// `fn x(&self) -> bool` — field is `bool`
    Bool,
    /// `fn x(&self) -> u64` — field is `u64`
    U64,
    /// `fn x(&self) -> DateTime<Utc>` — field is `DateTime<Utc>`
    DateTime,
    /// `fn x(&self) -> Option<DateTime<Utc>>` — field is `Option<DateTime<Utc>>`
    OptionDateTime,
    /// `fn x(&self) -> &HashMap<String, Value>` — field is `HashMap<String, Value>`
    RefHashMap,
    /// `fn x(&self) -> &InvitationStatus` — field is `InvitationStatus`
    RefStatus,
    /// `fn x(&self) -> Option<&serde_json::Value>` — field is `Option<serde_json::Value>`
    OptionRefValue,
}

/// One getter that needs to be generated for a trait.
struct GetterDef {
    /// The name of the getter method (e.g. `"user_id"`).
    getter_name: &'static str,
    /// How the value is returned.
    kind: ReturnKind,
}

// ---------------------------------------------------------------------------
// Field resolution helpers
// ---------------------------------------------------------------------------

/// Parsed information about a struct field relevant to our derive.
struct FieldInfo {
    /// The identifier of the struct field.
    ident: syn::Ident,
    /// If the field has `#[auth(field = "...")]`, the overridden getter name.
    auth_field_name: Option<String>,
}

/// Parse `#[auth(field = "getter_name")]` from field attributes.
fn parse_auth_attr(attrs: &[syn::Attribute]) -> Option<String> {
    for attr in attrs {
        if !attr.path().is_ident("auth") {
            continue;
        }
        // Parse: #[auth(field = "some_name")]
        let mut field_name = None;
        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("field") {
                let value = meta.value()?;
                let lit: syn::LitStr = value.parse()?;
                field_name = Some(lit.value());
            }
            Ok(())
        });
        if field_name.is_some() {
            return field_name;
        }
    }
    None
}

/// Given a list of parsed fields and a getter name, find the matching field.
///
/// Matching rules:
/// 1. A field with `#[auth(field = "getter_name")]` takes priority.
/// 2. Otherwise, a field whose identifier equals `getter_name`.
fn find_field_for_getter<'a>(fields: &'a [FieldInfo], getter_name: &str) -> Option<&'a syn::Ident> {
    // Priority 1: explicit #[auth(field = "...")] annotation
    for f in fields {
        if let Some(ref mapped) = f.auth_field_name
            && mapped == getter_name
        {
            return Some(&f.ident);
        }
    }
    // Priority 2: field name matches getter name
    for f in fields {
        if f.ident == getter_name {
            return Some(&f.ident);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Code generation
// ---------------------------------------------------------------------------

/// Generate the return-type tokens and method-body tokens for a single getter.
fn gen_getter_tokens(field_ident: &syn::Ident, kind: ReturnKind) -> (TokenStream2, TokenStream2) {
    match kind {
        ReturnKind::RefStr => (quote! { &str }, quote! { &self.#field_ident }),
        ReturnKind::OptionRefStr => (
            quote! { ::core::option::Option<&str> },
            quote! { self.#field_ident.as_deref() },
        ),
        ReturnKind::Bool => (quote! { bool }, quote! { self.#field_ident }),
        ReturnKind::U64 => (quote! { u64 }, quote! { self.#field_ident }),
        ReturnKind::DateTime => (
            quote! { ::chrono::DateTime<::chrono::Utc> },
            quote! { self.#field_ident },
        ),
        ReturnKind::OptionDateTime => (
            quote! { ::core::option::Option<::chrono::DateTime<::chrono::Utc>> },
            quote! { self.#field_ident },
        ),
        ReturnKind::RefHashMap => (
            quote! { &::std::collections::HashMap<::std::string::String, ::serde_json::Value> },
            quote! { &self.#field_ident },
        ),
        ReturnKind::RefStatus => (
            quote! { &::better_auth_core::types::InvitationStatus },
            quote! { &self.#field_ident },
        ),
        ReturnKind::OptionRefValue => (
            quote! { ::core::option::Option<&::serde_json::Value> },
            quote! { self.#field_ident.as_ref() },
        ),
    }
}

/// Core function: given a `DeriveInput`, trait path tokens, trait name (for
/// error messages), and a list of getter definitions, generate the full
/// `impl Trait for Struct { ... }` block.
fn derive_entity_trait(
    input: &DeriveInput,
    trait_path: TokenStream2,
    trait_name: &str,
    getters: &[GetterDef],
) -> TokenStream2 {
    let struct_name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    // Extract named fields
    let named_fields = match &input.data {
        syn::Data::Struct(data) => match &data.fields {
            syn::Fields::Named(fields) => &fields.named,
            _ => {
                return syn::Error::new_spanned(
                    struct_name,
                    format!(
                        "{} can only be derived for structs with named fields",
                        trait_name
                    ),
                )
                .to_compile_error();
            }
        },
        _ => {
            return syn::Error::new_spanned(
                struct_name,
                format!("{} can only be derived for structs", trait_name),
            )
            .to_compile_error();
        }
    };

    // Parse field info
    let field_infos: Vec<FieldInfo> = named_fields
        .iter()
        .filter_map(|f| {
            let ident = f.ident.clone()?;
            let auth_field_name = parse_auth_attr(&f.attrs);
            Some(FieldInfo {
                ident,
                auth_field_name,
            })
        })
        .collect();

    // Generate each getter method
    let mut methods = Vec::new();
    for getter in getters {
        let getter_ident = syn::Ident::new(getter.getter_name, proc_macro2::Span::call_site());

        let field_ident = match find_field_for_getter(&field_infos, getter.getter_name) {
            Some(ident) => ident.clone(),
            None => {
                let msg = format!(
                    "Missing field '{}' for {} derive. \
                     Add a field `{}: <appropriate_type>` or use \
                     `#[auth(field = \"{}\")]` on an existing field.",
                    getter.getter_name, trait_name, getter.getter_name, getter.getter_name,
                );
                return syn::Error::new_spanned(struct_name, msg).to_compile_error();
            }
        };

        let (ret_type, body) = gen_getter_tokens(&field_ident, getter.kind);

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

// ---------------------------------------------------------------------------
// Macro definitions — one per entity trait
// ---------------------------------------------------------------------------

#[proc_macro_derive(AuthUser, attributes(auth))]
pub fn derive_auth_user(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let getters = vec![
        GetterDef {
            getter_name: "id",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "email",
            kind: ReturnKind::OptionRefStr,
        },
        GetterDef {
            getter_name: "name",
            kind: ReturnKind::OptionRefStr,
        },
        GetterDef {
            getter_name: "email_verified",
            kind: ReturnKind::Bool,
        },
        GetterDef {
            getter_name: "image",
            kind: ReturnKind::OptionRefStr,
        },
        GetterDef {
            getter_name: "created_at",
            kind: ReturnKind::DateTime,
        },
        GetterDef {
            getter_name: "updated_at",
            kind: ReturnKind::DateTime,
        },
        GetterDef {
            getter_name: "username",
            kind: ReturnKind::OptionRefStr,
        },
        GetterDef {
            getter_name: "display_username",
            kind: ReturnKind::OptionRefStr,
        },
        GetterDef {
            getter_name: "two_factor_enabled",
            kind: ReturnKind::Bool,
        },
        GetterDef {
            getter_name: "role",
            kind: ReturnKind::OptionRefStr,
        },
        GetterDef {
            getter_name: "banned",
            kind: ReturnKind::Bool,
        },
        GetterDef {
            getter_name: "ban_reason",
            kind: ReturnKind::OptionRefStr,
        },
        GetterDef {
            getter_name: "ban_expires",
            kind: ReturnKind::OptionDateTime,
        },
        GetterDef {
            getter_name: "metadata",
            kind: ReturnKind::RefHashMap,
        },
    ];
    derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthUser },
        "AuthUser",
        &getters,
    )
    .into()
}

#[proc_macro_derive(AuthSession, attributes(auth))]
pub fn derive_auth_session(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let getters = vec![
        GetterDef {
            getter_name: "id",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "expires_at",
            kind: ReturnKind::DateTime,
        },
        GetterDef {
            getter_name: "token",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "created_at",
            kind: ReturnKind::DateTime,
        },
        GetterDef {
            getter_name: "updated_at",
            kind: ReturnKind::DateTime,
        },
        GetterDef {
            getter_name: "ip_address",
            kind: ReturnKind::OptionRefStr,
        },
        GetterDef {
            getter_name: "user_agent",
            kind: ReturnKind::OptionRefStr,
        },
        GetterDef {
            getter_name: "user_id",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "impersonated_by",
            kind: ReturnKind::OptionRefStr,
        },
        GetterDef {
            getter_name: "active_organization_id",
            kind: ReturnKind::OptionRefStr,
        },
        GetterDef {
            getter_name: "active",
            kind: ReturnKind::Bool,
        },
    ];
    derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthSession },
        "AuthSession",
        &getters,
    )
    .into()
}

#[proc_macro_derive(AuthAccount, attributes(auth))]
pub fn derive_auth_account(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let getters = vec![
        GetterDef {
            getter_name: "id",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "account_id",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "provider_id",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "user_id",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "access_token",
            kind: ReturnKind::OptionRefStr,
        },
        GetterDef {
            getter_name: "refresh_token",
            kind: ReturnKind::OptionRefStr,
        },
        GetterDef {
            getter_name: "id_token",
            kind: ReturnKind::OptionRefStr,
        },
        GetterDef {
            getter_name: "access_token_expires_at",
            kind: ReturnKind::OptionDateTime,
        },
        GetterDef {
            getter_name: "refresh_token_expires_at",
            kind: ReturnKind::OptionDateTime,
        },
        GetterDef {
            getter_name: "scope",
            kind: ReturnKind::OptionRefStr,
        },
        GetterDef {
            getter_name: "password",
            kind: ReturnKind::OptionRefStr,
        },
        GetterDef {
            getter_name: "created_at",
            kind: ReturnKind::DateTime,
        },
        GetterDef {
            getter_name: "updated_at",
            kind: ReturnKind::DateTime,
        },
    ];
    derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthAccount },
        "AuthAccount",
        &getters,
    )
    .into()
}

#[proc_macro_derive(AuthOrganization, attributes(auth))]
pub fn derive_auth_organization(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let getters = vec![
        GetterDef {
            getter_name: "id",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "name",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "slug",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "logo",
            kind: ReturnKind::OptionRefStr,
        },
        GetterDef {
            getter_name: "metadata",
            kind: ReturnKind::OptionRefValue,
        },
        GetterDef {
            getter_name: "created_at",
            kind: ReturnKind::DateTime,
        },
        GetterDef {
            getter_name: "updated_at",
            kind: ReturnKind::DateTime,
        },
    ];
    derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthOrganization },
        "AuthOrganization",
        &getters,
    )
    .into()
}

#[proc_macro_derive(AuthMember, attributes(auth))]
pub fn derive_auth_member(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let getters = vec![
        GetterDef {
            getter_name: "id",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "organization_id",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "user_id",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "role",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "created_at",
            kind: ReturnKind::DateTime,
        },
    ];
    derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthMember },
        "AuthMember",
        &getters,
    )
    .into()
}

#[proc_macro_derive(AuthInvitation, attributes(auth))]
pub fn derive_auth_invitation(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    // Only required methods — `is_pending` and `is_expired` have default impls.
    let getters = vec![
        GetterDef {
            getter_name: "id",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "organization_id",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "email",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "role",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "status",
            kind: ReturnKind::RefStatus,
        },
        GetterDef {
            getter_name: "inviter_id",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "expires_at",
            kind: ReturnKind::DateTime,
        },
        GetterDef {
            getter_name: "created_at",
            kind: ReturnKind::DateTime,
        },
    ];
    derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthInvitation },
        "AuthInvitation",
        &getters,
    )
    .into()
}

#[proc_macro_derive(AuthVerification, attributes(auth))]
pub fn derive_auth_verification(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let getters = vec![
        GetterDef {
            getter_name: "id",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "identifier",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "value",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "expires_at",
            kind: ReturnKind::DateTime,
        },
        GetterDef {
            getter_name: "created_at",
            kind: ReturnKind::DateTime,
        },
        GetterDef {
            getter_name: "updated_at",
            kind: ReturnKind::DateTime,
        },
    ];
    derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthVerification },
        "AuthVerification",
        &getters,
    )
    .into()
}

#[proc_macro_derive(AuthTwoFactor, attributes(auth))]
pub fn derive_auth_two_factor(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let getters = vec![
        GetterDef {
            getter_name: "id",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "secret",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "backup_codes",
            kind: ReturnKind::OptionRefStr,
        },
        GetterDef {
            getter_name: "user_id",
            kind: ReturnKind::RefStr,
        },
    ];
    derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthTwoFactor },
        "AuthTwoFactor",
        &getters,
    )
    .into()
}

#[proc_macro_derive(AuthPasskey, attributes(auth))]
pub fn derive_auth_passkey(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let getters = vec![
        GetterDef {
            getter_name: "id",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "name",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "public_key",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "user_id",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "credential_id",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "counter",
            kind: ReturnKind::U64,
        },
        GetterDef {
            getter_name: "device_type",
            kind: ReturnKind::RefStr,
        },
        GetterDef {
            getter_name: "backed_up",
            kind: ReturnKind::Bool,
        },
    ];
    derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthPasskey },
        "AuthPasskey",
        &getters,
    )
    .into()
}
