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
    /// `fn x(&self) -> &serde_json::Value` — field is `serde_json::Value`
    RefValue,
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
    /// If the field has `#[auth(default = "...")]`, the default expression.
    auth_default: Option<TokenStream2>,
}

/// Parse `#[auth(...)]` attributes from a field.
///
/// Supported:
/// - `#[auth(field = "getter_name")]` — remap field to a getter name
/// - `#[auth(default = "expr")]` — default expression for Memory* derives
fn parse_auth_attrs(attrs: &[syn::Attribute]) -> (Option<String>, Option<TokenStream2>) {
    let mut field_name = None;
    let mut default_expr = None;
    for attr in attrs {
        if !attr.path().is_ident("auth") {
            continue;
        }
        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("field") {
                let value = meta.value()?;
                let lit: syn::LitStr = value.parse()?;
                field_name = Some(lit.value());
            } else if meta.path.is_ident("default") {
                let value = meta.value()?;
                let lit: syn::LitStr = value.parse()?;
                let parsed: syn::Expr = syn::parse_str(&lit.value()).map_err(|e| {
                    syn::Error::new_spanned(&lit, format!("invalid default expression: {e}"))
                })?;
                default_expr = Some(quote! { #parsed });
            }
            Ok(())
        });
    }
    (field_name, default_expr)
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
        ReturnKind::RefValue => (
            quote! { &::serde_json::Value },
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

// ---------------------------------------------------------------------------
// FromRow generation (enabled via #[auth(from_row)] on the struct)
// ---------------------------------------------------------------------------

/// Check if the struct has `#[auth(from_row)]`.
fn has_auth_from_row(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("auth") {
            return false;
        }
        let mut found = false;
        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("from_row") {
                found = true;
            }
            Ok(())
        });
        found
    })
}

/// Parsed field information for FromRow generation.
struct FromRowField {
    ident: syn::Ident,
    ty: syn::Type,
    is_json: bool,
    default_expr: Option<TokenStream2>,
}

/// Parse fields for FromRow generation, extracting type info and relevant attributes.
fn parse_from_row_fields(input: &DeriveInput) -> Result<Vec<FromRowField>, TokenStream2> {
    let struct_name = &input.ident;
    let named_fields = match &input.data {
        syn::Data::Struct(data) => match &data.fields {
            syn::Fields::Named(fields) => &fields.named,
            _ => {
                return Err(syn::Error::new_spanned(
                    struct_name,
                    "from_row requires a struct with named fields",
                )
                .to_compile_error());
            }
        },
        _ => {
            return Err(
                syn::Error::new_spanned(struct_name, "from_row requires a struct")
                    .to_compile_error(),
            );
        }
    };

    Ok(named_fields
        .iter()
        .filter_map(|f| {
            let ident = f.ident.clone()?;
            let ty = f.ty.clone();
            let mut is_json = false;
            let mut default_expr = None;

            for attr in &f.attrs {
                if !attr.path().is_ident("auth") {
                    continue;
                }
                let _ = attr.parse_nested_meta(|meta| {
                    if meta.path.is_ident("json") {
                        is_json = true;
                    } else if meta.path.is_ident("default") {
                        let value = meta.value()?;
                        let lit: syn::LitStr = value.parse()?;
                        let parsed: syn::Expr =
                            syn::parse_str(&lit.value()).map_err(|e| {
                                syn::Error::new_spanned(
                                    &lit,
                                    format!("invalid default expression: {e}"),
                                )
                            })?;
                        default_expr = Some(quote! { #parsed });
                    }
                    Ok(())
                });
            }

            Some(FromRowField {
                ident,
                ty,
                is_json,
                default_expr,
            })
        })
        .collect())
}

/// Extract the inner type `T` from `Option<T>`.
fn extract_option_inner(ty: &syn::Type) -> Option<&syn::Type> {
    let syn::Type::Path(type_path) = ty else {
        return None;
    };
    let segment = type_path.path.segments.last()?;
    if segment.ident != "Option" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(ref args) = segment.arguments else {
        return None;
    };
    match args.args.first()? {
        syn::GenericArgument::Type(inner) => Some(inner),
        _ => None,
    }
}

/// Get the last path segment identifier as a string.
fn type_last_segment_name(ty: &syn::Type) -> Option<String> {
    let syn::Type::Path(type_path) = ty else {
        return None;
    };
    type_path
        .path
        .segments
        .last()
        .map(|s| s.ident.to_string())
}

/// Known types that sqlx can decode directly (no special handling needed).
fn is_known_sqlx_type_name(name: &str) -> bool {
    matches!(
        name,
        "String"
            | "bool"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "f32"
            | "f64"
            | "DateTime"
            | "DateTimeUtc"
            | "NaiveDateTime"
            | "NaiveDate"
            | "NaiveTime"
            | "Uuid"
    )
}

/// Check if a type name refers to a JSON value type.
fn is_json_type_name(name: &str) -> bool {
    name == "Json" || name == "Value"
}

/// Generate the expression for a single field in a `FromRow` impl.
///
/// Classification logic:
/// 1. Explicit `#[auth(json)]` or auto-detected `Json`/`Value` type → JSON unwrap
/// 2. `#[auth(default = "expr")]` → `try_get(...).unwrap_or_else(|_| expr)`
/// 3. Unknown non-Option type (not in known list) → assume `From<String>` enum
/// 4. Everything else → simple `try_get`
fn gen_from_row_field_expr(field: &FromRowField) -> TokenStream2 {
    let ident = &field.ident;
    let col_name = ident.to_string();

    // Unwrap Option<T> to inspect the inner type
    let (is_option, inner_ty) = match extract_option_inner(&field.ty) {
        Some(inner) => (true, inner),
        None => (false, &field.ty),
    };

    let inner_name = type_last_segment_name(inner_ty);
    let is_json = field.is_json || inner_name.as_deref().is_some_and(is_json_type_name);
    let is_known = inner_name.as_deref().is_some_and(is_known_sqlx_type_name);

    if is_json && is_option {
        // Option<Json> / Option<serde_json::Value>
        quote! {
            #ident: row.try_get::<
                ::core::option::Option<::sqlx::types::Json<::serde_json::Value>>, _
            >(#col_name)?.map(|j| j.0)
        }
    } else if is_json {
        // Json / serde_json::Value
        quote! {
            #ident: row.try_get::<
                ::sqlx::types::Json<::serde_json::Value>, _
            >(#col_name)?.0
        }
    } else if let Some(ref default_expr) = field.default_expr {
        // Field with a default value
        quote! {
            #ident: row.try_get(#col_name).unwrap_or_else(|_| #default_expr)
        }
    } else if !is_known && !is_option {
        // Unknown non-Option type → assume enum implementing From<String>
        quote! {
            #ident: {
                let __s: ::std::string::String = row.try_get(#col_name)?;
                ::core::convert::From::from(__s)
            }
        }
    } else {
        // Known type or Option<known> → simple try_get
        quote! {
            #ident: row.try_get(#col_name)?
        }
    }
}

/// If the struct has `#[auth(from_row)]`, generate an
/// `impl sqlx::FromRow<'_, PgRow> for Struct` block.
/// Returns empty tokens if the attribute is absent.
fn maybe_gen_from_row(input: &DeriveInput) -> TokenStream2 {
    if !has_auth_from_row(&input.attrs) {
        return quote! {};
    }

    let fields = match parse_from_row_fields(input) {
        Ok(f) => f,
        Err(e) => return e,
    };

    let struct_name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let field_exprs: Vec<TokenStream2> = fields.iter().map(gen_from_row_field_expr).collect();

    quote! {
        impl #impl_generics ::sqlx::FromRow<'_, ::sqlx::postgres::PgRow>
            for #struct_name #ty_generics #where_clause
        {
            fn from_row(
                row: &::sqlx::postgres::PgRow,
            ) -> ::core::result::Result<Self, ::sqlx::Error> {
                use ::sqlx::Row as _;
                ::core::result::Result::Ok(Self {
                    #(#field_exprs),*
                })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Code generation
// ---------------------------------------------------------------------------

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
            let (auth_field_name, auth_default) = parse_auth_attrs(&f.attrs);
            Some(FieldInfo {
                ident,
                auth_field_name,
                auth_default,
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
            kind: ReturnKind::RefValue,
        },
    ];
    let trait_impl = derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthUser },
        "AuthUser",
        &getters,
    );
    let from_row_impl = maybe_gen_from_row(&input);
    quote! { #trait_impl #from_row_impl }.into()
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
    let trait_impl = derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthSession },
        "AuthSession",
        &getters,
    );
    let from_row_impl = maybe_gen_from_row(&input);
    quote! { #trait_impl #from_row_impl }.into()
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
    let trait_impl = derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthAccount },
        "AuthAccount",
        &getters,
    );
    let from_row_impl = maybe_gen_from_row(&input);
    quote! { #trait_impl #from_row_impl }.into()
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
    let trait_impl = derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthOrganization },
        "AuthOrganization",
        &getters,
    );
    let from_row_impl = maybe_gen_from_row(&input);
    quote! { #trait_impl #from_row_impl }.into()
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
    let trait_impl = derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthMember },
        "AuthMember",
        &getters,
    );
    let from_row_impl = maybe_gen_from_row(&input);
    quote! { #trait_impl #from_row_impl }.into()
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
    let trait_impl = derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthInvitation },
        "AuthInvitation",
        &getters,
    );
    let from_row_impl = maybe_gen_from_row(&input);
    quote! { #trait_impl #from_row_impl }.into()
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
    let trait_impl = derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthVerification },
        "AuthVerification",
        &getters,
    );
    let from_row_impl = maybe_gen_from_row(&input);
    quote! { #trait_impl #from_row_impl }.into()
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
    let trait_impl = derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthTwoFactor },
        "AuthTwoFactor",
        &getters,
    );
    let from_row_impl = maybe_gen_from_row(&input);
    quote! { #trait_impl #from_row_impl }.into()
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
    let trait_impl = derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthPasskey },
        "AuthPasskey",
        &getters,
    );
    let from_row_impl = maybe_gen_from_row(&input);
    quote! { #trait_impl #from_row_impl }.into()
}

// ===========================================================================
// Memory trait derive macros
//
// Generate `MemoryUser`, `MemorySession`, etc. implementations that tell
// the generic `MemoryDatabaseAdapter` how to construct and mutate custom
// entity types.
// ===========================================================================

// -- Helpers for from_create code generation --

/// How a struct field is initialised inside `from_create`.
enum CreateInit {
    /// The `id` parameter.
    IdParam,
    /// The `token` parameter (sessions only).
    TokenParam,
    /// The `now` parameter.
    NowParam,
    /// `create.<field>.clone()`
    CloneCreate(&'static str),
    /// `create.<field>` (Copy types like DateTime)
    CopyCreate(&'static str),
    /// `create.<field>.unwrap_or(false)`
    UnwrapBoolCreate(&'static str),
    /// `create.<field>.clone().unwrap_or_default()`
    UnwrapDefaultCreate(&'static str),
    /// A literal `true` or `false`.
    StaticBool(bool),
    /// `None`
    StaticNone,
    /// `InvitationStatus::Pending`
    InvitationPending,
}

fn gen_create_init_expr(init: &CreateInit) -> TokenStream2 {
    match init {
        CreateInit::IdParam => quote! { id },
        CreateInit::TokenParam => quote! { token },
        CreateInit::NowParam => quote! { now },
        CreateInit::CloneCreate(f) => {
            let field = mk_ident(f);
            quote! { create.#field.clone() }
        }
        CreateInit::CopyCreate(f) => {
            let field = mk_ident(f);
            quote! { create.#field }
        }
        CreateInit::UnwrapBoolCreate(f) => {
            let field = mk_ident(f);
            quote! { create.#field.unwrap_or(false) }
        }
        CreateInit::UnwrapDefaultCreate(f) => {
            let field = mk_ident(f);
            quote! { create.#field.clone().unwrap_or_default() }
        }
        CreateInit::StaticBool(b) => quote! { #b },
        CreateInit::StaticNone => quote! { ::core::option::Option::None },
        CreateInit::InvitationPending => {
            quote! { ::better_auth_core::types::InvitationStatus::Pending }
        }
    }
}

/// Build the `Self { field: expr, ... }` body for `from_create`.
fn gen_from_create_body(
    field_infos: &[FieldInfo],
    create_mappings: &[(&str, CreateInit)],
) -> TokenStream2 {
    let field_inits: Vec<TokenStream2> = field_infos
        .iter()
        .map(|info| {
            let field_ident = &info.ident;
            let ident_str = info.ident.to_string();
            let getter_name = info.auth_field_name.as_deref().unwrap_or(&ident_str);

            let init_expr = create_mappings
                .iter()
                .find(|(name, _)| *name == getter_name)
                .map(|(_, init)| gen_create_init_expr(init))
                .unwrap_or_else(|| {
                    if let Some(ref expr) = info.auth_default {
                        expr.clone()
                    } else {
                        quote! { ::core::default::Default::default() }
                    }
                });

            quote! { #field_ident: #init_expr }
        })
        .collect();

    quote! { Self { #(#field_inits),* } }
}

// -- Helpers for apply_update code generation --

/// How an update field is applied to the struct.
#[derive(Clone, Copy)]
enum UpdateApply {
    /// `if let Some(v) = &update.f { self.f = Some(v.clone()); }`
    CloneIntoOption,
    /// `if let Some(v) = update.f { self.f = v; }`
    CopyDirect,
    /// `if let Some(v) = update.f { self.f = Some(v); }`
    CopyIntoOption,
    /// `if let Some(v) = &update.f { self.f = v.clone(); }`
    CloneDirect,
}

fn gen_update_apply_stmt(
    struct_field: &syn::Ident,
    update_field: &syn::Ident,
    apply: UpdateApply,
) -> TokenStream2 {
    match apply {
        UpdateApply::CloneIntoOption => quote! {
            if let ::core::option::Option::Some(ref v) = update.#update_field {
                self.#struct_field = ::core::option::Option::Some(v.clone());
            }
        },
        UpdateApply::CopyDirect => quote! {
            if let ::core::option::Option::Some(v) = update.#update_field {
                self.#struct_field = v;
            }
        },
        UpdateApply::CopyIntoOption => quote! {
            if let ::core::option::Option::Some(v) = update.#update_field {
                self.#struct_field = ::core::option::Option::Some(v);
            }
        },
        UpdateApply::CloneDirect => quote! {
            if let ::core::option::Option::Some(ref v) = update.#update_field {
                self.#struct_field = v.clone();
            }
        },
    }
}

/// Build the body of `apply_update`, including the final `updated_at = now()`.
fn gen_apply_update_body(
    field_infos: &[FieldInfo],
    update_mappings: &[(&str, &str, UpdateApply)],
) -> TokenStream2 {
    let mut stmts = Vec::new();

    for &(update_field_name, getter_name, apply) in update_mappings {
        if let Some(struct_field) = find_field_for_getter(field_infos, getter_name) {
            let update_ident = mk_ident(update_field_name);
            stmts.push(gen_update_apply_stmt(struct_field, &update_ident, apply));
        }
    }

    // Always set updated_at at the end
    if let Some(field) = find_field_for_getter(field_infos, "updated_at") {
        stmts.push(quote! { self.#field = ::chrono::Utc::now(); });
    }

    quote! { #(#stmts)* }
}

// -- Shared utility --

fn mk_ident(s: &str) -> syn::Ident {
    syn::Ident::new(s, proc_macro2::Span::call_site())
}

/// Parse named fields from a DeriveInput, returning field infos or a compile error.
fn parse_memory_fields(
    input: &DeriveInput,
    trait_name: &str,
) -> Result<Vec<FieldInfo>, TokenStream2> {
    let struct_name = &input.ident;
    let named_fields = match &input.data {
        syn::Data::Struct(data) => match &data.fields {
            syn::Fields::Named(fields) => &fields.named,
            _ => {
                return Err(syn::Error::new_spanned(
                    struct_name,
                    format!("{trait_name} can only be derived for structs with named fields"),
                )
                .to_compile_error());
            }
        },
        _ => {
            return Err(syn::Error::new_spanned(
                struct_name,
                format!("{trait_name} requires a struct"),
            )
            .to_compile_error());
        }
    };

    Ok(named_fields
        .iter()
        .filter_map(|f| {
            let ident = f.ident.clone()?;
            let (auth_field_name, auth_default) = parse_auth_attrs(&f.attrs);
            Some(FieldInfo {
                ident,
                auth_field_name,
                auth_default,
            })
        })
        .collect())
}

// ---------------------------------------------------------------------------
// MemoryUser
// ---------------------------------------------------------------------------

#[proc_macro_derive(MemoryUser, attributes(auth))]
pub fn derive_memory_user(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let field_infos = match parse_memory_fields(&input, "MemoryUser") {
        Ok(fi) => fi,
        Err(err) => return err.into(),
    };

    let create_mappings: Vec<(&str, CreateInit)> = vec![
        ("id", CreateInit::IdParam),
        ("email", CreateInit::CloneCreate("email")),
        ("name", CreateInit::CloneCreate("name")),
        (
            "email_verified",
            CreateInit::UnwrapBoolCreate("email_verified"),
        ),
        ("image", CreateInit::CloneCreate("image")),
        ("created_at", CreateInit::NowParam),
        ("updated_at", CreateInit::NowParam),
        ("username", CreateInit::CloneCreate("username")),
        (
            "display_username",
            CreateInit::CloneCreate("display_username"),
        ),
        ("two_factor_enabled", CreateInit::StaticBool(false)),
        ("role", CreateInit::CloneCreate("role")),
        ("banned", CreateInit::StaticBool(false)),
        ("ban_reason", CreateInit::StaticNone),
        ("ban_expires", CreateInit::StaticNone),
        ("metadata", CreateInit::UnwrapDefaultCreate("metadata")),
    ];

    use UpdateApply::*;
    let update_mappings: Vec<(&str, &str, UpdateApply)> = vec![
        ("email", "email", CloneIntoOption),
        ("name", "name", CloneIntoOption),
        ("image", "image", CloneIntoOption),
        ("email_verified", "email_verified", CopyDirect),
        ("username", "username", CloneIntoOption),
        ("display_username", "display_username", CloneIntoOption),
        ("role", "role", CloneIntoOption),
        ("banned", "banned", CopyDirect),
        ("ban_reason", "ban_reason", CloneIntoOption),
        ("ban_expires", "ban_expires", CopyIntoOption),
        ("two_factor_enabled", "two_factor_enabled", CopyDirect),
        ("metadata", "metadata", CloneDirect),
    ];

    let create_body = gen_from_create_body(&field_infos, &create_mappings);
    let update_body = gen_apply_update_body(&field_infos, &update_mappings);

    quote! {
        impl #impl_generics ::better_auth_core::adapters::memory::MemoryUser
            for #struct_name #ty_generics #where_clause
        {
            fn from_create(
                id: ::std::string::String,
                create: &::better_auth_core::types::CreateUser,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) -> Self {
                #create_body
            }

            fn apply_update(&mut self, update: &::better_auth_core::types::UpdateUser) {
                #update_body
            }
        }
    }
    .into()
}

// ---------------------------------------------------------------------------
// MemorySession
// ---------------------------------------------------------------------------

#[proc_macro_derive(MemorySession, attributes(auth))]
pub fn derive_memory_session(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let field_infos = match parse_memory_fields(&input, "MemorySession") {
        Ok(fi) => fi,
        Err(err) => return err.into(),
    };

    let create_mappings: Vec<(&str, CreateInit)> = vec![
        ("id", CreateInit::IdParam),
        ("token", CreateInit::TokenParam),
        ("expires_at", CreateInit::CopyCreate("expires_at")),
        ("created_at", CreateInit::NowParam),
        ("updated_at", CreateInit::NowParam),
        ("ip_address", CreateInit::CloneCreate("ip_address")),
        ("user_agent", CreateInit::CloneCreate("user_agent")),
        ("user_id", CreateInit::CloneCreate("user_id")),
        (
            "impersonated_by",
            CreateInit::CloneCreate("impersonated_by"),
        ),
        (
            "active_organization_id",
            CreateInit::CloneCreate("active_organization_id"),
        ),
        ("active", CreateInit::StaticBool(true)),
    ];

    let create_body = gen_from_create_body(&field_infos, &create_mappings);

    // Setters: find the struct fields for each setter target
    let expires_at_field = find_field_for_getter(&field_infos, "expires_at");
    let active_org_field = find_field_for_getter(&field_infos, "active_organization_id");
    let updated_at_field = find_field_for_getter(&field_infos, "updated_at");

    let set_expires = expires_at_field.map(|f| {
        quote! {
            fn set_expires_at(&mut self, at: ::chrono::DateTime<::chrono::Utc>) {
                self.#f = at;
            }
        }
    });
    let set_active_org = active_org_field.map(|f| {
        quote! {
            fn set_active_organization_id(
                &mut self,
                org_id: ::core::option::Option<::std::string::String>,
            ) {
                self.#f = org_id;
            }
        }
    });
    let set_updated = updated_at_field.map(|f| {
        quote! {
            fn set_updated_at(&mut self, at: ::chrono::DateTime<::chrono::Utc>) {
                self.#f = at;
            }
        }
    });

    quote! {
        impl #impl_generics ::better_auth_core::adapters::memory::MemorySession
            for #struct_name #ty_generics #where_clause
        {
            fn from_create(
                id: ::std::string::String,
                token: ::std::string::String,
                create: &::better_auth_core::types::CreateSession,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) -> Self {
                #create_body
            }

            #set_expires
            #set_active_org
            #set_updated
        }
    }
    .into()
}

// ---------------------------------------------------------------------------
// MemoryAccount
// ---------------------------------------------------------------------------

#[proc_macro_derive(MemoryAccount, attributes(auth))]
pub fn derive_memory_account(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let field_infos = match parse_memory_fields(&input, "MemoryAccount") {
        Ok(fi) => fi,
        Err(err) => return err.into(),
    };

    let create_mappings: Vec<(&str, CreateInit)> = vec![
        ("id", CreateInit::IdParam),
        ("account_id", CreateInit::CloneCreate("account_id")),
        ("provider_id", CreateInit::CloneCreate("provider_id")),
        ("user_id", CreateInit::CloneCreate("user_id")),
        ("access_token", CreateInit::CloneCreate("access_token")),
        ("refresh_token", CreateInit::CloneCreate("refresh_token")),
        ("id_token", CreateInit::CloneCreate("id_token")),
        (
            "access_token_expires_at",
            CreateInit::CopyCreate("access_token_expires_at"),
        ),
        (
            "refresh_token_expires_at",
            CreateInit::CopyCreate("refresh_token_expires_at"),
        ),
        ("scope", CreateInit::CloneCreate("scope")),
        ("password", CreateInit::CloneCreate("password")),
        ("created_at", CreateInit::NowParam),
        ("updated_at", CreateInit::NowParam),
    ];

    let create_body = gen_from_create_body(&field_infos, &create_mappings);

    quote! {
        impl #impl_generics ::better_auth_core::adapters::memory::MemoryAccount
            for #struct_name #ty_generics #where_clause
        {
            fn from_create(
                id: ::std::string::String,
                create: &::better_auth_core::types::CreateAccount,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) -> Self {
                #create_body
            }
        }
    }
    .into()
}

// ---------------------------------------------------------------------------
// MemoryOrganization
// ---------------------------------------------------------------------------

#[proc_macro_derive(MemoryOrganization, attributes(auth))]
pub fn derive_memory_organization(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let field_infos = match parse_memory_fields(&input, "MemoryOrganization") {
        Ok(fi) => fi,
        Err(err) => return err.into(),
    };

    let create_mappings: Vec<(&str, CreateInit)> = vec![
        ("id", CreateInit::IdParam),
        ("name", CreateInit::CloneCreate("name")),
        ("slug", CreateInit::CloneCreate("slug")),
        ("logo", CreateInit::CloneCreate("logo")),
        ("metadata", CreateInit::CloneCreate("metadata")),
        ("created_at", CreateInit::NowParam),
        ("updated_at", CreateInit::NowParam),
    ];

    use UpdateApply::*;
    let update_mappings: Vec<(&str, &str, UpdateApply)> = vec![
        ("name", "name", CloneDirect),
        ("slug", "slug", CloneDirect),
        ("logo", "logo", CloneIntoOption),
        ("metadata", "metadata", CloneIntoOption),
    ];

    let create_body = gen_from_create_body(&field_infos, &create_mappings);
    let update_body = gen_apply_update_body(&field_infos, &update_mappings);

    quote! {
        impl #impl_generics ::better_auth_core::adapters::memory::MemoryOrganization
            for #struct_name #ty_generics #where_clause
        {
            fn from_create(
                id: ::std::string::String,
                create: &::better_auth_core::types::CreateOrganization,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) -> Self {
                #create_body
            }

            fn apply_update(&mut self, update: &::better_auth_core::types::UpdateOrganization) {
                #update_body
            }
        }
    }
    .into()
}

// ---------------------------------------------------------------------------
// MemoryMember
// ---------------------------------------------------------------------------

#[proc_macro_derive(MemoryMember, attributes(auth))]
pub fn derive_memory_member(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let field_infos = match parse_memory_fields(&input, "MemoryMember") {
        Ok(fi) => fi,
        Err(err) => return err.into(),
    };

    let create_mappings: Vec<(&str, CreateInit)> = vec![
        ("id", CreateInit::IdParam),
        (
            "organization_id",
            CreateInit::CloneCreate("organization_id"),
        ),
        ("user_id", CreateInit::CloneCreate("user_id")),
        ("role", CreateInit::CloneCreate("role")),
        ("created_at", CreateInit::NowParam),
    ];

    let create_body = gen_from_create_body(&field_infos, &create_mappings);

    let role_field = find_field_for_getter(&field_infos, "role");
    let set_role = role_field.map(|f| {
        quote! {
            fn set_role(&mut self, role: ::std::string::String) {
                self.#f = role;
            }
        }
    });

    quote! {
        impl #impl_generics ::better_auth_core::adapters::memory::MemoryMember
            for #struct_name #ty_generics #where_clause
        {
            fn from_create(
                id: ::std::string::String,
                create: &::better_auth_core::types::CreateMember,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) -> Self {
                #create_body
            }

            #set_role
        }
    }
    .into()
}

// ---------------------------------------------------------------------------
// MemoryInvitation
// ---------------------------------------------------------------------------

#[proc_macro_derive(MemoryInvitation, attributes(auth))]
pub fn derive_memory_invitation(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let field_infos = match parse_memory_fields(&input, "MemoryInvitation") {
        Ok(fi) => fi,
        Err(err) => return err.into(),
    };

    let create_mappings: Vec<(&str, CreateInit)> = vec![
        ("id", CreateInit::IdParam),
        (
            "organization_id",
            CreateInit::CloneCreate("organization_id"),
        ),
        ("email", CreateInit::CloneCreate("email")),
        ("role", CreateInit::CloneCreate("role")),
        ("status", CreateInit::InvitationPending),
        ("inviter_id", CreateInit::CloneCreate("inviter_id")),
        ("expires_at", CreateInit::CopyCreate("expires_at")),
        ("created_at", CreateInit::NowParam),
    ];

    let create_body = gen_from_create_body(&field_infos, &create_mappings);

    let status_field = find_field_for_getter(&field_infos, "status");
    let set_status = status_field.map(|f| {
        quote! {
            fn set_status(&mut self, status: ::better_auth_core::types::InvitationStatus) {
                self.#f = status;
            }
        }
    });

    quote! {
        impl #impl_generics ::better_auth_core::adapters::memory::MemoryInvitation
            for #struct_name #ty_generics #where_clause
        {
            fn from_create(
                id: ::std::string::String,
                create: &::better_auth_core::types::CreateInvitation,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) -> Self {
                #create_body
            }

            #set_status
        }
    }
    .into()
}

// ---------------------------------------------------------------------------
// MemoryVerification
// ---------------------------------------------------------------------------

#[proc_macro_derive(MemoryVerification, attributes(auth))]
pub fn derive_memory_verification(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let field_infos = match parse_memory_fields(&input, "MemoryVerification") {
        Ok(fi) => fi,
        Err(err) => return err.into(),
    };

    let create_mappings: Vec<(&str, CreateInit)> = vec![
        ("id", CreateInit::IdParam),
        ("identifier", CreateInit::CloneCreate("identifier")),
        ("value", CreateInit::CloneCreate("value")),
        ("expires_at", CreateInit::CopyCreate("expires_at")),
        ("created_at", CreateInit::NowParam),
        ("updated_at", CreateInit::NowParam),
    ];

    let create_body = gen_from_create_body(&field_infos, &create_mappings);

    quote! {
        impl #impl_generics ::better_auth_core::adapters::memory::MemoryVerification
            for #struct_name #ty_generics #where_clause
        {
            fn from_create(
                id: ::std::string::String,
                create: &::better_auth_core::types::CreateVerification,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) -> Self {
                #create_body
            }
        }
    }
    .into()
}
