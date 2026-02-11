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

use ReturnKind::*;

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

/// Parse named fields from a DeriveInput, returning field infos or a compile error.
fn parse_named_fields(
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
// Code generation — Auth* trait getters
// ---------------------------------------------------------------------------

/// Generate the return-type tokens and method-body tokens for a single getter.
fn gen_getter_tokens(field_ident: &syn::Ident, kind: ReturnKind) -> (TokenStream2, TokenStream2) {
    match kind {
        RefStr => (quote! { &str }, quote! { &self.#field_ident }),
        OptionRefStr => (
            quote! { ::core::option::Option<&str> },
            quote! { self.#field_ident.as_deref() },
        ),
        Bool => (quote! { bool }, quote! { self.#field_ident }),
        U64 => (quote! { u64 }, quote! { self.#field_ident }),
        DateTime => (
            quote! { ::chrono::DateTime<::chrono::Utc> },
            quote! { self.#field_ident },
        ),
        OptionDateTime => (
            quote! { ::core::option::Option<::chrono::DateTime<::chrono::Utc>> },
            quote! { self.#field_ident },
        ),
        RefValue => (
            quote! { &::serde_json::Value },
            quote! { &self.#field_ident },
        ),
        RefStatus => (
            quote! { &::better_auth_core::types::InvitationStatus },
            quote! { &self.#field_ident },
        ),
        OptionRefValue => (
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
                        let parsed: syn::Expr = syn::parse_str(&lit.value()).map_err(|e| {
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
    type_path.path.segments.last().map(|s| s.ident.to_string())
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
/// 1. Explicit `#[auth(json)]` or auto-detected `Json`/`Value` type -> JSON unwrap
/// 2. `#[auth(default = "expr")]` -> `try_get(...).unwrap_or_else(|_| expr)`
/// 3. Unknown non-Option type (not in known list) -> assume `From<String>` enum
/// 4. Everything else -> simple `try_get`
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
        quote! {
            #ident: row.try_get::<
                ::core::option::Option<::sqlx::types::Json<::serde_json::Value>>, _
            >(#col_name)?.map(|j| j.0)
        }
    } else if is_json {
        quote! {
            #ident: row.try_get::<
                ::sqlx::types::Json<::serde_json::Value>, _
            >(#col_name)?.0
        }
    } else if let Some(ref default_expr) = field.default_expr {
        quote! {
            #ident: row.try_get(#col_name).unwrap_or_else(|_| #default_expr)
        }
    } else if !is_known && !is_option {
        // Unknown non-Option type -> assume enum implementing From<String>
        quote! {
            #ident: {
                let __s: ::std::string::String = row.try_get(#col_name)?;
                ::core::convert::From::from(__s)
            }
        }
    } else {
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

// ===========================================================================
// Auth* trait derive — shared core + static getter definitions
// ===========================================================================

/// Core function: given a `DeriveInput`, trait path tokens, trait name (for
/// error messages), and a list of `(getter_name, ReturnKind)` pairs, generate
/// the full `impl Trait for Struct { ... }` block.
fn derive_entity_trait(
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

// ---------------------------------------------------------------------------
// Auth* getter definitions (static arrays)
// ---------------------------------------------------------------------------

const AUTH_USER_GETTERS: &[(&str, ReturnKind)] = &[
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

const AUTH_SESSION_GETTERS: &[(&str, ReturnKind)] = &[
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

const AUTH_ACCOUNT_GETTERS: &[(&str, ReturnKind)] = &[
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

const AUTH_ORGANIZATION_GETTERS: &[(&str, ReturnKind)] = &[
    ("id", RefStr),
    ("name", RefStr),
    ("slug", RefStr),
    ("logo", OptionRefStr),
    ("metadata", OptionRefValue),
    ("created_at", DateTime),
    ("updated_at", DateTime),
];

const AUTH_MEMBER_GETTERS: &[(&str, ReturnKind)] = &[
    ("id", RefStr),
    ("organization_id", RefStr),
    ("user_id", RefStr),
    ("role", RefStr),
    ("created_at", DateTime),
];

const AUTH_INVITATION_GETTERS: &[(&str, ReturnKind)] = &[
    ("id", RefStr),
    ("organization_id", RefStr),
    ("email", RefStr),
    ("role", RefStr),
    ("status", RefStatus),
    ("inviter_id", RefStr),
    ("expires_at", DateTime),
    ("created_at", DateTime),
];

const AUTH_VERIFICATION_GETTERS: &[(&str, ReturnKind)] = &[
    ("id", RefStr),
    ("identifier", RefStr),
    ("value", RefStr),
    ("expires_at", DateTime),
    ("created_at", DateTime),
    ("updated_at", DateTime),
];

const AUTH_TWO_FACTOR_GETTERS: &[(&str, ReturnKind)] = &[
    ("id", RefStr),
    ("secret", RefStr),
    ("backup_codes", OptionRefStr),
    ("user_id", RefStr),
];

const AUTH_PASSKEY_GETTERS: &[(&str, ReturnKind)] = &[
    ("id", RefStr),
    ("name", RefStr),
    ("public_key", RefStr),
    ("user_id", RefStr),
    ("credential_id", RefStr),
    ("counter", U64),
    ("device_type", RefStr),
    ("backed_up", Bool),
];

// ---------------------------------------------------------------------------
// Auth* macro entry points
// ---------------------------------------------------------------------------

#[proc_macro_derive(AuthUser, attributes(auth))]
pub fn derive_auth_user(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let t = derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthUser },
        "AuthUser",
        AUTH_USER_GETTERS,
    );
    let r = maybe_gen_from_row(&input);
    quote! { #t #r }.into()
}

#[proc_macro_derive(AuthSession, attributes(auth))]
pub fn derive_auth_session(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let t = derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthSession },
        "AuthSession",
        AUTH_SESSION_GETTERS,
    );
    let r = maybe_gen_from_row(&input);
    quote! { #t #r }.into()
}

#[proc_macro_derive(AuthAccount, attributes(auth))]
pub fn derive_auth_account(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let t = derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthAccount },
        "AuthAccount",
        AUTH_ACCOUNT_GETTERS,
    );
    let r = maybe_gen_from_row(&input);
    quote! { #t #r }.into()
}

#[proc_macro_derive(AuthOrganization, attributes(auth))]
pub fn derive_auth_organization(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let t = derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthOrganization },
        "AuthOrganization",
        AUTH_ORGANIZATION_GETTERS,
    );
    let r = maybe_gen_from_row(&input);
    quote! { #t #r }.into()
}

#[proc_macro_derive(AuthMember, attributes(auth))]
pub fn derive_auth_member(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let t = derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthMember },
        "AuthMember",
        AUTH_MEMBER_GETTERS,
    );
    let r = maybe_gen_from_row(&input);
    quote! { #t #r }.into()
}

#[proc_macro_derive(AuthInvitation, attributes(auth))]
pub fn derive_auth_invitation(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let t = derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthInvitation },
        "AuthInvitation",
        AUTH_INVITATION_GETTERS,
    );
    let r = maybe_gen_from_row(&input);
    quote! { #t #r }.into()
}

#[proc_macro_derive(AuthVerification, attributes(auth))]
pub fn derive_auth_verification(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let t = derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthVerification },
        "AuthVerification",
        AUTH_VERIFICATION_GETTERS,
    );
    let r = maybe_gen_from_row(&input);
    quote! { #t #r }.into()
}

#[proc_macro_derive(AuthTwoFactor, attributes(auth))]
pub fn derive_auth_two_factor(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let t = derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthTwoFactor },
        "AuthTwoFactor",
        AUTH_TWO_FACTOR_GETTERS,
    );
    let r = maybe_gen_from_row(&input);
    quote! { #t #r }.into()
}

#[proc_macro_derive(AuthPasskey, attributes(auth))]
pub fn derive_auth_passkey(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let t = derive_entity_trait(
        &input,
        quote! { ::better_auth_core::entity::AuthPasskey },
        "AuthPasskey",
        AUTH_PASSKEY_GETTERS,
    );
    let r = maybe_gen_from_row(&input);
    quote! { #t #r }.into()
}

// ===========================================================================
// Memory* trait derive macros — shared core + static field definitions
// ===========================================================================

// -- Enums for from_create / apply_update code generation --

/// How a struct field is initialised inside `from_create`.
#[derive(Clone, Copy)]
enum CreateInit {
    IdParam,
    TokenParam,
    NowParam,
    CloneCreate(&'static str),
    CopyCreate(&'static str),
    UnwrapBoolCreate(&'static str),
    UnwrapDefaultCreate(&'static str),
    StaticBool(bool),
    StaticNone,
    InvitationPending,
}

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

/// Setter methods that some Memory* traits require.
#[derive(Clone, Copy)]
enum SetterDef {
    /// `fn set_expires_at(&mut self, at: DateTime<Utc>)` — field "expires_at"
    ExpiresAt,
    /// `fn set_active_organization_id(&mut self, org_id: Option<String>)` — field "active_organization_id"
    ActiveOrganizationId,
    /// `fn set_updated_at(&mut self, at: DateTime<Utc>)` — field "updated_at"
    UpdatedAt,
    /// `fn set_role(&mut self, role: String)` — field "role"
    Role,
    /// `fn set_status(&mut self, status: InvitationStatus)` — field "status"
    Status,
}

use CreateInit::*;
use UpdateApply::*;

// -- Code generation helpers --

fn mk_ident(s: &str) -> syn::Ident {
    syn::Ident::new(s, proc_macro2::Span::call_site())
}

fn gen_create_init_expr(init: &CreateInit) -> TokenStream2 {
    match init {
        IdParam => quote! { id },
        TokenParam => quote! { token },
        NowParam => quote! { now },
        CloneCreate(f) => {
            let field = mk_ident(f);
            quote! { create.#field.clone() }
        }
        CopyCreate(f) => {
            let field = mk_ident(f);
            quote! { create.#field }
        }
        UnwrapBoolCreate(f) => {
            let field = mk_ident(f);
            quote! { create.#field.unwrap_or(false) }
        }
        UnwrapDefaultCreate(f) => {
            let field = mk_ident(f);
            quote! { create.#field.clone().unwrap_or_default() }
        }
        StaticBool(b) => quote! { #b },
        StaticNone => quote! { ::core::option::Option::None },
        InvitationPending => {
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

/// Generate setter method implementations from SetterDef descriptors.
fn gen_setter_methods(field_infos: &[FieldInfo], setters: &[SetterDef]) -> TokenStream2 {
    let mut methods = Vec::new();
    for setter in setters {
        match setter {
            SetterDef::ExpiresAt => {
                if let Some(f) = find_field_for_getter(field_infos, "expires_at") {
                    methods.push(quote! {
                        fn set_expires_at(&mut self, at: ::chrono::DateTime<::chrono::Utc>) {
                            self.#f = at;
                        }
                    });
                }
            }
            SetterDef::ActiveOrganizationId => {
                if let Some(f) = find_field_for_getter(field_infos, "active_organization_id") {
                    methods.push(quote! {
                        fn set_active_organization_id(
                            &mut self,
                            org_id: ::core::option::Option<::std::string::String>,
                        ) {
                            self.#f = org_id;
                        }
                    });
                }
            }
            SetterDef::UpdatedAt => {
                if let Some(f) = find_field_for_getter(field_infos, "updated_at") {
                    methods.push(quote! {
                        fn set_updated_at(&mut self, at: ::chrono::DateTime<::chrono::Utc>) {
                            self.#f = at;
                        }
                    });
                }
            }
            SetterDef::Role => {
                if let Some(f) = find_field_for_getter(field_infos, "role") {
                    methods.push(quote! {
                        fn set_role(&mut self, role: ::std::string::String) {
                            self.#f = role;
                        }
                    });
                }
            }
            SetterDef::Status => {
                if let Some(f) = find_field_for_getter(field_infos, "status") {
                    methods.push(quote! {
                        fn set_status(&mut self, status: ::better_auth_core::types::InvitationStatus) {
                            self.#f = status;
                        }
                    });
                }
            }
        }
    }
    quote! { #(#methods)* }
}

// ---------------------------------------------------------------------------
// Memory* trait definition descriptor
// ---------------------------------------------------------------------------

/// Configuration for a Memory* trait derive macro. Each Memory* macro
/// is fully described by one of these — the shared `derive_memory_trait`
/// function does all the code generation.
struct MemoryTraitDef {
    trait_name: &'static str,
    create_type: &'static str,
    has_token_param: bool,
    create_mappings: &'static [(&'static str, CreateInit)],
    update_type: Option<&'static str>,
    update_mappings: &'static [(&'static str, &'static str, UpdateApply)],
    setters: &'static [SetterDef],
}

/// Shared code generation for all Memory* traits.
fn derive_memory_trait(input: &DeriveInput, def: &MemoryTraitDef) -> TokenStream2 {
    let struct_name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let field_infos = match parse_named_fields(input, def.trait_name) {
        Ok(fi) => fi,
        Err(err) => return err,
    };

    let create_body = gen_from_create_body(&field_infos, def.create_mappings);
    let trait_ident = mk_ident(def.trait_name);
    let create_type_ident = mk_ident(def.create_type);

    let from_create_fn = if def.has_token_param {
        quote! {
            fn from_create(
                id: ::std::string::String,
                token: ::std::string::String,
                create: &::better_auth_core::types::#create_type_ident,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) -> Self {
                #create_body
            }
        }
    } else {
        quote! {
            fn from_create(
                id: ::std::string::String,
                create: &::better_auth_core::types::#create_type_ident,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) -> Self {
                #create_body
            }
        }
    };

    let update_fn = if let Some(update_type_name) = def.update_type {
        let update_type_ident = mk_ident(update_type_name);
        let update_body = gen_apply_update_body(&field_infos, def.update_mappings);
        quote! {
            fn apply_update(&mut self, update: &::better_auth_core::types::#update_type_ident) {
                #update_body
            }
        }
    } else {
        quote! {}
    };

    let setter_fns = gen_setter_methods(&field_infos, def.setters);

    quote! {
        impl #impl_generics ::better_auth_core::adapters::memory::#trait_ident
            for #struct_name #ty_generics #where_clause
        {
            #from_create_fn
            #update_fn
            #setter_fns
        }
    }
}

// ---------------------------------------------------------------------------
// Memory* static field definitions
// ---------------------------------------------------------------------------

const MEMORY_USER_DEF: MemoryTraitDef = MemoryTraitDef {
    trait_name: "MemoryUser",
    create_type: "CreateUser",
    has_token_param: false,
    create_mappings: &[
        ("id", IdParam),
        ("email", CloneCreate("email")),
        ("name", CloneCreate("name")),
        ("email_verified", UnwrapBoolCreate("email_verified")),
        ("image", CloneCreate("image")),
        ("created_at", NowParam),
        ("updated_at", NowParam),
        ("username", CloneCreate("username")),
        ("display_username", CloneCreate("display_username")),
        ("two_factor_enabled", StaticBool(false)),
        ("role", CloneCreate("role")),
        ("banned", StaticBool(false)),
        ("ban_reason", StaticNone),
        ("ban_expires", StaticNone),
        ("metadata", UnwrapDefaultCreate("metadata")),
    ],
    update_type: Some("UpdateUser"),
    update_mappings: &[
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
    ],
    setters: &[],
};

const MEMORY_SESSION_DEF: MemoryTraitDef = MemoryTraitDef {
    trait_name: "MemorySession",
    create_type: "CreateSession",
    has_token_param: true,
    create_mappings: &[
        ("id", IdParam),
        ("token", TokenParam),
        ("expires_at", CopyCreate("expires_at")),
        ("created_at", NowParam),
        ("updated_at", NowParam),
        ("ip_address", CloneCreate("ip_address")),
        ("user_agent", CloneCreate("user_agent")),
        ("user_id", CloneCreate("user_id")),
        ("impersonated_by", CloneCreate("impersonated_by")),
        (
            "active_organization_id",
            CloneCreate("active_organization_id"),
        ),
        ("active", StaticBool(true)),
    ],
    update_type: None,
    update_mappings: &[],
    setters: &[
        SetterDef::ExpiresAt,
        SetterDef::ActiveOrganizationId,
        SetterDef::UpdatedAt,
    ],
};

const MEMORY_ACCOUNT_DEF: MemoryTraitDef = MemoryTraitDef {
    trait_name: "MemoryAccount",
    create_type: "CreateAccount",
    has_token_param: false,
    create_mappings: &[
        ("id", IdParam),
        ("account_id", CloneCreate("account_id")),
        ("provider_id", CloneCreate("provider_id")),
        ("user_id", CloneCreate("user_id")),
        ("access_token", CloneCreate("access_token")),
        ("refresh_token", CloneCreate("refresh_token")),
        ("id_token", CloneCreate("id_token")),
        (
            "access_token_expires_at",
            CopyCreate("access_token_expires_at"),
        ),
        (
            "refresh_token_expires_at",
            CopyCreate("refresh_token_expires_at"),
        ),
        ("scope", CloneCreate("scope")),
        ("password", CloneCreate("password")),
        ("created_at", NowParam),
        ("updated_at", NowParam),
    ],
    update_type: None,
    update_mappings: &[],
    setters: &[],
};

const MEMORY_ORGANIZATION_DEF: MemoryTraitDef = MemoryTraitDef {
    trait_name: "MemoryOrganization",
    create_type: "CreateOrganization",
    has_token_param: false,
    create_mappings: &[
        ("id", IdParam),
        ("name", CloneCreate("name")),
        ("slug", CloneCreate("slug")),
        ("logo", CloneCreate("logo")),
        ("metadata", CloneCreate("metadata")),
        ("created_at", NowParam),
        ("updated_at", NowParam),
    ],
    update_type: Some("UpdateOrganization"),
    update_mappings: &[
        ("name", "name", CloneDirect),
        ("slug", "slug", CloneDirect),
        ("logo", "logo", CloneIntoOption),
        ("metadata", "metadata", CloneIntoOption),
    ],
    setters: &[],
};

const MEMORY_MEMBER_DEF: MemoryTraitDef = MemoryTraitDef {
    trait_name: "MemoryMember",
    create_type: "CreateMember",
    has_token_param: false,
    create_mappings: &[
        ("id", IdParam),
        ("organization_id", CloneCreate("organization_id")),
        ("user_id", CloneCreate("user_id")),
        ("role", CloneCreate("role")),
        ("created_at", NowParam),
    ],
    update_type: None,
    update_mappings: &[],
    setters: &[SetterDef::Role],
};

const MEMORY_INVITATION_DEF: MemoryTraitDef = MemoryTraitDef {
    trait_name: "MemoryInvitation",
    create_type: "CreateInvitation",
    has_token_param: false,
    create_mappings: &[
        ("id", IdParam),
        ("organization_id", CloneCreate("organization_id")),
        ("email", CloneCreate("email")),
        ("role", CloneCreate("role")),
        ("status", InvitationPending),
        ("inviter_id", CloneCreate("inviter_id")),
        ("expires_at", CopyCreate("expires_at")),
        ("created_at", NowParam),
    ],
    update_type: None,
    update_mappings: &[],
    setters: &[SetterDef::Status],
};

const MEMORY_VERIFICATION_DEF: MemoryTraitDef = MemoryTraitDef {
    trait_name: "MemoryVerification",
    create_type: "CreateVerification",
    has_token_param: false,
    create_mappings: &[
        ("id", IdParam),
        ("identifier", CloneCreate("identifier")),
        ("value", CloneCreate("value")),
        ("expires_at", CopyCreate("expires_at")),
        ("created_at", NowParam),
        ("updated_at", NowParam),
    ],
    update_type: None,
    update_mappings: &[],
    setters: &[],
};

// ---------------------------------------------------------------------------
// Memory* macro entry points
// ---------------------------------------------------------------------------

#[proc_macro_derive(MemoryUser, attributes(auth))]
pub fn derive_memory_user(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_memory_trait(&input, &MEMORY_USER_DEF).into()
}

#[proc_macro_derive(MemorySession, attributes(auth))]
pub fn derive_memory_session(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_memory_trait(&input, &MEMORY_SESSION_DEF).into()
}

#[proc_macro_derive(MemoryAccount, attributes(auth))]
pub fn derive_memory_account(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_memory_trait(&input, &MEMORY_ACCOUNT_DEF).into()
}

#[proc_macro_derive(MemoryOrganization, attributes(auth))]
pub fn derive_memory_organization(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_memory_trait(&input, &MEMORY_ORGANIZATION_DEF).into()
}

#[proc_macro_derive(MemoryMember, attributes(auth))]
pub fn derive_memory_member(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_memory_trait(&input, &MEMORY_MEMBER_DEF).into()
}

#[proc_macro_derive(MemoryInvitation, attributes(auth))]
pub fn derive_memory_invitation(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_memory_trait(&input, &MEMORY_INVITATION_DEF).into()
}

#[proc_macro_derive(MemoryVerification, attributes(auth))]
pub fn derive_memory_verification(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_memory_trait(&input, &MEMORY_VERIFICATION_DEF).into()
}
