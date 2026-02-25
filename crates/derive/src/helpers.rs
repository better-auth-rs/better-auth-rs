use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::DeriveInput;

/// Describes how a trait getter returns a value and how the generated code
/// should access the corresponding struct field.
#[derive(Clone, Copy)]
pub(crate) enum ReturnKind {
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

pub(crate) use ReturnKind::*;

/// Parsed information about a struct field relevant to our derive.
pub(crate) struct FieldInfo {
    /// The identifier of the struct field.
    pub ident: syn::Ident,
    /// If the field has `#[auth(field = "...")]`, the overridden getter name.
    pub auth_field_name: Option<String>,
    /// If the field has `#[auth(column = "...")]`, the explicit DB column name.
    pub auth_column: Option<String>,
    /// If the field has `#[auth(default = "...")]`, the default expression.
    pub auth_default: Option<TokenStream2>,
}

/// Parsed result of `#[auth(...)]` field-level attributes.
pub(crate) struct ParsedAuthAttrs {
    pub field_name: Option<String>,
    pub column_name: Option<String>,
    pub default_expr: Option<TokenStream2>,
}

/// Parse `#[auth(...)]` attributes from a field.
///
/// Supported:
/// - `#[auth(field = "getter_name")]` — remap field to a getter name
/// - `#[auth(column = "col")]` — explicit DB column name
/// - `#[auth(default = "expr")]` — default expression for Memory* derives
pub(crate) fn parse_auth_attrs(attrs: &[syn::Attribute]) -> Result<ParsedAuthAttrs, syn::Error> {
    let mut field_name = None;
    let mut column_name = None;
    let mut default_expr = None;
    for attr in attrs {
        if !attr.path().is_ident("auth") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("field") {
                let value = meta.value()?;
                let lit: syn::LitStr = value.parse()?;
                field_name = Some(lit.value());
            } else if meta.path.is_ident("column") {
                let value = meta.value()?;
                let lit: syn::LitStr = value.parse()?;
                column_name = Some(lit.value());
            } else if meta.path.is_ident("default") {
                let value = meta.value()?;
                let lit: syn::LitStr = value.parse()?;
                let parsed: syn::Expr = syn::parse_str(&lit.value()).map_err(|e| {
                    syn::Error::new_spanned(&lit, format!("invalid default expression: {e}"))
                })?;
                default_expr = Some(quote! { #parsed });
            } else if !meta.path.is_ident("from_row")
                && !meta.path.is_ident("json")
                && !meta.path.is_ident("table")
            {
                // Ignore known struct-level and from_row attributes;
                // unknown attributes are silently skipped to allow forward compat.
            }
            Ok(())
        })?;
    }
    Ok(ParsedAuthAttrs {
        field_name,
        column_name,
        default_expr,
    })
}

/// Parse struct-level `#[auth(table = "...")]` attribute.
///
/// Returns `Some(table_name)` if the attribute is present.
pub(crate) fn parse_struct_auth_table(
    attrs: &[syn::Attribute],
) -> Result<Option<String>, syn::Error> {
    let mut table_name = None;
    for attr in attrs {
        if !attr.path().is_ident("auth") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("table") {
                let value = meta.value()?;
                let lit: syn::LitStr = value.parse()?;
                table_name = Some(lit.value());
            } else if !meta.path.is_ident("field")
                && !meta.path.is_ident("column")
                && !meta.path.is_ident("default")
                && !meta.path.is_ident("from_row")
                && !meta.path.is_ident("json")
            {
                // Ignore known field-level attributes;
                // unknown attributes are silently skipped to allow forward compat.
            }
            Ok(())
        })?;
    }
    Ok(table_name)
}

/// Given a list of parsed fields and a getter name, find the matching field.
///
/// Matching rules:
/// 1. A field with `#[auth(field = "getter_name")]` takes priority.
/// 2. Otherwise, a field whose identifier equals `getter_name`.
pub(crate) fn find_field_for_getter<'a>(
    fields: &'a [FieldInfo],
    getter_name: &str,
) -> Option<&'a syn::Ident> {
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
pub(crate) fn parse_named_fields(
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

    let mut fields = Vec::new();
    for f in named_fields {
        let Some(ident) = f.ident.clone() else {
            continue;
        };
        let parsed = parse_auth_attrs(&f.attrs).map_err(|e| e.to_compile_error())?;
        fields.push(FieldInfo {
            ident,
            auth_field_name: parsed.field_name,
            auth_column: parsed.column_name,
            auth_default: parsed.default_expr,
        });
    }
    Ok(fields)
}

/// Generate the return-type tokens and method-body tokens for a single getter.
pub(crate) fn gen_getter_tokens(
    field_ident: &syn::Ident,
    kind: ReturnKind,
) -> (TokenStream2, TokenStream2) {
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
