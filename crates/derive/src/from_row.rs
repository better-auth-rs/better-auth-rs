use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::DeriveInput;

/// Check if the struct has `#[auth(from_row)]`.
pub(crate) fn has_auth_from_row(attrs: &[syn::Attribute]) -> bool {
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
pub(crate) fn maybe_gen_from_row(input: &DeriveInput) -> TokenStream2 {
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
