use super::*;

pub(super) fn field_type<'a>(
    fields: &'a syn::FieldsNamed,
    name: &str,
) -> syn::Result<&'a syn::Type> {
    fields
        .named
        .iter()
        .find(|field| field.ident.as_ref().is_some_and(|ident| ident == name))
        .map(|field| &field.ty)
        .ok_or_else(|| {
            syn::Error::new_spanned(fields, format!("missing required auth field `{name}`"))
        })
}

pub(super) fn string_view(ty: &syn::Type, name: &str) -> TokenStream {
    let ident = format_ident!("{name}");
    if matches!(ty, syn::Type::Path(path) if path.path.segments.last().is_some_and(|segment| segment.ident == "String"))
    {
        quote!(::std::borrow::Cow::Borrowed(&self.#ident))
    } else {
        quote!(::std::borrow::Cow::Owned(self.#ident.to_string()))
    }
}

pub(super) fn is_reference(role: EntityRole, field: &syn::Field) -> syn::Result<bool> {
    let mut configured = None;
    for attr in field
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("auth"))
    {
        attr.parse_nested_meta(|meta| {
            if !meta.path.is_ident("reference") {
                return Err(meta.error("expected `reference`"));
            }
            configured = Some(if meta.input.peek(syn::Token![=]) {
                meta.value()?.parse::<syn::LitBool>()?.value
            } else {
                true
            });
            Ok(())
        })?;
    }
    let table = match role {
        EntityRole::Session => "sessions",
        EntityRole::Account => "accounts",
        _ => registry::plugin_schemas()
            .iter()
            .flat_map(|plugin| plugin.extra_entities)
            .find(|entity| entity.role == Some(role))
            .map_or("", |entity| entity.table_name),
    };
    Ok(configured.unwrap_or_else(|| {
        registry::entity_foreign_keys(table)
            .iter()
            .any(|(column, _)| field.ident.as_ref().is_some_and(|ident| ident == column))
    }))
}

pub(super) fn decode(field: &syn::Field, core: &TokenStream, seaorm: &TokenStream) -> TokenStream {
    let optional = optional_inner(&field.ty);
    let ty = optional.unwrap_or(&field.ty);
    if !matches!(ty, syn::Type::Path(path) if path.path.segments.last().is_some_and(|segment| matches!(segment.ident.to_string().as_str(), "String" | "Uuid" | "i16" | "i32" | "i64" | "u16" | "u32" | "u64")))
    {
        return adapter_record::decode_field(field, seaorm);
    }
    let value = quote! {
        match value {
            #core::FieldValue::String(value) => value.parse::<#ty>()
                .map_err(|error| #core::AuthError::bad_request(format!("Invalid model identifier: {error}")))?,
            value => #seaorm::__private_field_decode::<#ty>(value)?,
        }
    };
    if optional.is_some() {
        quote! { if value.is_null() { None } else { Some(#value) } }
    } else {
        value
    }
}

pub(super) fn optional_inner(ty: &syn::Type) -> Option<&syn::Type> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    let segment = path.path.segments.last()?;
    if segment.ident != "Option" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return None;
    };
    match arguments.args.first()? {
        syn::GenericArgument::Type(ty) => Some(ty),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse::Parser;

    #[test]
    fn explicit_reference_policy_overrides_registry() -> syn::Result<()> {
        for (tokens, expected) in [
            (quote!(user_id: Option<String>), true),
            (quote!(#[auth(reference)] user_id: Option<String>), true),
            (
                quote!(#[auth(reference = true)] user_id: Option<String>),
                true,
            ),
            (
                quote!(#[auth(reference = false)] user_id: Option<String>),
                false,
            ),
            (quote!(scope: Option<String>), false),
            (quote!(#[auth(reference)] scope: Option<String>), true),
        ] {
            let field = syn::Field::parse_named.parse2(tokens)?;
            if is_reference(EntityRole::DeviceCode, &field)? != expected {
                return Err(syn::Error::new_spanned(
                    field,
                    "explicit reference policy did not preserve its precedence over the registry",
                ));
            }
        }
        Ok(())
    }
}
