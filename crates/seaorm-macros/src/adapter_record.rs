use super::*;

pub(super) fn generate(
    input: &DeriveInput,
    fields: &syn::FieldsNamed,
    role: EntityRole,
    seaorm: &TokenStream,
    core: &TokenStream,
) -> syn::Result<TokenStream> {
    let (model, view, query_fields) = match role {
        EntityRole::Account => (
            "SeaOrmAccountModel",
            "AccountView",
            vec!["id", "account_id", "provider_id", "user_id", "created_at"],
        ),
        EntityRole::Verification => (
            "SeaOrmVerificationModel",
            "VerificationView",
            vec!["id", "identifier", "value", "expires_at", "created_at"],
        ),
        _ => {
            return Err(syn::Error::new_spanned(
                input,
                "expected an account or verification",
            ));
        }
    };
    let model = format_ident!("{model}");
    let view = format_ident!("{view}");
    let known = registry::core_field_names(role);
    let rename_all = serde_serialized_name(&input.attrs, "rename_all")?
        .map(|rule| {
            serde_rename_rule::RenameRule::from_rename_all_str(&rule)
                .map_err(|error| syn::Error::new_spanned(input, error.to_string()))
        })
        .transpose()?;
    let mut columns = Vec::new();
    let mut setters = Vec::new();
    let mut values = Vec::new();
    let mut core_values = Vec::new();
    for field in &fields.named {
        let Some(ident) = &field.ident else { continue };
        let rust_name = ident.to_string();
        let logical = serde_rename_rule::RenameRule::CamelCase.apply_to_field(&rust_name);
        let serialized = serde_serialized_name(&field.attrs, "rename")?.unwrap_or_else(|| {
            rename_all
                .as_ref()
                .map_or_else(|| rust_name.clone(), |rule| rule.apply_to_field(&rust_name))
        });
        let column = format_ident!(
            "{}",
            serde_rename_rule::RenameRule::PascalCase.apply_to_field(&rust_name)
        );
        let mut aliases = vec![rust_name.clone(), logical.clone(), serialized];
        aliases.sort();
        aliases.dedup();
        columns.push(quote!(#(#aliases)|* => Ok(Column::#column),));
        setters.push(quote!(#(#aliases)|* => active.#ident = #seaorm::sea_orm::ActiveValue::Set(#core::serde_json::from_value(value)?),));
        let value = match date_field(&field.ty) {
            Some(false) => {
                quote!(#core::utils::date::serialize(&self.#ident, #core::serde_json::value::Serializer)?)
            }
            Some(true) => {
                quote!(#core::utils::date::serialize_option(&self.#ident, #core::serde_json::value::Serializer)?)
            }
            None => quote!(#core::serde_json::to_value(&self.#ident)?),
        };
        values.push(quote!(Column::#column => #value,));
        if known.contains(&rust_name.as_str()) {
            core_values.push(quote!((#logical.to_owned(), #value),));
        }
    }
    let query_columns = query_fields.into_iter().map(|field| {
        let method = format_ident!("{field}_column");
        let column = format_ident!(
            "{}",
            serde_rename_rule::RenameRule::PascalCase.apply_to_field(field)
        );
        quote!(fn #method() -> Self::Column { Column::#column })
    });
    let user_id = (role == EntityRole::Account).then(|| {
        quote! {
            type UserId = String;
            fn parse_user_id(value: &str) -> #core::AuthResult<String> { Ok(value.to_owned()) }
        }
    });
    let ident = &input.ident;
    Ok(quote! {
        impl #seaorm::#model for #ident {
            type Id = String;
            type Entity = Entity;
            type ActiveModel = ActiveModel;
            type Column = Column;
            #user_id
            #(#query_columns)*
            fn parse_id(value: &str) -> #core::AuthResult<String> { Ok(value.to_owned()) }

            fn field_column(name: &str) -> #core::AuthResult<Column> {
                match name {
                    #(#columns)*
                    _ => Err(#core::AuthError::config(format!("Unknown adapter model field: {name}"))),
                }
            }

            fn native_json_field(name: &str) -> bool {
                Self::field_column(name).is_ok_and(|column| matches!(
                    #seaorm::sea_orm::ColumnTrait::def(&column).get_column_type(),
                    #seaorm::sea_orm::ColumnType::Json | #seaorm::sea_orm::ColumnType::JsonBinary
                ))
            }

            fn new_active(id: Option<String>, mut fields: #core::serde_json::Map<String, #core::serde_json::Value>) -> #core::AuthResult<ActiveModel> {
                if let Some(id) = id {
                    let _ = fields.insert("id".into(), #core::serde_json::Value::String(id));
                } else if !fields.contains_key("id") {
                    let _ = fields.insert("id".into(), #core::serde_json::Value::String(#core::uuid::Uuid::new_v4().to_string()));
                }
                let mut active = <ActiveModel as Default>::default();
                Self::apply_fields(&mut active, fields)?;
                Ok(active)
            }

            fn apply_fields(active: &mut ActiveModel, fields: #core::serde_json::Map<String, #core::serde_json::Value>) -> #core::AuthResult<()> {
                for (name, value) in fields {
                    match name.as_str() {
                        #(#setters)*
                        _ => return Err(#core::AuthError::config(format!("Unknown adapter model field: {name}"))),
                    }
                }
                Ok(())
            }

            fn record(&self, config: &#core::user_fields::UserConfig, supports_native_json: bool, supports_native_dates: bool) -> #core::AuthResult<#core::wire::#view> {
                let mut logical = #core::serde_json::Map::from_iter([#(#core_values)*]);
                if let Some(id) = logical.remove("id") {
                    let id = #core::SchemaValue::<String>::from_json(Some(id)).display_string()?;
                    let _ = logical.insert("id".into(), #core::serde_json::Value::String(id));
                }
                let mut storage = #core::serde_json::Map::new();
                for (name, field) in &config.additional_fields {
                    if name == "id" { continue; }
                    let name = field.field_name.as_deref().unwrap_or(name);
                    let value = match Self::field_column(name)? { #(#values)* };
                    let _ = storage.insert(name.to_owned(), value);
                }
                Ok(#core::wire::#view::from_adapter_fields(config.record_output_fields(logical, &storage, supports_native_json, supports_native_dates)?))
            }
        }
    })
}

fn date_field(ty: &syn::Type) -> Option<bool> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    let segment = path.path.segments.last()?;
    if segment.ident == "DateTime" || segment.ident == "DateTimeUtc" {
        return Some(false);
    }
    if segment.ident != "Option" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return None;
    };
    let syn::GenericArgument::Type(inner) = arguments.args.first()? else {
        return None;
    };
    date_field(inner).map(|_| true)
}
