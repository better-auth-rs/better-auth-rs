use super::*;

pub(super) fn generate(
    input: &DeriveInput,
    fields: &syn::FieldsNamed,
    role: EntityRole,
    seaorm: &TokenStream,
    core: &TokenStream,
) -> syn::Result<TokenStream> {
    let (model, query_fields) = match role {
        EntityRole::Account => (
            "SeaOrmAccountModel",
            vec!["id", "account_id", "provider_id", "user_id", "created_at"],
        ),
        EntityRole::Verification => (
            "SeaOrmVerificationModel",
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
        let decoded = if rust_name == "id" || identity::is_reference(role, field)? {
            identity::decode(field, core)
        } else {
            quote!(#core::serde_json::from_value(value)?)
        };
        setters.push(
            quote!(#(#aliases)|* => active.#ident = #seaorm::sea_orm::ActiveValue::Set(#decoded),),
        );
        let value = field_value(field, core);
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
    let user_id = if role == EntityRole::Account {
        let ty = identity::field_type(fields, "user_id")?;
        let parse = if identity::optional_inner(ty).is_some() {
            quote!(value.parse().map(Some))
        } else {
            quote!(value.parse())
        };
        quote! {
            type UserId = #ty;
            fn parse_user_id(value: &str) -> #core::AuthResult<Self::UserId> {
                #parse.map_err(|error| #core::AuthError::bad_request(format!("Invalid account user id: {error}")))
            }
        }
    } else {
        TokenStream::new()
    };
    let id_type = identity::field_type(fields, "id")?;
    let reference_output = (role == EntityRole::Account).then(|| {
        quote! {
            if !config.fields().contains_key("userId") {
                if let Some(id) = logical.remove("userId") {
                    let id = #core::SchemaValue::<String>::from_json(Some(id)).display_string()?;
                    let _ = logical.insert("userId".into(), #core::serde_json::Value::String(id));
                }
            }
        }
    });
    let ident = &input.ident;
    Ok(quote! {
        impl #seaorm::#model for #ident {
            type Id = #id_type;
            type Entity = Entity;
            type ActiveModel = ActiveModel;
            type Column = Column;
            #user_id
            #(#query_columns)*
            fn parse_id(value: &str) -> #core::AuthResult<Self::Id> {
                value.parse().map_err(|error| #core::AuthError::bad_request(format!("Invalid model id: {error}")))
            }

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

            fn new_active(id: Option<Self::Id>, mut fields: #core::serde_json::Map<String, #core::serde_json::Value>) -> #core::AuthResult<ActiveModel> {
                let _ = fields.remove("id");
                if let Some(id) = id {
                    let _ = fields.insert("id".into(), #core::serde_json::to_value(id)?);
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

            fn record_fields(&self, config: &#core::user_fields::UserConfig) -> #core::AuthResult<#core::user_fields::AdapterRecord> {
                let mut logical = #core::serde_json::Map::from_iter([#(#core_values)*]);
                if let Some(id) = logical.remove("id") {
                    let id = #core::SchemaValue::<String>::from_json(Some(id)).display_string()?;
                    let _ = logical.insert("id".into(), #core::serde_json::Value::String(id));
                }
                #reference_output
                let mut storage = #core::serde_json::Map::new();
                for (name, field) in config.fields() {
                    if name == "id" { continue; }
                    let name = #core::store::schema::resolve_field_name(field.field_name.as_deref(), name);
                    let value = match Self::field_column(name)? { #(#values)* };
                    let _ = storage.insert(name.to_owned(), value);
                }
                Ok(#core::user_fields::AdapterRecord::new(logical, storage))
            }
        }
    })
}

pub(super) fn field_value(field: &syn::Field, core: &TokenStream) -> TokenStream {
    let ident = &field.ident;
    match date_field(&field.ty) {
        Some(false) => {
            quote!(#core::utils::date::serialize(&self.#ident, #core::serde_json::value::Serializer)?)
        }
        Some(true) => {
            quote!(#core::utils::date::serialize_option(&self.#ident, #core::serde_json::value::Serializer)?)
        }
        None => quote!(#core::serde_json::to_value(&self.#ident)?),
    }
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
