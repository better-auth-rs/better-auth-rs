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
            identity::decode(field, core, seaorm)
        } else {
            decode_field(field, seaorm)
        };
        setters.push(
            quote!(#(#aliases)|* => active.#ident = #seaorm::sea_orm::ActiveValue::Set(#decoded),),
        );
        let value = field_value(ident, seaorm);
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
                    let id = #core::SchemaValue::<String>::from_field(id).display_string()?;
                    let _ = logical.insert("userId".into(), #core::FieldValue::String(id));
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

            fn new_active(id: Option<Self::Id>, _fields: &#core::FieldMap) -> #core::AuthResult<ActiveModel> {
                Ok(ActiveModel {
                    id: id.map_or(#seaorm::sea_orm::ActiveValue::NotSet, #seaorm::sea_orm::ActiveValue::Set),
                    ..Default::default()
                })
            }

            fn apply_fields(active: &mut ActiveModel, fields: #core::FieldMap) -> #core::AuthResult<()> {
                for (name, value) in fields {
                    match name.as_str() {
                        #(#setters)*
                        _ => return Err(#core::AuthError::config(format!("Unknown adapter model field: {name}"))),
                    }
                }
                Ok(())
            }

            fn record_fields(&self, config: &#core::user_fields::UserConfig) -> #core::AuthResult<#core::user_fields::AdapterRecord> {
                let mut logical = #core::FieldMap::from_iter([#(#core_values)*]);
                if let Some(id) = logical.remove("id") {
                    let id = #core::SchemaValue::<String>::from_field(id).display_string()?;
                    let _ = logical.insert("id".into(), #core::FieldValue::String(id));
                }
                #reference_output
                let mut storage = #core::FieldMap::new();
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

pub(super) fn field_value(ident: &syn::Ident, seaorm: &TokenStream) -> TokenStream {
    let column = format_ident!(
        "{}",
        serde_rename_rule::RenameRule::PascalCase.apply_to_field(&ident.to_string())
    );
    quote!(#seaorm::__private_field_value(#seaorm::sea_orm::ModelTrait::get(self, Column::#column))?)
}

pub(super) fn decode_field(field: &syn::Field, seaorm: &TokenStream) -> TokenStream {
    decode_type(&field.ty, seaorm)
}

pub(super) fn decode_type(ty: &syn::Type, seaorm: &TokenStream) -> TokenStream {
    if let Some(inner) = identity::optional_inner(ty) {
        quote!(if value.is_null() { None } else { Some(#seaorm::__private_field_decode::<#inner>(value)?) })
    } else {
        quote!(#seaorm::__private_field_decode::<#ty>(value)?)
    }
}
