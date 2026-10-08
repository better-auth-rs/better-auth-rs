use super::*;

pub(super) fn generate(
    input: &DeriveInput,
    fields: &syn::FieldsNamed,
    options: &EntityOptions,
    (seaorm_root, core_root): (&TokenStream, &TokenStream),
) -> syn::Result<TokenStream> {
    let role = options.role;
    let record = match role {
        EntityRole::ApiKey => "ApiKey",
        EntityRole::DeviceCode => "DeviceCode",
        EntityRole::Passkey => "Passkey",
        EntityRole::TwoFactor => "TwoFactor",
        EntityRole::Jwk => "Jwk",
        EntityRole::WalletAddress => "WalletAddress",
        EntityRole::RateLimit => "RateLimitRecord",
        _ => {
            return Err(syn::Error::new_spanned(
                input,
                "expected a plugin entity role",
            ));
        }
    };
    let record = format_ident!("{record}");
    let record = if role == EntityRole::RateLimit {
        quote!(#core_root::store::#record)
    } else {
        quote!(#core_root::#record)
    };
    let core = registry::core_field_names(role);
    let rename_all = serde_serialized_name(&input.attrs, "rename_all")?
        .map(|rule| {
            serde_rename_rule::RenameRule::from_rename_all_str(&rule)
                .map_err(|error| syn::Error::new_spanned(input, error.to_string()))
        })
        .transpose()?;
    let mut columns = Vec::new();
    let mut column_aliases = std::collections::BTreeSet::new();
    let mut core_columns = Vec::new();
    let mut values = Vec::new();
    let mut references = Vec::new();
    let mut assignments = Vec::new();
    let mut output = Vec::new();
    let mut raw_output = Vec::new();
    let dynamic_record = matches!(
        role,
        EntityRole::ApiKey | EntityRole::Passkey | EntityRole::DeviceCode | EntityRole::TwoFactor
    );
    for field in &fields.named {
        let Some(ident) = &field.ident else { continue };
        let name = ident.to_string();
        let column = format_ident!(
            "{}",
            serde_rename_rule::RenameRule::PascalCase.apply_to_field(&name)
        );
        let serialized = serde_serialized_name(&field.attrs, "rename")?.unwrap_or_else(|| {
            rename_all
                .as_ref()
                .map_or_else(|| name.clone(), |rule| rule.apply_to_field(&name))
        });
        let mut aliases = field_aliases::field_aliases(&name, &serialized, &field.attrs)?;
        if role == EntityRole::ApiKey && name == "key_hash" {
            aliases.push("key".to_owned());
        }
        if role == EntityRole::Passkey && name == "credential_id" {
            aliases.push("credentialID".to_owned());
        }
        aliases.sort();
        aliases.dedup();
        aliases.retain(|alias| column_aliases.insert(alias.clone()));
        if !aliases.is_empty() {
            columns.push(quote!(#(#aliases)|* => Ok(Column::#column),));
        }
        let reference = identity::is_reference(role, field)?;
        references.push(quote!(Column::#column => #reference,));
        let decoded = if name == "id" || reference {
            identity::decode(field, core_root, seaorm_root)
        } else {
            adapter_record::decode_field(field, seaorm_root)
        };
        assignments.push(quote!(Column::#column => active.#ident = #seaorm_root::sea_orm::ActiveValue::Set(#decoded),));
        let stored_value = adapter_record::field_value(ident, seaorm_root);
        values.push(quote!(Column::#column => #stored_value,));
        if !core.contains(&name.as_str()) {
            core_columns.push(quote!(Column::#column => None,));
            continue;
        }
        let logical = registry::canonical_field_name(role, &name);
        core_columns.push(quote!(Column::#column => Some(#logical),));
        raw_output.push(quote!((#logical.to_owned(), #stored_value),));
        if dynamic_record {
            continue;
        }
        let value = if name == "id" {
            quote!(#core_root::SchemaValue::Typed(self.#ident.to_string()))
        } else if reference {
            if identity::optional_inner(&field.ty).is_some() {
                quote!(self.#ident.as_ref().map(ToString::to_string))
            } else {
                quote!(self.#ident.to_string())
            }
        } else if role == EntityRole::RateLimit && name == "count" {
            quote!(f64::from(self.#ident.to_owned()))
        } else if role == EntityRole::WalletAddress && name == "chain_id" {
            quote!(i64::from(self.#ident))
        } else if matches!(
            name.as_str(),
            "expires_at" | "last_polled_at" | "locked_until" | "created_at" | "updated_at"
        ) {
            if identity::optional_inner(&field.ty).is_some() {
                quote!(self.#ident.map(Into::into))
            } else {
                quote!(self.#ident.into())
            }
        } else {
            quote!(self.#ident.to_owned())
        };
        let value = if role == EntityRole::WalletAddress && name == "user_id" {
            quote!(#core_root::SchemaValue::from_field(#core_root::SchemaField::into_field(#value)))
        } else {
            value
        };
        output.push(quote!(#ident: #value,));
    }
    let passkey_storage = options.native_passkey.then(|| {
        quote! {
            fn passkey_storage() -> #core_root::PasskeyStorage {
                #core_root::PasskeyStorage::Native
            }
        }
    });
    let two_factor_storage = options.native_two_factor.then(|| {
        quote! {
            fn two_factor_storage() -> #core_root::TwoFactorStorage {
                #core_root::TwoFactorStorage::Native
            }
        }
    });
    if matches!(
        role,
        EntityRole::ApiKey
            | EntityRole::DeviceCode
            | EntityRole::Passkey
            | EntityRole::Jwk
            | EntityRole::WalletAddress
            | EntityRole::TwoFactor
    ) {
        output.push(quote!(additional_fields: Default::default(),));
    }
    let declaration = options.model_name.as_ref().map(|name| {
        quote! {
            fn model_declaration() -> Option<#core_root::schema::ModelDeclaration> {
                Some(#core_root::schema::ModelDeclaration {
                    role: #core_root::schema::EntityRole::RateLimit,
                    model_name: Some(#name),
                    fields: None,
                })
            }
        }
    });
    let ident = &input.ident;
    let logical = if dynamic_record {
        quote!(#core_root::FieldMap::from_iter([#(#raw_output)*]))
    } else {
        quote!(Default::default())
    };
    let record_body = if dynamic_record {
        quote!(<#record as #core_root::FromFieldMap>::from_field_values(#core_root::FieldMap::from_iter([#(#raw_output)*])))
    } else {
        quote!(Ok(#record { #(#output)* }))
    };
    Ok(quote! {
        impl #seaorm_root::SeaOrmPluginModel for #ident {
            type Record = #record;
            type Entity = Entity;
            type ActiveModel = ActiveModel;
            type Column = Column;
            #declaration
            #passkey_storage
            #two_factor_storage
            fn column(name: &str) -> #core_root::AuthResult<Column> {
                if let Some(column) = <Column as #seaorm_root::sea_orm::Iterable>::iter()
                    .find(|column| #seaorm_root::sea_orm::IdenStatic::as_str(column) == name)
                {
                    return Ok(column);
                }
                match name { #(#columns)* _ => Err(#core_root::AuthError::config(format!("Unknown plugin model column: {name}"))) }
            }
            fn core_field_name(column: &Column) -> Option<&'static str> {
                match column { #(#core_columns)* }
            }
            fn record_fields(&self, fields: &#core_root::user_fields::UserConfig) -> #core_root::AuthResult<#core_root::user_fields::AdapterRecord> {
                let mut storage = #core_root::FieldMap::new();
                for (name, field) in fields.fields() {
                    let name = #core_root::store::schema::resolve_field_name(field.field_name.as_deref(), name);
                    let value = match Self::column(name)? { #(#values)* };
                    let _ = storage.insert(name.to_owned(), value);
                }
                Ok(#core_root::user_fields::AdapterRecord::new(#logical, storage))
            }
            fn record(&self) -> #core_root::AuthResult<Self::Record> {
                #record_body
            }
            fn is_id_reference(column: &Column) -> bool {
                match column { #(#references)* }
            }
            fn apply_fields(active: &mut ActiveModel, fields: #core_root::FieldMap) -> #core_root::AuthResult<()> {
                for (name, value) in fields {
                    match Self::column(&name)? { #(#assignments)* }
                }
                Ok(())
            }
        }
    })
}
