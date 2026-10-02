use super::*;

pub(super) fn generate(
    input: &DeriveInput,
    fields: &syn::FieldsNamed,
    role: EntityRole,
    model_name: Option<&LitStr>,
    seaorm_root: &TokenStream,
    core_root: &TokenStream,
) -> syn::Result<TokenStream> {
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
    let mut core_columns = Vec::new();
    let mut values = Vec::new();
    let mut references = Vec::new();
    let mut assignments = Vec::new();
    let mut output = Vec::new();
    for field in &fields.named {
        let Some(ident) = &field.ident else { continue };
        let name = ident.to_string();
        let column = format_ident!(
            "{}",
            serde_rename_rule::RenameRule::PascalCase.apply_to_field(&name)
        );
        let mut aliases = vec![
            name.clone(),
            serde_rename_rule::RenameRule::CamelCase.apply_to_field(&name),
        ];
        let serialized = serde_serialized_name(&field.attrs, "rename")?.unwrap_or_else(|| {
            rename_all
                .as_ref()
                .map_or_else(|| name.clone(), |rule| rule.apply_to_field(&name))
        });
        aliases.push(serialized);
        if role == EntityRole::ApiKey && name == "key_hash" {
            aliases.push("key".to_owned());
        }
        if role == EntityRole::Passkey && name == "credential_id" {
            aliases.push("credentialID".to_owned());
        }
        aliases.sort();
        aliases.dedup();
        columns.push(quote!(#(#aliases)|* => Ok(Column::#column),));
        let reference = identity::is_reference(role, field)?;
        references.push(quote!(Column::#column => #reference,));
        let decoded = if name == "id" || reference {
            identity::decode(field, core_root)
        } else {
            quote!(#core_root::serde_json::from_value(value)?)
        };
        assignments.push(quote!(#(#aliases)|* => active.#ident = #seaorm_root::sea_orm::ActiveValue::Set(#decoded),));
        let stored_value = adapter_record::field_value(field, core_root);
        values.push(quote!(Column::#column => #stored_value,));
        if !core.contains(&name.as_str()) {
            core_columns.push(quote!(Column::#column => None,));
            continue;
        }
        let logical = serde_rename_rule::RenameRule::CamelCase.apply_to_field(&name);
        core_columns.push(quote!(Column::#column => Some(#logical),));
        let value = if name == "id" {
            quote!(#core_root::SchemaValue::Typed(self.#ident.to_string()))
        } else if reference {
            if identity::optional_inner(&field.ty).is_some() {
                quote!(self.#ident.as_ref().map(ToString::to_string))
            } else {
                quote!(self.#ident.to_string())
            }
        } else if role == EntityRole::DeviceCode && matches!(name.as_str(), "client_id" | "scope") {
            if identity::optional_inner(&field.ty).is_some() {
                quote!(#core_root::SchemaValue::Typed(self.#ident.to_owned()))
            } else {
                quote!(#core_root::SchemaValue::Typed(Some(self.#ident.to_owned())))
            }
        } else if role == EntityRole::DeviceCode && name == "polling_interval" {
            quote!(self.#ident.map(f64::from))
        } else if role == EntityRole::RateLimit && name == "count" {
            quote!(f64::from(self.#ident.to_owned()))
        } else if role == EntityRole::ApiKey && name == "name"
            || role == EntityRole::Passkey && matches!(name.as_str(), "name" | "aaguid")
        {
            quote!(#core_root::SchemaValue::Typed(self.#ident.to_owned()))
        } else if role == EntityRole::ApiKey && name == "start" {
            quote!(self.#ident.clone().map(#core_root::ApiKeyStart::from))
        } else if role == EntityRole::ApiKey && matches!(name.as_str(), "created_at" | "updated_at")
        {
            quote!(self.#ident.to_rfc3339_opts(#seaorm_root::__private_chrono::SecondsFormat::Millis, true))
        } else if role == EntityRole::ApiKey
            && matches!(
                name.as_str(),
                "expires_at" | "last_request" | "last_refill_at"
            )
        {
            quote!(self.#ident.map(|value| value.to_rfc3339_opts(#seaorm_root::__private_chrono::SecondsFormat::Millis, true)))
        } else if role == EntityRole::Passkey && name == "counter" {
            quote!(u64::try_from(self.#ident).map_err(|error| #core_root::AuthError::config(format!("Invalid stored passkey counter: {error}")))?)
        } else {
            quote!(self.#ident.to_owned())
        };
        output.push(quote!(#ident: #value,));
    }
    if role == EntityRole::DeviceCode {
        output.push(quote!(additional_fields: Default::default(),));
    }
    let declaration = model_name.map(|name| {
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
    Ok(quote! {
        impl #seaorm_root::SeaOrmPluginModel for #ident {
            type Record = #record;
            type Entity = Entity;
            type ActiveModel = ActiveModel;
            type Column = Column;
            #declaration
            fn column(name: &str) -> #core_root::AuthResult<Column> {
                match name { #(#columns)* _ => Err(#core_root::AuthError::config(format!("Unknown plugin model column: {name}"))) }
            }
            fn core_field_name(column: &Column) -> Option<&'static str> {
                match column { #(#core_columns)* }
            }
            fn record_fields(&self, fields: &#core_root::user_fields::UserConfig) -> #core_root::AuthResult<#core_root::user_fields::AdapterRecord> {
                let mut storage = #core_root::serde_json::Map::new();
                for (name, field) in fields.fields() {
                    let name = #core_root::store::schema::resolve_field_name(field.field_name.as_deref(), name);
                    let value = match Self::column(name)? { #(#values)* };
                    let _ = storage.insert(name.to_owned(), value);
                }
                Ok(#core_root::user_fields::AdapterRecord::new(Default::default(), storage))
            }
            fn record(&self) -> #core_root::AuthResult<Self::Record> {
                Ok(#record { #(#output)* })
            }
            fn is_id_reference(column: &Column) -> bool {
                match column { #(#references)* }
            }
            fn apply_fields(active: &mut ActiveModel, fields: #core_root::serde_json::Map<String, #core_root::serde_json::Value>) -> #core_root::AuthResult<()> {
                for (name, value) in fields {
                    match name.as_str() { #(#assignments)* _ => return Err(#core_root::AuthError::config(format!("Unknown plugin model field: {name}"))) }
                }
                Ok(())
            }
        }
    })
}
