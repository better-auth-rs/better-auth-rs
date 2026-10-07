use super::*;

pub(super) fn generate(
    input: &DeriveInput,
    fields: &syn::FieldsNamed,
    role: EntityRole,
    seaorm_root: &TokenStream,
    core_root: &TokenStream,
) -> syn::Result<TokenStream> {
    let record = match role {
        EntityRole::Organization => "Organization",
        EntityRole::Member => "Member",
        EntityRole::Invitation => "Invitation",
        EntityRole::Team => "Team",
        EntityRole::TeamMember => "TeamMember",
        EntityRole::OrganizationRole => "OrganizationRole",
        _ => {
            return Err(syn::Error::new_spanned(
                input,
                "expected an organization entity role",
            ));
        }
    };
    let record = format_ident!("{record}");
    let core_fields = registry::core_field_names(role);
    let rename_rule = serde_serialized_name(&input.attrs, "rename_all")?
        .map(|rule| {
            serde_rename_rule::RenameRule::from_rename_all_str(&rule)
                .map_err(|error| syn::Error::new_spanned(input, error.to_string()))
        })
        .transpose()?;
    let mut columns = Vec::new();
    let mut references = Vec::new();
    let mut serialized_columns = Vec::new();
    let mut core_columns = Vec::new();
    let mut core_names = Vec::new();
    let mut core_values = Vec::new();
    let mut output_values = Vec::new();
    let mut assignments = Vec::new();
    let mut output = Vec::new();
    for field in &fields.named {
        let Some(ident) = &field.ident else { continue };
        let name = ident.to_string();
        let serialized = serde_serialized_name(&field.attrs, "rename")?.unwrap_or_else(|| {
            rename_rule
                .as_ref()
                .map_or_else(|| name.clone(), |rule| rule.apply_to_field(&name))
        });
        let column = format_ident!(
            "{}",
            serde_rename_rule::RenameRule::PascalCase.apply_to_field(&name)
        );
        let is_core = core_fields.contains(&name.as_str());
        let public_name = if is_core {
            serde_rename_rule::RenameRule::CamelCase.apply_to_field(&name)
        } else {
            serialized.clone()
        };
        let mut aliases = vec![name.clone(), serialized.clone(), public_name.clone()];
        aliases.sort();
        aliases.dedup();
        columns.push(quote!(#(#aliases)|* => Ok(Column::#column),));
        serialized_columns.push(quote!(Column::#column => #serialized,));
        if is_core {
            core_columns.push(quote!(Column::#column));
            core_names.push(quote!(Column::#column => Some(#public_name),));
            let value = adapter_record::field_value(ident, seaorm_root);
            core_values.push(quote!((#public_name.to_owned(), #value)));
        } else {
            core_names.push(quote!(Column::#column => None,));
        }
        let reference = identity::is_reference(role, field)?;
        references.push(quote!(Column::#column => #reference,));
        let decoded = if name == "id" || reference {
            identity::decode(field, core_root, seaorm_root)
        } else {
            adapter_record::decode_field(field, seaorm_root)
        };
        assignments.push(quote!(#(#aliases)|* => active.#ident = #seaorm_root::sea_orm::ActiveValue::Set(#decoded),));
        if is_core {
            if name == "member_count" {
                continue;
            }
            if matches!(name.as_str(), "auth_updated_at" | "membership_key") {
                output_values.push(quote!(let _ = projected.remove(#public_name);));
                continue;
            }
            if role == EntityRole::TeamMember {
                output.push(if matches!(name.as_str(), "id" | "team_id") {
                    quote!(#ident: #core_root::SchemaValue::Typed(self.#ident.to_string()))
                } else if name == "user_id" {
                    quote!(#ident: self.#ident.to_string())
                } else if name == "created_at" {
                    quote!(#ident: self.#ident.into())
                } else {
                    quote!(#ident: self.#ident.to_owned())
                });
                continue;
            }
            if name == "id" {
                output_values.push(quote!(let _ = projected.remove(#public_name);));
                output.push(if name == "id" {
                    quote!(#ident: #core_root::SchemaValue::Typed(self.#ident.to_string()))
                } else if name == "created_at" {
                    quote!(#ident: self.#ident.into())
                } else {
                    quote!(#ident: self.#ident.to_owned())
                });
                continue;
            }
            if matches!(name.as_str(), "created_at" | "updated_at" | "expires_at") {
                output_values.push(quote! {
                    let value = projected.remove(#public_name);
                    let #ident = if fields.fields().get(#public_name).is_some_and(|field| !matches!(field.field_type, #core_root::user_fields::UserFieldType::Date)) {
                        value.map(#core_root::SchemaValue::Dynamic).unwrap_or_default()
                    } else {
                        #core_root::SchemaValue::from_field(value.unwrap_or_default())
                    };
                });
            } else {
                let reference = reference.then(|| quote! {
                    if !fields.fields().contains_key(#public_name) {
                        if let Some(value) = value.as_mut().filter(|value| !value.is_null()) {
                            *value = #core_root::FieldValue::String(#core_root::SchemaValue::<String>::from_field(value.clone()).display_string()?);
                        }
                    }
                });
                output_values.push(if reference.is_some() { quote! {
                    let mut value = projected.remove(#public_name);
                    #reference
                    let #ident = #core_root::SchemaValue::from_field(value.unwrap_or_default());
                }} else { quote! {
                    let #ident = #core_root::SchemaValue::from_field(projected.remove(#public_name).unwrap_or_default());
                }});
            }
            output.push(quote!(#ident));
        }
    }
    let ident = &input.ident;
    let extras = if role == EntityRole::TeamMember {
        quote!()
    } else {
        quote!(additional_fields: projected,)
    };
    let record_fields = if role == EntityRole::TeamMember {
        quote! {
            Ok(#core_root::user_fields::AdapterRecord::new(Default::default(), Default::default()))
        }
    } else {
        quote! {
            let model = #core_root::entity::AuthRecordFields::field_values(self)?;
            let core = #core_root::FieldMap::from_iter([#(#core_values),*]);
            let mut storage = #core_root::FieldMap::new();
            for (name, field) in fields.fields() {
                if name == "id" { continue; }
                let storage_name = #core_root::store::schema::resolve_field_name(field.field_name.as_deref(), name);
                let column = Self::column(storage_name)?;
                let value = if let Some(core_name) = Self::core_field_name(&column) {
                    core.get(core_name)
                } else {
                    let serialized_name = match column {
                        #(#serialized_columns)*
                    };
                    model.get(serialized_name)
                };
                if let Some(value) = value {
                    let _ = storage.insert(storage_name.to_owned(), value.clone());
                }
            }
            Ok(#core_root::user_fields::AdapterRecord::new(core, storage))
        }
    };
    Ok(quote! {
        impl #seaorm_root::SeaOrmOrganizationModel for #ident {
            type Record = #core_root::#record;
            type Entity = Entity;
            type ActiveModel = ActiveModel;
            type Column = Column;
            fn column(name: &str) -> #core_root::AuthResult<Column> {
                match name { #(#columns)* _ => Err(#core_root::AuthError::config(format!("Unknown organization model column: {name}"))) }
            }
            fn is_core_column(column: &Column) -> bool {
                matches!(column, #(#core_columns)|*)
            }
            fn core_field_name(column: &Column) -> Option<&'static str> {
                match column { #(#core_names)* }
            }
            fn record_fields(&self, fields: &#core_root::user_fields::UserConfig) -> #core_root::AuthResult<#core_root::user_fields::AdapterRecord> {
                #record_fields
            }
            fn record_from_fields(&self, fields: &#core_root::user_fields::UserConfig, mut projected: #core_root::FieldMap) -> #core_root::AuthResult<Self::Record> {
                #(#output_values)*
                Ok(#core_root::#record { #(#output,)* #extras })
            }
            fn is_id_reference(column: &Column) -> bool {
                match column { #(#references)* }
            }
            fn apply_fields(active: &mut ActiveModel, fields: #core_root::FieldMap) -> #core_root::AuthResult<()> {
                for (name, value) in fields {
                    match name.as_str() { #(#assignments)* _ => return Err(#core_root::AuthError::config(format!("Unknown organization model field: {name}"))) }
                }
                Ok(())
            }
        }
    })
}
