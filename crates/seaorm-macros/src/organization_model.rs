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
            core_values.push(
                quote!((#public_name.to_owned(), #core_root::serde_json::to_value(&self.#ident)?)),
            );
        } else {
            core_names.push(quote!(Column::#column => None,));
        }
        assignments.push(quote!(#(#aliases)|* => active.#ident = #seaorm_root::sea_orm::ActiveValue::Set(#core_root::serde_json::from_value(value)?),));
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
                    quote!(#ident: #core_root::SchemaValue::Typed(self.#ident.to_owned()))
                } else {
                    quote!(#ident: self.#ident.to_owned())
                });
                continue;
            }
            if name == "id" {
                output_values.push(quote!(let _ = projected.remove(#public_name);));
                output.push(if name == "id" {
                    quote!(#ident: #core_root::SchemaValue::Typed(self.#ident.to_owned()))
                } else {
                    quote!(#ident: self.#ident.to_owned())
                });
                continue;
            }
            if matches!(name.as_str(), "created_at" | "updated_at" | "expires_at") {
                output_values.push(quote! {
                    let value = projected.remove(#public_name);
                    let #ident = if fields.additional_fields.get(#public_name).is_some_and(|field| !matches!(field.field_type, #core_root::user_fields::UserFieldType::Date)) {
                        value.map(#core_root::SchemaValue::Dynamic).unwrap_or_default()
                    } else {
                        #core_root::SchemaValue::from_json(value)
                    };
                });
            } else if matches!(
                (role, name.as_str()),
                (EntityRole::Organization, "metadata")
                    | (EntityRole::OrganizationRole, "permission")
            ) {
                let unconfigured = if role == EntityRole::Organization
                    && matches!(&field.ty, syn::Type::Path(path) if path.path.segments.last().is_some_and(|segment| segment.ident == "Option"))
                {
                    quote! {
                        if matches!(
                            #seaorm_root::sea_orm::ColumnTrait::def(&Column::#column).get_column_type(),
                            #seaorm_root::sea_orm::ColumnType::Json | #seaorm_root::sea_orm::ColumnType::JsonBinary
                        ) {
                            #core_root::SchemaValue::Typed(self.#ident.as_ref().map(#core_root::serde_json::to_value).transpose()?)
                        } else {
                            value.map(#core_root::SchemaValue::Dynamic).unwrap_or_default()
                        }
                    }
                } else {
                    quote!(#core_root::SchemaValue::from_json(value))
                };
                output_values.push(quote! {
                    let value = projected.remove(#public_name);
                    let #ident = if fields.additional_fields.contains_key(#public_name) {
                        value.map(#core_root::SchemaValue::Dynamic).unwrap_or_default()
                    } else {
                        #unconfigured
                    };
                });
            } else {
                output_values.push(quote! {
                    let #ident = #core_root::SchemaValue::from_json(projected.remove(#public_name));
                });
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
    let projection = if role == EntityRole::TeamMember {
        quote! {
            let mut projected = #core_root::serde_json::Map::new();
            #(#output_values)*
        }
    } else {
        quote! {
            let model = #core_root::serde_json::to_value(self)?;
            let model = model.as_object().ok_or_else(|| #core_root::AuthError::config("Organization models must serialize as objects"))?;
            let core = #core_root::serde_json::Map::from_iter([#(#core_values),*]);
            let mut storage = #core_root::serde_json::Map::new();
            for (name, field) in &fields.additional_fields {
                if name == "id" { continue; }
                let storage_name = field.field_name.as_deref().unwrap_or(name);
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
            let mut projected = fields.organization_output_fields(core, &storage)?;
            #(#output_values)*
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
            fn record(&self, fields: &#core_root::user_fields::UserConfig) -> #core_root::AuthResult<Self::Record> {
                #projection
                Ok(#core_root::#record { #(#output,)* #extras })
            }
            fn apply_fields(active: &mut ActiveModel, fields: #core_root::serde_json::Map<String, #core_root::serde_json::Value>) -> #core_root::AuthResult<()> {
                for (name, value) in fields {
                    match name.as_str() { #(#assignments)* _ => return Err(#core_root::AuthError::config(format!("Unknown organization model field: {name}"))) }
                }
                Ok(())
            }
        }
    })
}
