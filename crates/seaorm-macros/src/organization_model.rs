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
        let aliases = if name == serialized {
            quote!(#name)
        } else {
            quote!(#name | #serialized)
        };
        columns.push(quote!(#aliases => Ok(Column::#column),));
        serialized_columns.push(quote!(Column::#column => #serialized,));
        if core_fields.contains(&name.as_str()) {
            core_columns.push(quote!(Column::#column));
        }
        assignments.push(quote!(#aliases => active.#ident = #seaorm_root::sea_orm::ActiveValue::Set(#core_root::serde_json::from_value(value)?),));
        if core_fields.contains(&name.as_str())
            && !matches!(name.as_str(), "member_count" | "membership_key")
        {
            if name == "status" {
                output.push(quote!(#ident: self.#ident.to_owned().into()));
            } else {
                output.push(quote!(#ident: self.#ident.to_owned()));
            }
        }
    }
    let ident = &input.ident;
    let extras = if role == EntityRole::TeamMember {
        quote!()
    } else {
        quote!(additional_fields: fields.output_fields(&storage)?,)
    };
    let projection = if role == EntityRole::TeamMember {
        quote!(let _ = fields;)
    } else {
        quote! {
            let model = #core_root::serde_json::to_value(self)?;
            let model = model.as_object().ok_or_else(|| #core_root::AuthError::config("Organization models must serialize as objects"))?;
            let mut storage = #core_root::serde_json::Map::new();
            for (name, field) in &fields.additional_fields {
                let storage_name = field.field_name.as_deref().unwrap_or(name);
                let serialized_name = match Self::column(storage_name)? {
                    #(#serialized_columns)*
                };
                if let Some(value) = model.get(serialized_name) {
                    let _ = storage.insert(storage_name.to_owned(), value.clone());
                }
            }
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
