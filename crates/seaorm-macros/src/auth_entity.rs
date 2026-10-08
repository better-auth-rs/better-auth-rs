use better_auth_schema_registry::{self as registry, EntityRole};
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Ident, Span, TokenStream};
use quote::{format_ident, quote};
use syn::{
    Attribute, Data, DeriveInput, Expr, Fields, Lit, LitStr, Meta, Token, punctuated::Punctuated,
};
#[path = "organization_model.rs"]
mod organization_model;
use organization_model::generate as gen_organization_model;
#[path = "adapter_record.rs"]
mod adapter_record;
#[path = "field_aliases.rs"]
mod field_aliases;
#[path = "identity.rs"]
mod identity;
#[path = "plugin_model.rs"]
mod plugin_model;

fn serde_serialized_name(attrs: &[Attribute], key: &str) -> syn::Result<Option<String>> {
    for attr in attrs.iter().filter(|attr| attr.path().is_ident("serde")) {
        for meta in attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)? {
            if !meta.path().is_ident(key) {
                continue;
            }
            let value = match meta {
                Meta::NameValue(value) => Some(value.value),
                Meta::List(list) => list
                    .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?
                    .into_iter()
                    .find_map(|meta| match meta {
                        Meta::NameValue(value) if value.path.is_ident("serialize") => {
                            Some(value.value)
                        }
                        _ => None,
                    }),
                Meta::Path(_) => None,
            };
            if let Some(Expr::Lit(value)) = value
                && let Lit::Str(value) = value.lit
            {
                return Ok(Some(value.value()));
            }
        }
    }
    Ok(None)
}

fn found_crate_tokens(name: &str) -> Option<TokenStream> {
    match crate_name(name).ok()? {
        FoundCrate::Itself => {
            // `Itself` means the Cargo.toml that triggered compilation lists
            // this crate as its own package name.  Examples and integration
            // tests compile as separate binaries that link the crate
            // externally, so `crate::` would be wrong — use the extern name.
            let ident = Ident::new(&name.replace('-', "_"), Span::call_site());
            Some(quote!(::#ident))
        }
        FoundCrate::Name(name) => {
            let ident = Ident::new(&name, Span::call_site());
            Some(quote!(::#ident))
        }
    }
}

fn resolve_roots() -> syn::Result<(TokenStream, TokenStream)> {
    if let Some(better_auth_root) = found_crate_tokens("better-auth") {
        return Ok((
            quote!(#better_auth_root::seaorm),
            quote!(#better_auth_root::__private_core),
        ));
    }
    if let Some(seaorm_root) = found_crate_tokens("better-auth-seaorm") {
        let core_root = quote!(#seaorm_root::__private_core);
        return Ok((seaorm_root, core_root));
    }
    Err(syn::Error::new(
        Span::call_site(),
        "AuthEntity requires better-auth with the `seaorm2` feature or a direct better-auth-seaorm dependency",
    ))
}

pub(crate) fn derive_auth_entity(input: &DeriveInput) -> TokenStream {
    let (seaorm_root, core_root) = match resolve_roots() {
        Ok(roots) => roots,
        Err(error) => return error.to_compile_error(),
    };
    let options = match parse_options(input) {
        Ok(options) => options,
        Err(err) => return err.to_compile_error(),
    };
    let EntityOptions {
        role, row_presence, ..
    } = options;

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => fields,
            _ => {
                return syn::Error::new_spanned(
                    &input.ident,
                    "AuthEntity requires a struct with named fields",
                )
                .to_compile_error();
            }
        },
        _ => {
            return syn::Error::new_spanned(&input.ident, "AuthEntity requires a struct")
                .to_compile_error();
        }
    };

    let idents: Vec<_> = fields
        .named
        .iter()
        .filter_map(|field| field.ident.clone())
        .collect();

    let core = registry::core_field_names(role);
    let plugin = registry::plugin_field_names(role);

    // Validate core fields are present
    if let Some(missing) = core.iter().find(|required| {
        !(matches!(
            role,
            EntityRole::ApiKey
                | EntityRole::Passkey
                | EntityRole::DeviceCode
                | EntityRole::TwoFactor
                | EntityRole::Jwk
                | EntityRole::WalletAddress
        ) && **required != "id"
            || row_presence && **required == "active")
            && !idents.iter().any(|ident| ident == *required)
    }) {
        return syn::Error::new_spanned(
            &input.ident,
            format!("missing required auth field `{missing}` for this role"),
        )
        .to_compile_error();
    }

    let has = |name: &str| idents.iter().any(|i| i == name);

    // LastLoginMethod uses runtime field policies rather than typed CreateUser fields.
    let all_known: Vec<&str> = core
        .iter()
        .chain(plugin.iter())
        .copied()
        .filter(|name| *name != "last_login_method")
        .collect();
    let extra_not_set: Vec<_> = idents
        .iter()
        .filter(|ident| !all_known.iter().any(|known| ident == known))
        .map(|field| {
            quote! { #field: #seaorm_root::sea_orm::ActiveValue::NotSet }
        })
        .collect();

    let ident = &input.ident;
    let extra_updates = (|| -> syn::Result<(Vec<TokenStream>, TokenStream)> {
        let rule = serde_serialized_name(&input.attrs, "rename_all")?
            .map(|rule| {
                serde_rename_rule::RenameRule::from_rename_all_str(&rule)
                    .map_err(|error| syn::Error::new_spanned(input, error.to_string()))
            })
            .transpose()?;
        let mut updates = Vec::new();
        let mut json_columns = Vec::new();
        let mut field_columns = Vec::new();
        for field in &fields.named {
            let Some(ident) = &field.ident else {
                continue;
            };
            let name = serde_serialized_name(&field.attrs, "rename")?.unwrap_or_else(|| {
                rule.as_ref().map_or_else(
                    || ident.to_string(),
                    |rule| rule.apply_to_field(&ident.to_string()),
                )
            });
            let column = format_ident!(
                "{}",
                serde_rename_rule::RenameRule::PascalCase.apply_to_field(&ident.to_string())
            );
            let column_aliases =
                field_aliases::field_aliases(&ident.to_string(), &name, &field.attrs)?;
            if row_presence && column_aliases.iter().any(|alias| alias == "active") {
                return Err(syn::Error::new_spanned(
                    field,
                    "row_presence session models cannot expose an active field",
                ));
            }
            field_columns.push(quote! { #(#column_aliases)|* => Ok(Column::#column), });
            if role != EntityRole::Session
                && all_known.iter().any(|known| ident == known)
                && ident != "username"
                && ident != "display_username"
                && ident != "name"
                && ident != "image"
            {
                continue;
            }
            let mut aliases =
                if matches!(role, EntityRole::Session) || ident == "name" || ident == "image" {
                    column_aliases
                } else {
                    vec![name]
                };
            if ident == "username" || ident == "display_username" {
                let canonical = if ident == "username" {
                    "username"
                } else {
                    "displayUsername"
                };
                if !aliases.iter().any(|name| name == canonical) {
                    aliases.push(canonical.to_owned());
                }
            }
            let value = if ident == "id" || identity::is_reference(role, field)? {
                identity::decode(field, &core_root, &seaorm_root)
            } else {
                adapter_record::decode_field(field, &seaorm_root)
            };
            updates.push(quote! {
                #(#aliases)|* => active.#ident = #seaorm_root::sea_orm::ActiveValue::Set(
                    #value,
                ),
            });
            json_columns.push(quote! {
                #(#aliases)|* => matches!(#seaorm_root::sea_orm::ColumnTrait::def(&Column::#column).get_column_type(), #seaorm_root::sea_orm::ColumnType::Json | #seaorm_root::sea_orm::ColumnType::JsonBinary),
            });
        }
        let methods = quote! {
            fn native_json_field(name: &str) -> bool {
                match name { #(#json_columns)* _ => false }
            }
            fn field_column(name: &str) -> #core_root::AuthResult<<Self::Entity as #seaorm_root::sea_orm::EntityTrait>::Column> {
                match name {
                    #(#field_columns)*
                    _ => Err(#core_root::AuthError::config(format!("Unknown reference model field: {name}"))),
                }
            }
        };
        Ok((updates, methods))
    })();
    let (extra_updates, field_methods) = match extra_updates {
        Ok(updates) => updates,
        Err(error) => return error.to_compile_error(),
    };

    let aliases = if matches!(role, EntityRole::Session | EntityRole::User) {
        match field_aliases::generate(
            input,
            fields,
            &all_known
                .iter()
                .copied()
                .filter(|name| {
                    role != EntityRole::User
                        || !["name", "image", "two_factor_enabled"].contains(name)
                })
                .collect::<Vec<_>>(),
        ) {
            Ok(methods) => methods,
            Err(error) => return error.to_compile_error(),
        }
    } else {
        TokenStream::new()
    };

    let record_fields = (|| -> syn::Result<TokenStream> {
        let rule = serde_serialized_name(&input.attrs, "rename_all")?
            .map(|rule| {
                serde_rename_rule::RenameRule::from_rename_all_str(&rule)
                    .map_err(|error| syn::Error::new_spanned(input, error.to_string()))
            })
            .transpose()?;
        let values = fields
            .named
            .iter()
            .map(|field| {
                let ident = field.ident.as_ref().ok_or_else(|| {
                    syn::Error::new_spanned(field, "AuthEntity requires named fields")
                })?;
                let name = ident.to_string();
                let name = serde_serialized_name(&field.attrs, "rename")?.unwrap_or_else(|| {
                    rule.as_ref()
                        .map_or_else(|| name.clone(), |rule| rule.apply_to_field(&name))
                });
                let value = adapter_record::field_value(ident, &seaorm_root);
                Ok(quote!((#name.to_owned(), #value)))
            })
            .collect::<syn::Result<Vec<_>>>()?;
        Ok(quote! {
            impl #core_root::entity::AuthRecordFields for #ident {
                fn field_values(&self) -> #core_root::AuthResult<#core_root::FieldMap> {
                    Ok(#core_root::FieldMap::from_iter([#(#values),*]))
                }
            }
        })
    })()
    .unwrap_or_else(syn::Error::into_compile_error);
    let implementation = match role {
        EntityRole::User => gen_user(
            (ident, fields),
            &aliases,
            &has,
            &extra_not_set,
            &extra_updates,
            &field_methods,
            (&seaorm_root, &core_root),
        )
        .unwrap_or_else(syn::Error::into_compile_error),
        EntityRole::Session => gen_session(
            (ident, fields),
            &aliases,
            &has,
            &extra_not_set,
            &extra_updates,
            &field_methods,
            (&seaorm_root, &core_root),
        )
        .unwrap_or_else(syn::Error::into_compile_error),
        role @ (EntityRole::Account | EntityRole::Verification) => {
            adapter_record::generate(input, fields, role, &seaorm_root, &core_root)
                .unwrap_or_else(syn::Error::into_compile_error)
        }
        EntityRole::ApiKey
        | EntityRole::DeviceCode
        | EntityRole::Passkey
        | EntityRole::TwoFactor
        | EntityRole::Jwk
        | EntityRole::WalletAddress
        | EntityRole::RateLimit => {
            plugin_model::generate(input, fields, &options, (&seaorm_root, &core_root))
                .unwrap_or_else(syn::Error::into_compile_error)
        }
        role => gen_organization_model(input, fields, role, &seaorm_root, &core_root)
            .unwrap_or_else(|error| error.to_compile_error()),
    };
    quote!(#record_fields #implementation)
}

fn gen_user(
    model: (&Ident, &syn::FieldsNamed),
    aliases: &TokenStream,
    has: &dyn Fn(&str) -> bool,
    extras: &[TokenStream],
    extra_updates: &[TokenStream],
    field_methods: &TokenStream,
    (seaorm_root, core_root): (&TokenStream, &TokenStream),
) -> syn::Result<TokenStream> {
    let (ident, fields) = model;
    let id_type = identity::field_type(fields, "id")?;
    let id_view = identity::string_view(id_type, "id");
    let decode_name =
        adapter_record::decode_type(identity::field_type(fields, "name")?, seaorm_root);
    let decode_image =
        adapter_record::decode_type(identity::field_type(fields, "image")?, seaorm_root);
    let decode_metadata = fields
        .named
        .iter()
        .find(|field| {
            field
                .ident
                .as_ref()
                .is_some_and(|ident| ident == "metadata")
        })
        .map(|field| adapter_record::decode_field(field, seaorm_root));
    let optional_two_factor = fields.named.iter().any(|field| {
        field
            .ident
            .as_ref()
            .is_some_and(|ident| ident == "two_factor_enabled")
            && identity::optional_inner(&field.ty).is_some()
    });
    let plugin_fields: Vec<_> = registry::plugin_field_names(EntityRole::User)
        .into_iter()
        .filter(|name| has(name))
        .collect();

    let native_getters = [
        "email", "email_verified", "created_at", "updated_at", "is_anonymous",
        "phone_number", "phone_number_verified", "username", "display_username",
        "two_factor_enabled", "role", "banned", "ban_reason", "ban_expires",
    ].into_iter().map(|name| {
        let field = format_ident!("{name}");
        let ty = match name {
            "email_verified" | "banned" => quote!(bool),
            "created_at" | "updated_at" => quote!(#core_root::FieldDate),
            "ban_expires" => quote!(Option<#core_root::FieldDate>),
            "is_anonymous" | "phone_number_verified" | "two_factor_enabled" => quote!(Option<bool>),
            _ => quote!(Option<::std::borrow::Cow<'_, str>>),
        };
        let value = if has(name) {
            quote!(#core_root::SchemaValue::from_field(#core_root::SchemaField::into_field(&self.#field)))
        } else {
            quote!(#core_root::SchemaValue::Undefined)
        };
        quote! { fn #field(&self) -> #core_root::SchemaValue<#ty> { #value } }
    });
    let phone_column_impl = if has("phone_number") {
        quote! { fn phone_number_column() -> Option<Self::Column> { Some(Column::PhoneNumber) } }
    } else {
        quote! {}
    };

    // new_active — plugin fields get Set(default) when present, omitted when absent
    let plugin_new_active = plugin_set_fields_user(
        has,
        optional_two_factor,
        decode_metadata.as_ref(),
        seaorm_root,
        core_root,
    );

    // apply_update — only update fields that exist
    let plugin_apply_update = plugin_update_fields_user(
        has,
        optional_two_factor,
        decode_metadata.as_ref(),
        seaorm_root,
        core_root,
    );

    let username_column_impl = if has("username") {
        quote! { fn username_column() -> Option<Self::Column> { Some(Column::Username) } }
    } else {
        // Use trait default (returns None)
        quote! {}
    };

    Ok(quote! {
        impl #core_root::entity::AuthUser for #ident {
            #aliases
            const PLUGIN_FIELDS: &'static [&'static str] = &[#(#plugin_fields),*];
            fn id(&self) -> #core_root::SchemaValue<::std::borrow::Cow<'_, str>> { #core_root::SchemaValue::Typed(#id_view) }
            #(#native_getters)*
        }

        impl #seaorm_root::SeaOrmUserModel for #ident {
            #field_methods
            fn apply_fields(active: &mut Self::ActiveModel, fields: #core_root::FieldMap) -> #core_root::AuthResult<()> {
                for (name, value) in fields {
                    match name.as_str() {
                        #(#extra_updates)*
                        _ => return Err(#core_root::AuthError::config(format!("Unknown user model field: {name}"))),
                    }
                }
                Ok(())
            }
            type Id = #id_type;
            type Entity = Entity;
            type ActiveModel = ActiveModel;
            type Column = Column;

            fn id_column() -> Self::Column { Column::Id }
            fn email_column() -> Self::Column { Column::Email }
            #phone_column_impl
            #username_column_impl
            fn name_column() -> Self::Column { Column::Name }
            fn created_at_column() -> Self::Column { Column::CreatedAt }
            fn parse_id(id: &str) -> #core_root::AuthResult<Self::Id> {
                id.parse().map_err(|error| #core_root::AuthError::bad_request(format!("Invalid user id: {error}")))
            }

            fn new_active(
                id: ::std::option::Option<Self::Id>,
                create_user: #core_root::types::CreateUser,
                now: #seaorm_root::sea_orm::entity::prelude::DateTimeUtc,
            ) -> #core_root::AuthResult<Self::ActiveModel> {
                Ok(Self::ActiveModel {
                    id: id.map_or(#seaorm_root::sea_orm::ActiveValue::NotSet, #seaorm_root::sea_orm::ActiveValue::Set),
                    email: #seaorm_root::sea_orm::ActiveValue::Set(create_user.email),
                    name: match Some(create_user.name.into_field_value()).filter(|value| !value.is_undefined()) {
                        Some(value) => #seaorm_root::sea_orm::ActiveValue::Set(#decode_name),
                        None => #seaorm_root::sea_orm::ActiveValue::NotSet,
                    },
                    image: match Some(create_user.image.into_field_value()).filter(|value| !value.is_undefined()) {
                        Some(value) => #seaorm_root::sea_orm::ActiveValue::Set(#decode_image),
                        None => #seaorm_root::sea_orm::ActiveValue::NotSet,
                    },
                    email_verified: #seaorm_root::sea_orm::ActiveValue::Set(create_user.email_verified.unwrap_or(false)),
                    created_at: #seaorm_root::sea_orm::ActiveValue::Set(now),
                    updated_at: #seaorm_root::sea_orm::ActiveValue::Set(now),
                    #(#plugin_new_active,)*
                    #(#extras,)*
                })
            }

            fn apply_update(
                active: &mut Self::ActiveModel,
                update: #core_root::types::UpdateUser,
                now: #seaorm_root::sea_orm::entity::prelude::DateTimeUtc,
            ) -> #core_root::AuthResult<()> {
                if let Some(value) = Some(update.name.into_field_value()).filter(|value| !value.is_undefined()) {
                    active.name = #seaorm_root::sea_orm::ActiveValue::Set(#decode_name);
                }
                if let Some(value) = Some(update.image.into_field_value()).filter(|value| !value.is_undefined()) {
                    active.image = #seaorm_root::sea_orm::ActiveValue::Set(#decode_image);
                }
                if let ::std::option::Option::Some(email) = update.email {
                    active.email = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(email));
                }
                if let ::std::option::Option::Some(email_verified) = update.email_verified {
                    active.email_verified = #seaorm_root::sea_orm::ActiveValue::Set(email_verified);
                }
                #(#plugin_apply_update)*
                active.updated_at = #seaorm_root::sea_orm::ActiveValue::Set(now);
                Ok(())
            }
        }
    })
}

/// Generate `new_active` field assignments for present plugin fields on User.
fn plugin_set_fields_user(
    has: &dyn Fn(&str) -> bool,
    optional_two_factor: bool,
    decode_metadata: Option<&TokenStream>,
    seaorm_root: &TokenStream,
    core_root: &TokenStream,
) -> Vec<TokenStream> {
    let mut out = Vec::new();
    for name in ["is_anonymous", "phone_number", "phone_number_verified"] {
        if has(name) {
            let field = format_ident!("{name}");
            out.push(
                quote! { #field: #seaorm_root::sea_orm::ActiveValue::Set(create_user.#field) },
            );
        }
    }
    if has("username") {
        out.push(
            quote! { username: #seaorm_root::sea_orm::ActiveValue::Set(create_user.username.flatten()) },
        );
    }
    if has("display_username") {
        out.push(quote! { display_username: #seaorm_root::sea_orm::ActiveValue::Set(create_user.display_username.flatten()) });
    }
    if has("two_factor_enabled") {
        let value = if optional_two_factor {
            quote!(Some(false))
        } else {
            quote!(false)
        };
        out.push(quote! { two_factor_enabled: #seaorm_root::sea_orm::ActiveValue::Set(#value) });
    }
    if has("role") {
        out.push(quote! { role: #seaorm_root::sea_orm::ActiveValue::Set(create_user.role) });
    }
    if has("banned") {
        out.push(quote! { banned: #seaorm_root::sea_orm::ActiveValue::Set(create_user.banned.unwrap_or(false)) });
    }
    if has("ban_reason") {
        out.push(
            quote! { ban_reason: #seaorm_root::sea_orm::ActiveValue::Set(create_user.ban_reason) },
        );
    }
    if has("ban_expires") {
        out.push(quote! { ban_expires: #seaorm_root::sea_orm::ActiveValue::Set(create_user.ban_expires.map(|value| #seaorm_root::__private_field_decode(#core_root::FieldValue::Date(value))).transpose()?) });
    }
    if let Some(decode_metadata) = decode_metadata {
        out.push(quote! { metadata: #seaorm_root::sea_orm::ActiveValue::Set({ let value = create_user.metadata.unwrap_or_else(|| #core_root::FieldValue::Object(::std::sync::Arc::new(Default::default()))); #decode_metadata }) });
    }
    out
}

/// Generate `apply_update` statements for present plugin fields on User.
fn plugin_update_fields_user(
    has: &dyn Fn(&str) -> bool,
    optional_two_factor: bool,
    decode_metadata: Option<&TokenStream>,
    seaorm_root: &TokenStream,
    core_root: &TokenStream,
) -> Vec<TokenStream> {
    let mut out = Vec::new();
    for name in ["is_anonymous", "phone_number_verified"] {
        if has(name) {
            let field = format_ident!("{name}");
            out.push(quote! { if let Some(value) = update.#field { active.#field = #seaorm_root::sea_orm::ActiveValue::Set(Some(value)); } });
        }
    }
    if has("phone_number") {
        out.push(quote! { if let Some(value) = update.phone_number { active.phone_number = #seaorm_root::sea_orm::ActiveValue::Set(value); } });
    }
    if has("username") {
        out.push(quote! {
            if let ::std::option::Option::Some(username) = update.username {
                active.username = #seaorm_root::sea_orm::ActiveValue::Set(username);
            }
        });
    }
    if has("display_username") {
        out.push(quote! {
            if let ::std::option::Option::Some(display_username) = update.display_username {
                active.display_username = #seaorm_root::sea_orm::ActiveValue::Set(display_username);
            }
        });
    }
    if has("role") {
        out.push(quote! {
            if let ::std::option::Option::Some(role) = update.role {
                active.role = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(role));
            }
        });
    }
    if has("two_factor_enabled") {
        let value = if optional_two_factor {
            quote!(Some(two_factor_enabled))
        } else {
            quote!(two_factor_enabled)
        };
        out.push(quote! {
            if let ::std::option::Option::Some(two_factor_enabled) = update.two_factor_enabled {
                active.two_factor_enabled = #seaorm_root::sea_orm::ActiveValue::Set(#value);
            }
        });
    }
    if let Some(decode_metadata) = decode_metadata {
        out.push(quote! {
            if let ::std::option::Option::Some(value) = update.metadata {
                active.metadata = #seaorm_root::sea_orm::ActiveValue::Set(#decode_metadata);
            }
        });
    }
    for name in ["banned", "ban_reason"] {
        if has(name) {
            let field = format_ident!("{name}");
            out.push(quote! {
                if let Some(value) = update.#field {
                    active.#field = #seaorm_root::sea_orm::ActiveValue::Set(value);
                }
            });
        }
    }
    if has("ban_expires") {
        out.push(quote! { if let Some(value) = update.ban_expires { active.ban_expires = #seaorm_root::sea_orm::ActiveValue::Set(value.map(|value| #seaorm_root::__private_field_decode(#core_root::FieldValue::Date(value))).transpose()?); } });
    }
    out
}

fn gen_session(
    model: (&Ident, &syn::FieldsNamed),
    aliases: &TokenStream,
    has: &dyn Fn(&str) -> bool,
    extras: &[TokenStream],
    extra_updates: &[TokenStream],
    field_methods: &TokenStream,
    (seaorm_root, core_root): (&TokenStream, &TokenStream),
) -> syn::Result<TokenStream> {
    let (ident, fields) = model;
    let id_type = identity::field_type(fields, "id")?;
    let user_id_type = identity::field_type(fields, "user_id")?;
    let id_view = identity::string_view(id_type, "id");
    let user_id_view = identity::string_view(user_id_type, "user_id");
    let decode = |name: &str, value: TokenStream| -> syn::Result<TokenStream> {
        let decode = adapter_record::decode_type(identity::field_type(fields, name)?, seaorm_root);
        Ok(quote!({
            let value = #core_root::SchemaField::into_field(#value);
            #decode
        }))
    };
    let native_fields = [
        "token",
        "expires_at",
        "created_at",
        "updated_at",
        "ip_address",
        "user_agent",
        "impersonated_by",
        "active_organization_id",
        "active_team_id",
    ];
    let updates = native_fields
        .into_iter()
        .filter(|name| has(name))
        .map(|name| {
            let field = format_ident!("{name}");
            let value = decode(name, quote!(value))?;
            Ok(quote! {
                if let Some(value) = update.#field {
                    active.#field = #seaorm_root::sea_orm::ActiveValue::Set(#value);
                }
            })
        })
        .collect::<syn::Result<Vec<_>>>()?;
    let getters = native_fields.into_iter().map(|name| {
        let field = format_ident!("{name}");
        let ty = match name {
            "expires_at" | "created_at" | "updated_at" => quote!(#core_root::FieldDate),
            "token" => quote!(::std::borrow::Cow<'_, str>),
            _ => quote!(Option<::std::borrow::Cow<'_, str>>),
        };
        let value = if has(name) {
            quote!(#core_root::SchemaValue::from_field(#core_root::SchemaField::into_field(&self.#field)))
        } else {
            quote!(#core_root::SchemaValue::Typed(None))
        };
        quote! { fn #field(&self) -> #core_root::SchemaValue<#ty> { #value } }
    });
    let plugin_fields: Vec<_> = registry::plugin_field_names(EntityRole::Session)
        .into_iter()
        .filter(|name| has(name))
        .collect();

    let active_value = if has("active") {
        quote!(self.active)
    } else {
        quote!(true)
    };
    let active_column = if has("active") {
        quote!(Some(Column::Active))
    } else {
        quote!(None)
    };
    let active_insert =
        has("active").then(|| quote!(active: #seaorm_root::sea_orm::ActiveValue::Set(true),));
    let initial_fields = native_fields
        .into_iter()
        .filter(|name| has(name) && *name != "expires_at")
        .map(|name| {
            let field = format_ident!("{name}");
            let input = match name {
                "token" => quote!(token),
                "created_at" | "updated_at" => quote!(now),
                "active_team_id" => quote!(None::<String>),
                _ => quote!(create_session.#field),
            };
            let value = decode(name, input)?;
            Ok(quote!(#field: #seaorm_root::sea_orm::ActiveValue::Set(#value)))
        })
        .collect::<syn::Result<Vec<_>>>()?;
    let setters = [
        "expires_at",
        "updated_at",
        "active_organization_id",
        "active_team_id",
    ]
    .into_iter()
    .map(|name| {
        let field = format_ident!("{name}");
        let method = format_ident!("set_{name}");
        let ty = if matches!(name, "expires_at" | "updated_at") {
            quote!(#seaorm_root::sea_orm::entity::prelude::DateTimeUtc)
        } else {
            quote!(Option<String>)
        };
        let body = if has(name) {
            let value = decode(name, quote!(value))?;
            quote!(active.#field = #seaorm_root::sea_orm::ActiveValue::Set(#value);)
        } else {
            quote!(let _ = (active, value);)
        };
        Ok(quote! {
            fn #method(active: &mut Self::ActiveModel, value: #ty) -> #core_root::AuthResult<()> {
                #body
                Ok(())
            }
        })
    })
    .collect::<syn::Result<Vec<_>>>()?;

    Ok(quote! {
        impl #core_root::entity::AuthSession for #ident {
            #aliases
            const PLUGIN_FIELDS: &'static [&'static str] = &[#(#plugin_fields),*];
            fn id(&self) -> #core_root::SchemaValue<::std::borrow::Cow<'_, str>> { #core_root::SchemaValue::Typed(#id_view) }
            #(#getters)*
            fn user_id(&self) -> #core_root::SchemaValue<::std::borrow::Cow<'_, str>> { #core_root::SchemaValue::Typed(#user_id_view) }
            fn active(&self) -> bool { #active_value }
        }

        impl #seaorm_root::SeaOrmSessionModel for #ident {
            fn apply_update(active: &mut Self::ActiveModel, update: #seaorm_root::SessionUpdate) -> #core_root::AuthResult<()> {
                if let Some(id) = update.id { active.id = #seaorm_root::sea_orm::ActiveValue::Set(Self::parse_id(&id)?); }
                if let Some(id) = update.user_id { active.user_id = #seaorm_root::sea_orm::ActiveValue::Set(Self::parse_user_id(&id)?); }
                #(#updates)*
                Ok(())
            }
            #field_methods
            type Id = #id_type;
            type UserId = #user_id_type;
            type Entity = Entity;
            type ActiveModel = ActiveModel;
            type Column = Column;

            fn apply_fields(
                active: &mut Self::ActiveModel,
                fields: #core_root::FieldMap,
            ) -> #core_root::AuthResult<()> {
                for (name, value) in fields {
                    match name.as_str() {
                        #(#extra_updates)*
                        _ => return Err(#core_root::AuthError::Config(
                            format!("Unknown session model field: {name}"),
                        )),
                    }
                }
                Ok(())
            }

            fn id_column() -> Self::Column { Column::Id }
            fn token_column() -> Self::Column { Column::Token }
            fn user_id_column() -> Self::Column { Column::UserId }
            fn active_column() -> Option<Self::Column> { #active_column }
            fn expires_at_column() -> Self::Column { Column::ExpiresAt }
            fn created_at_column() -> Self::Column { Column::CreatedAt }
            fn parse_id(id: &str) -> #core_root::AuthResult<Self::Id> {
                id.parse().map_err(|error| #core_root::AuthError::bad_request(format!("Invalid session id: {error}")))
            }
            fn parse_user_id(user_id: &str) -> #core_root::AuthResult<Self::UserId> {
                user_id.parse().map_err(|error| #core_root::AuthError::bad_request(format!("Invalid session user id: {error}")))
            }

            fn new_active(
                id: ::std::option::Option<Self::Id>,
                token: ::std::string::String,
                create_session: #core_root::types::CreateSession,
                now: #seaorm_root::sea_orm::entity::prelude::DateTimeUtc,
            ) -> #core_root::AuthResult<Self::ActiveModel> {
                Ok(Self::ActiveModel {
                    id: id.map_or(#seaorm_root::sea_orm::ActiveValue::NotSet, #seaorm_root::sea_orm::ActiveValue::Set),
                    user_id: match create_session.user_id { #core_root::SchemaValue::Typed(id) => #seaorm_root::sea_orm::ActiveValue::Set(Self::parse_user_id(&id)?), _ => #seaorm_root::sea_orm::ActiveValue::NotSet },
                    expires_at: #seaorm_root::sea_orm::ActiveValue::NotSet,
                    #(#initial_fields,)*
                    #active_insert
                    #(#extras,)*
                })
            }

            fn new_active_from_fields(
                id: Option<Self::Id>,
                _fields: &#core_root::FieldMap,
            ) -> #core_root::AuthResult<Self::ActiveModel> {
                Ok(Self::ActiveModel {
                    id: id.map_or(#seaorm_root::sea_orm::ActiveValue::NotSet, #seaorm_root::sea_orm::ActiveValue::Set),
                    #active_insert
                    ..Default::default()
                })
            }

            #(#setters)*
        }
    })
}

struct EntityOptions {
    role: EntityRole,
    model_name: Option<LitStr>,
    row_presence: bool,
    native_passkey: bool,
    native_two_factor: bool,
}

fn parse_options(input: &DeriveInput) -> syn::Result<EntityOptions> {
    let mut parsed = None;
    let mut model_name = None;
    let mut row_presence = false;
    let mut native_passkey = false;
    let mut native_two_factor = false;
    for attr in &input.attrs {
        if !attr.path().is_ident("auth") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("role") {
                let value = meta.value()?;
                let role: LitStr = value.parse()?;
                parsed = Some(match role.value().as_str() {
                    "user" => EntityRole::User,
                    "session" => EntityRole::Session,
                    "account" => EntityRole::Account,
                    "verification" => EntityRole::Verification,
                    "api_key" => EntityRole::ApiKey,
                    "device_code" => EntityRole::DeviceCode,
                    "passkey" => EntityRole::Passkey,
                    "two_factor" => EntityRole::TwoFactor,
                    "jwk" => EntityRole::Jwk,
                    "wallet_address" => EntityRole::WalletAddress,
                    "rate_limit" => EntityRole::RateLimit,
                    "organization" => EntityRole::Organization,
                    "member" => EntityRole::Member,
                    "invitation" => EntityRole::Invitation,
                    "team" => EntityRole::Team,
                    "team_member" => EntityRole::TeamMember,
                    "organization_role" => EntityRole::OrganizationRole,
                    _ => {
                        return Err(syn::Error::new_spanned(
                            role,
                            "unsupported auth role; use a core, organization, or supported plugin model role",
                        ));
                    }
                });
                Ok(())
            } else if meta.path.is_ident("row_presence") {
                row_presence = true;
                Ok(())
            } else if meta.path.is_ident("native_passkey") {
                native_passkey = true;
                Ok(())
            } else if meta.path.is_ident("native_two_factor") {
                native_two_factor = true;
                Ok(())
            } else if meta.path.is_ident("model_name") {
                model_name = Some(meta.value()?.parse::<LitStr>()?);
                Ok(())
            } else {
                Err(meta.error("expected `role = \"...\"`, `model_name = \"...\"`, `row_presence`, `native_passkey`, or `native_two_factor`"))
            }
        })?;
    }

    let role = parsed.ok_or_else(|| {
        syn::Error::new_spanned(
            input,
            "missing #[auth(role = \"...\")] attribute for AuthEntity",
        )
    })?;
    if role != EntityRole::RateLimit
        && let Some(name) = &model_name
    {
        return Err(syn::Error::new_spanned(
            name,
            "model_name is supported for the rate_limit role",
        ));
    }
    if row_presence && role != EntityRole::Session {
        return Err(syn::Error::new_spanned(
            input,
            "row_presence is supported for the session role",
        ));
    }
    if native_passkey && role != EntityRole::Passkey {
        return Err(syn::Error::new_spanned(
            input,
            "native_passkey is supported for the passkey role",
        ));
    }
    if native_two_factor && role != EntityRole::TwoFactor {
        return Err(syn::Error::new_spanned(
            input,
            "native_two_factor is supported for the two_factor role",
        ));
    }
    Ok(EntityOptions {
        role,
        model_name,
        row_presence,
        native_passkey,
        native_two_factor,
    })
}
