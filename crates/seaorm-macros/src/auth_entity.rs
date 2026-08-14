use better_auth_schema_registry::{self as registry, EntityRole};
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;
use syn::{Data, DeriveInput, Fields, LitStr};

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

fn resolve_roots() -> (TokenStream, TokenStream) {
    if let Some(better_auth_root) = found_crate_tokens("better-auth") {
        return (
            quote!(#better_auth_root::seaorm),
            quote!(#better_auth_root::__private_core),
        );
    }

    match crate_name("better-auth-seaorm") {
        Ok(FoundCrate::Itself) => (quote!(crate), quote!(crate::__private_core)),
        _ => (
            syn::Error::new(
                Span::call_site(),
                "AuthEntity must be used through better_auth::seaorm with the `seaorm2` feature enabled",
            )
            .to_compile_error(),
            quote!(::core::compile_error!("unreachable")),
        ),
    }
}

pub(crate) fn derive_auth_entity(input: &DeriveInput) -> TokenStream {
    let (seaorm_root, core_root) = resolve_roots();
    let role = match parse_role(input) {
        Ok(role) => role,
        Err(err) => return err.to_compile_error(),
    };

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
    if let Some(missing) = core
        .iter()
        .find(|required| !idents.iter().any(|ident| ident == *required))
    {
        return syn::Error::new_spanned(
            &input.ident,
            format!("missing required auth field `{missing}` for this role"),
        )
        .to_compile_error();
    }

    let has = |name: &str| idents.iter().any(|i| i == name);

    // Extra fields: not core, not plugin — user-defined.
    let all_known: Vec<&str> = core.iter().chain(plugin.iter()).copied().collect();
    let extra_not_set: Vec<_> = idents
        .iter()
        .filter(|ident| !all_known.iter().any(|known| ident == known))
        .map(|field| {
            quote! { #field: #seaorm_root::sea_orm::ActiveValue::NotSet }
        })
        .collect();

    let ident = &input.ident;

    match role {
        EntityRole::User => gen_user(ident, &has, &extra_not_set, &seaorm_root, &core_root),
        EntityRole::Session => gen_session(ident, &has, &extra_not_set, &seaorm_root, &core_root),
        EntityRole::Account => gen_account(ident, &extra_not_set, &seaorm_root, &core_root),
        EntityRole::Verification => {
            gen_verification(ident, &extra_not_set, &seaorm_root, &core_root)
        }
    }
}

fn gen_user(
    ident: &Ident,
    has: &dyn Fn(&str) -> bool,
    extras: &[TokenStream],
    seaorm_root: &TokenStream,
    core_root: &TokenStream,
) -> TokenStream {
    // AuthUser trait — plugin fields return defaults when absent
    let username_impl = if has("username") {
        quote! { fn username(&self) -> Option<&str> { self.username.as_deref() } }
    } else {
        quote! { fn username(&self) -> Option<&str> { None } }
    };
    let display_username_impl = if has("display_username") {
        quote! { fn display_username(&self) -> Option<&str> { self.display_username.as_deref() } }
    } else {
        quote! { fn display_username(&self) -> Option<&str> { None } }
    };
    let two_factor_impl = if has("two_factor_enabled") {
        quote! { fn two_factor_enabled(&self) -> bool { self.two_factor_enabled } }
    } else {
        quote! { fn two_factor_enabled(&self) -> bool { false } }
    };
    let role_impl = if has("role") {
        quote! { fn role(&self) -> Option<&str> { self.role.as_deref() } }
    } else {
        quote! { fn role(&self) -> Option<&str> { None } }
    };
    let banned_impl = if has("banned") {
        quote! { fn banned(&self) -> bool { self.banned } }
    } else {
        quote! { fn banned(&self) -> bool { false } }
    };
    let ban_reason_impl = if has("ban_reason") {
        quote! { fn ban_reason(&self) -> Option<&str> { self.ban_reason.as_deref() } }
    } else {
        quote! { fn ban_reason(&self) -> Option<&str> { None } }
    };
    let ban_expires_impl = if has("ban_expires") {
        quote! { fn ban_expires(&self) -> Option<::chrono::DateTime<::chrono::Utc>> { self.ban_expires } }
    } else {
        quote! { fn ban_expires(&self) -> Option<::chrono::DateTime<::chrono::Utc>> { None } }
    };
    let metadata_impl = if has("metadata") {
        quote! { fn metadata(&self) -> &::serde_json::Value { &self.metadata } }
    } else {
        quote! { fn metadata(&self) -> &::serde_json::Value {
            static EMPTY: ::std::sync::LazyLock<::serde_json::Value> =
                ::std::sync::LazyLock::new(|| ::serde_json::json!({}));
            &EMPTY
        } }
    };

    // new_active — plugin fields get Set(default) when present, omitted when absent
    let plugin_new_active = plugin_set_fields_user(has, seaorm_root, core_root);

    // apply_update — only update fields that exist
    let plugin_apply_update = plugin_update_fields_user(has, seaorm_root);

    let username_column_impl = if has("username") {
        quote! { fn username_column() -> Option<Self::Column> { Some(Column::Username) } }
    } else {
        // Use trait default (returns None)
        quote! {}
    };

    quote! {
        impl #core_root::entity::AuthUser for #ident {
            fn id(&self) -> ::std::borrow::Cow<'_, str> { ::std::borrow::Cow::Borrowed(&self.id) }
            fn email(&self) -> Option<&str> { self.email.as_deref() }
            fn name(&self) -> Option<&str> { self.name.as_deref() }
            fn email_verified(&self) -> bool { self.email_verified }
            fn image(&self) -> Option<&str> { self.image.as_deref() }
            fn created_at(&self) -> ::chrono::DateTime<::chrono::Utc> { self.created_at }
            fn updated_at(&self) -> ::chrono::DateTime<::chrono::Utc> { self.updated_at }
            #username_impl
            #display_username_impl
            #two_factor_impl
            #role_impl
            #banned_impl
            #ban_reason_impl
            #ban_expires_impl
            #metadata_impl
        }

        impl #seaorm_root::SeaOrmUserModel for #ident {
            type Id = ::std::string::String;
            type Entity = Entity;
            type ActiveModel = ActiveModel;
            type Column = Column;

            fn id_column() -> Self::Column { Column::Id }
            fn email_column() -> Self::Column { Column::Email }
            #username_column_impl
            fn name_column() -> Self::Column { Column::Name }
            fn created_at_column() -> Self::Column { Column::CreatedAt }
            fn parse_id(id: &str) -> #core_root::AuthResult<Self::Id> {
                Ok(id.to_string())
            }

            fn new_active(
                id: ::std::option::Option<Self::Id>,
                create_user: #core_root::types::CreateUser,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) -> Self::ActiveModel {
                Self::ActiveModel {
                    id: #seaorm_root::sea_orm::ActiveValue::Set(
                        id.unwrap_or_else(|| #core_root::uuid::Uuid::new_v4().to_string())
                    ),
                    email: #seaorm_root::sea_orm::ActiveValue::Set(create_user.email),
                    name: #seaorm_root::sea_orm::ActiveValue::Set(create_user.name),
                    image: #seaorm_root::sea_orm::ActiveValue::Set(create_user.image),
                    email_verified: #seaorm_root::sea_orm::ActiveValue::Set(create_user.email_verified.unwrap_or(false)),
                    created_at: #seaorm_root::sea_orm::ActiveValue::Set(now),
                    updated_at: #seaorm_root::sea_orm::ActiveValue::Set(now),
                    #(#plugin_new_active,)*
                    #(#extras,)*
                }
            }

            fn apply_update(
                active: &mut Self::ActiveModel,
                update: #core_root::types::UpdateUser,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) {
                if let ::std::option::Option::Some(email) = update.email {
                    active.email = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(email));
                }
                if let ::std::option::Option::Some(name) = update.name {
                    active.name = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(name));
                }
                if let ::std::option::Option::Some(image) = update.image {
                    active.image = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(image));
                }
                if let ::std::option::Option::Some(email_verified) = update.email_verified {
                    active.email_verified = #seaorm_root::sea_orm::ActiveValue::Set(email_verified);
                }
                #(#plugin_apply_update)*
                active.updated_at = #seaorm_root::sea_orm::ActiveValue::Set(now);
            }
        }
    }
}

/// Generate `new_active` field assignments for present plugin fields on User.
fn plugin_set_fields_user(
    has: &dyn Fn(&str) -> bool,
    seaorm_root: &TokenStream,
    core_root: &TokenStream,
) -> Vec<TokenStream> {
    let mut out = Vec::new();
    if has("username") {
        out.push(
            quote! { username: #seaorm_root::sea_orm::ActiveValue::Set(create_user.username) },
        );
    }
    if has("display_username") {
        out.push(quote! { display_username: #seaorm_root::sea_orm::ActiveValue::Set(create_user.display_username) });
    }
    if has("two_factor_enabled") {
        out.push(quote! { two_factor_enabled: #seaorm_root::sea_orm::ActiveValue::Set(false) });
    }
    if has("role") {
        out.push(quote! { role: #seaorm_root::sea_orm::ActiveValue::Set(create_user.role) });
    }
    if has("banned") {
        out.push(quote! { banned: #seaorm_root::sea_orm::ActiveValue::Set(false) });
    }
    if has("ban_reason") {
        out.push(quote! { ban_reason: #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::None) });
    }
    if has("ban_expires") {
        out.push(quote! { ban_expires: #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::None) });
    }
    if has("metadata") {
        let _ = core_root; // used in the json! path
        out.push(quote! { metadata: #seaorm_root::sea_orm::ActiveValue::Set(create_user.metadata.unwrap_or(::serde_json::json!({}))) });
    }
    out
}

/// Generate `apply_update` statements for present plugin fields on User.
fn plugin_update_fields_user(
    has: &dyn Fn(&str) -> bool,
    seaorm_root: &TokenStream,
) -> Vec<TokenStream> {
    let mut out = Vec::new();
    if has("username") {
        out.push(quote! {
            if let ::std::option::Option::Some(username) = update.username {
                active.username = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(username));
            }
        });
    }
    if has("display_username") {
        out.push(quote! {
            if let ::std::option::Option::Some(display_username) = update.display_username {
                active.display_username = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(display_username));
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
        out.push(quote! {
            if let ::std::option::Option::Some(two_factor_enabled) = update.two_factor_enabled {
                active.two_factor_enabled = #seaorm_root::sea_orm::ActiveValue::Set(two_factor_enabled);
            }
        });
    }
    if has("metadata") {
        out.push(quote! {
            if let ::std::option::Option::Some(metadata) = update.metadata {
                active.metadata = #seaorm_root::sea_orm::ActiveValue::Set(metadata);
            }
        });
    }
    if has("banned") && has("ban_reason") && has("ban_expires") {
        out.push(quote! {
            if let ::std::option::Option::Some(banned) = update.banned {
                active.banned = #seaorm_root::sea_orm::ActiveValue::Set(banned);
                if !banned {
                    active.ban_reason = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::None);
                    active.ban_expires = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::None);
                }
            }
            if update.banned != ::std::option::Option::Some(false) {
                if let ::std::option::Option::Some(ban_reason) = update.ban_reason {
                    active.ban_reason = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(ban_reason));
                }
                if let ::std::option::Option::Some(ban_expires) = update.ban_expires {
                    active.ban_expires = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(ban_expires));
                }
            }
        });
    } else if has("banned") {
        out.push(quote! {
            if let ::std::option::Option::Some(banned) = update.banned {
                active.banned = #seaorm_root::sea_orm::ActiveValue::Set(banned);
            }
        });
    }
    out
}

fn gen_session(
    ident: &Ident,
    has: &dyn Fn(&str) -> bool,
    extras: &[TokenStream],
    seaorm_root: &TokenStream,
    core_root: &TokenStream,
) -> TokenStream {
    let impersonated_by_impl = if has("impersonated_by") {
        quote! { fn impersonated_by(&self) -> Option<&str> { self.impersonated_by.as_deref() } }
    } else {
        quote! { fn impersonated_by(&self) -> Option<&str> { None } }
    };
    let active_org_impl = if has("active_organization_id") {
        quote! { fn active_organization_id(&self) -> Option<&str> { self.active_organization_id.as_deref() } }
    } else {
        quote! { fn active_organization_id(&self) -> Option<&str> { None } }
    };

    let mut plugin_new_active = Vec::new();
    if has("impersonated_by") {
        plugin_new_active.push(quote! { impersonated_by: #seaorm_root::sea_orm::ActiveValue::Set(create_session.impersonated_by) });
    }
    if has("active_organization_id") {
        plugin_new_active.push(quote! { active_organization_id: #seaorm_root::sea_orm::ActiveValue::Set(create_session.active_organization_id) });
    }

    let set_active_org = if has("active_organization_id") {
        quote! {
            fn set_active_organization_id(
                active: &mut Self::ActiveModel,
                organization_id: ::std::option::Option<::std::string::String>,
            ) {
                active.active_organization_id = #seaorm_root::sea_orm::ActiveValue::Set(organization_id);
            }
        }
    } else {
        quote! {
            fn set_active_organization_id(
                _active: &mut Self::ActiveModel,
                _organization_id: ::std::option::Option<::std::string::String>,
            ) {
                // organization plugin not enabled — no-op
            }
        }
    };

    quote! {
        impl #core_root::entity::AuthSession for #ident {
            fn id(&self) -> ::std::borrow::Cow<'_, str> { ::std::borrow::Cow::Borrowed(&self.id) }
            fn expires_at(&self) -> ::chrono::DateTime<::chrono::Utc> { self.expires_at }
            fn token(&self) -> &str { &self.token }
            fn created_at(&self) -> ::chrono::DateTime<::chrono::Utc> { self.created_at }
            fn updated_at(&self) -> ::chrono::DateTime<::chrono::Utc> { self.updated_at }
            fn ip_address(&self) -> Option<&str> { self.ip_address.as_deref() }
            fn user_agent(&self) -> Option<&str> { self.user_agent.as_deref() }
            fn user_id(&self) -> ::std::borrow::Cow<'_, str> { ::std::borrow::Cow::Borrowed(&self.user_id) }
            #impersonated_by_impl
            #active_org_impl
            fn active(&self) -> bool { self.active }
        }

        impl #seaorm_root::SeaOrmSessionModel for #ident {
            type Id = ::std::string::String;
            type UserId = ::std::string::String;
            type Entity = Entity;
            type ActiveModel = ActiveModel;
            type Column = Column;

            fn id_column() -> Self::Column { Column::Id }
            fn token_column() -> Self::Column { Column::Token }
            fn user_id_column() -> Self::Column { Column::UserId }
            fn active_column() -> Self::Column { Column::Active }
            fn expires_at_column() -> Self::Column { Column::ExpiresAt }
            fn created_at_column() -> Self::Column { Column::CreatedAt }
            fn parse_id(id: &str) -> #core_root::AuthResult<Self::Id> {
                Ok(id.to_string())
            }
            fn parse_user_id(user_id: &str) -> #core_root::AuthResult<Self::UserId> {
                Ok(user_id.to_string())
            }

            fn new_active(
                id: ::std::option::Option<Self::Id>,
                token: ::std::string::String,
                create_session: #core_root::types::CreateSession,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) -> Self::ActiveModel {
                Self::ActiveModel {
                    id: #seaorm_root::sea_orm::ActiveValue::Set(
                        id.unwrap_or_else(|| #core_root::uuid::Uuid::new_v4().to_string())
                    ),
                    user_id: #seaorm_root::sea_orm::ActiveValue::Set(create_session.user_id),
                    token: #seaorm_root::sea_orm::ActiveValue::Set(token),
                    expires_at: #seaorm_root::sea_orm::ActiveValue::Set(create_session.expires_at),
                    created_at: #seaorm_root::sea_orm::ActiveValue::Set(now),
                    updated_at: #seaorm_root::sea_orm::ActiveValue::Set(now),
                    ip_address: #seaorm_root::sea_orm::ActiveValue::Set(create_session.ip_address),
                    user_agent: #seaorm_root::sea_orm::ActiveValue::Set(create_session.user_agent),
                    active: #seaorm_root::sea_orm::ActiveValue::Set(true),
                    #(#plugin_new_active,)*
                    #(#extras,)*
                }
            }

            fn set_expires_at(
                active: &mut Self::ActiveModel,
                expires_at: ::chrono::DateTime<::chrono::Utc>,
            ) {
                active.expires_at = #seaorm_root::sea_orm::ActiveValue::Set(expires_at);
            }

            fn set_updated_at(
                active: &mut Self::ActiveModel,
                updated_at: ::chrono::DateTime<::chrono::Utc>,
            ) {
                active.updated_at = #seaorm_root::sea_orm::ActiveValue::Set(updated_at);
            }

            #set_active_org
        }
    }
}

fn gen_account(
    ident: &Ident,
    extras: &[TokenStream],
    seaorm_root: &TokenStream,
    core_root: &TokenStream,
) -> TokenStream {
    // Account has no plugin-optional fields — all are core.
    quote! {
        impl #core_root::entity::AuthAccount for #ident {
            fn id(&self) -> ::std::borrow::Cow<'_, str> { ::std::borrow::Cow::Borrowed(&self.id) }
            fn account_id(&self) -> &str { &self.account_id }
            fn provider_id(&self) -> &str { &self.provider_id }
            fn user_id(&self) -> ::std::borrow::Cow<'_, str> { ::std::borrow::Cow::Borrowed(&self.user_id) }
            fn access_token(&self) -> Option<&str> { self.access_token.as_deref() }
            fn refresh_token(&self) -> Option<&str> { self.refresh_token.as_deref() }
            fn id_token(&self) -> Option<&str> { self.id_token.as_deref() }
            fn access_token_expires_at(&self) -> Option<::chrono::DateTime<::chrono::Utc>> { self.access_token_expires_at }
            fn refresh_token_expires_at(&self) -> Option<::chrono::DateTime<::chrono::Utc>> { self.refresh_token_expires_at }
            fn scope(&self) -> Option<&str> { self.scope.as_deref() }
            fn password(&self) -> Option<&str> { self.password.as_deref() }
            fn created_at(&self) -> ::chrono::DateTime<::chrono::Utc> { self.created_at }
            fn updated_at(&self) -> ::chrono::DateTime<::chrono::Utc> { self.updated_at }
        }

        impl #seaorm_root::SeaOrmAccountModel for #ident {
            type Id = ::std::string::String;
            type UserId = ::std::string::String;
            type Entity = Entity;
            type ActiveModel = ActiveModel;
            type Column = Column;

            fn id_column() -> Self::Column { Column::Id }
            fn provider_id_column() -> Self::Column { Column::ProviderId }
            fn account_id_column() -> Self::Column { Column::AccountId }
            fn user_id_column() -> Self::Column { Column::UserId }
            fn created_at_column() -> Self::Column { Column::CreatedAt }
            fn parse_id(id: &str) -> #core_root::AuthResult<Self::Id> {
                Ok(id.to_string())
            }
            fn parse_user_id(user_id: &str) -> #core_root::AuthResult<Self::UserId> {
                Ok(user_id.to_string())
            }

            fn new_active(
                id: ::std::option::Option<Self::Id>,
                create_account: #core_root::types::CreateAccount,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) -> Self::ActiveModel {
                Self::ActiveModel {
                    id: #seaorm_root::sea_orm::ActiveValue::Set(
                        id.unwrap_or_else(|| #core_root::uuid::Uuid::new_v4().to_string())
                    ),
                    account_id: #seaorm_root::sea_orm::ActiveValue::Set(create_account.account_id),
                    provider_id: #seaorm_root::sea_orm::ActiveValue::Set(create_account.provider_id),
                    user_id: #seaorm_root::sea_orm::ActiveValue::Set(create_account.user_id),
                    access_token: #seaorm_root::sea_orm::ActiveValue::Set(create_account.access_token),
                    refresh_token: #seaorm_root::sea_orm::ActiveValue::Set(create_account.refresh_token),
                    id_token: #seaorm_root::sea_orm::ActiveValue::Set(create_account.id_token),
                    access_token_expires_at: #seaorm_root::sea_orm::ActiveValue::Set(create_account.access_token_expires_at),
                    refresh_token_expires_at: #seaorm_root::sea_orm::ActiveValue::Set(create_account.refresh_token_expires_at),
                    scope: #seaorm_root::sea_orm::ActiveValue::Set(create_account.scope),
                    password: #seaorm_root::sea_orm::ActiveValue::Set(create_account.password),
                    created_at: #seaorm_root::sea_orm::ActiveValue::Set(now),
                    updated_at: #seaorm_root::sea_orm::ActiveValue::Set(now),
                    #(#extras,)*
                }
            }

            fn apply_update(
                active: &mut Self::ActiveModel,
                update: #core_root::types::UpdateAccount,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) {
                if let ::std::option::Option::Some(access_token) = update.access_token {
                    active.access_token = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(access_token));
                }
                if let ::std::option::Option::Some(refresh_token) = update.refresh_token {
                    active.refresh_token = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(refresh_token));
                }
                if let ::std::option::Option::Some(id_token) = update.id_token {
                    active.id_token = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(id_token));
                }
                if let ::std::option::Option::Some(access_token_expires_at) = update.access_token_expires_at {
                    active.access_token_expires_at = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(access_token_expires_at));
                }
                if let ::std::option::Option::Some(refresh_token_expires_at) = update.refresh_token_expires_at {
                    active.refresh_token_expires_at = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(refresh_token_expires_at));
                }
                if let ::std::option::Option::Some(scope) = update.scope {
                    active.scope = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(scope));
                }
                if let ::std::option::Option::Some(password) = update.password {
                    active.password = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(password));
                }
                active.updated_at = #seaorm_root::sea_orm::ActiveValue::Set(now);
            }
        }
    }
}

fn gen_verification(
    ident: &Ident,
    extras: &[TokenStream],
    seaorm_root: &TokenStream,
    core_root: &TokenStream,
) -> TokenStream {
    // Verification has no plugin-optional fields.
    quote! {
        impl #core_root::entity::AuthVerification for #ident {
            fn id(&self) -> ::std::borrow::Cow<'_, str> { ::std::borrow::Cow::Borrowed(&self.id) }
            fn identifier(&self) -> &str { &self.identifier }
            fn value(&self) -> &str { &self.value }
            fn expires_at(&self) -> ::chrono::DateTime<::chrono::Utc> { self.expires_at }
            fn created_at(&self) -> ::chrono::DateTime<::chrono::Utc> { self.created_at }
            fn updated_at(&self) -> ::chrono::DateTime<::chrono::Utc> { self.updated_at }
        }

        impl #seaorm_root::SeaOrmVerificationModel for #ident {
            type Id = ::std::string::String;
            type Entity = Entity;
            type ActiveModel = ActiveModel;
            type Column = Column;

            fn id_column() -> Self::Column { Column::Id }
            fn identifier_column() -> Self::Column { Column::Identifier }
            fn value_column() -> Self::Column { Column::Value }
            fn expires_at_column() -> Self::Column { Column::ExpiresAt }
            fn created_at_column() -> Self::Column { Column::CreatedAt }
            fn parse_id(id: &str) -> #core_root::AuthResult<Self::Id> {
                Ok(id.to_string())
            }

            fn new_active(
                id: ::std::option::Option<Self::Id>,
                verification: #core_root::types::CreateVerification,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) -> Self::ActiveModel {
                Self::ActiveModel {
                    id: #seaorm_root::sea_orm::ActiveValue::Set(
                        id.unwrap_or_else(|| #core_root::uuid::Uuid::new_v4().to_string())
                    ),
                    identifier: #seaorm_root::sea_orm::ActiveValue::Set(verification.identifier),
                    value: #seaorm_root::sea_orm::ActiveValue::Set(verification.value),
                    expires_at: #seaorm_root::sea_orm::ActiveValue::Set(verification.expires_at),
                    created_at: #seaorm_root::sea_orm::ActiveValue::Set(now),
                    updated_at: #seaorm_root::sea_orm::ActiveValue::Set(now),
                    #(#extras,)*
                }
            }
        }
    }
}

fn parse_role(input: &DeriveInput) -> Result<EntityRole, syn::Error> {
    let mut parsed = None;
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
                    _ => {
                        return Err(syn::Error::new_spanned(
                            role,
                            "unsupported auth role; expected user, session, account, or verification",
                        ));
                    }
                });
                Ok(())
            } else {
                Err(meta.error("expected `role = \"...\"`"))
            }
        })?;
    }

    parsed.ok_or_else(|| {
        syn::Error::new_spanned(
            input,
            "missing #[auth(role = \"...\")] attribute for AuthEntity",
        )
    })
}
