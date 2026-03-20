use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;
use syn::{Data, DeriveInput, Fields, LitStr};

#[derive(Clone, Copy)]
enum Role {
    User,
    Session,
    Account,
    Verification,
}

fn found_crate_tokens(name: &str) -> Option<TokenStream> {
    match crate_name(name).ok()? {
        FoundCrate::Itself => Some(quote!(crate)),
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

    let seaorm_root = found_crate_tokens("better-auth-seaorm").unwrap_or_else(|| {
        syn::Error::new(
            Span::call_site(),
            "could not resolve better-auth or better-auth-seaorm",
        )
        .to_compile_error()
    });
    let core_root = quote!(#seaorm_root::__private_core);
    (seaorm_root, core_root)
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
    let role_fields = required_fields(role);
    if let Some(missing) = role_fields
        .iter()
        .find(|required| !idents.iter().any(|ident| ident == *required))
    {
        return syn::Error::new_spanned(
            &input.ident,
            format!("missing required auth field `{missing}` for this role"),
        )
        .to_compile_error();
    }

    let ident = &input.ident;
    match role {
        Role::User => quote! {
            impl #core_root::entity::AuthUser for #ident {
                fn id(&self) -> ::std::borrow::Cow<'_, str> { ::std::borrow::Cow::Borrowed(&self.id) }
                fn email(&self) -> Option<&str> { self.email.as_deref() }
                fn name(&self) -> Option<&str> { self.name.as_deref() }
                fn email_verified(&self) -> bool { self.email_verified }
                fn image(&self) -> Option<&str> { self.image.as_deref() }
                fn created_at(&self) -> ::chrono::DateTime<::chrono::Utc> { self.created_at }
                fn updated_at(&self) -> ::chrono::DateTime<::chrono::Utc> { self.updated_at }
                fn username(&self) -> Option<&str> { self.username.as_deref() }
                fn display_username(&self) -> Option<&str> { self.display_username.as_deref() }
                fn two_factor_enabled(&self) -> bool { self.two_factor_enabled }
                fn role(&self) -> Option<&str> { self.role.as_deref() }
                fn banned(&self) -> bool { self.banned }
                fn ban_reason(&self) -> Option<&str> { self.ban_reason.as_deref() }
                fn ban_expires(&self) -> Option<::chrono::DateTime<::chrono::Utc>> { self.ban_expires }
                fn metadata(&self) -> &::serde_json::Value { &self.metadata }
            }

            impl #seaorm_root::SeaOrmUserModel for #ident {
                type Id = ::std::string::String;
                type Entity = Entity;
                type ActiveModel = ActiveModel;
                type Column = Column;

                fn id_column() -> Self::Column { Column::Id }
                fn email_column() -> Self::Column { Column::Email }
                fn username_column() -> Self::Column { Column::Username }
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
                        username: #seaorm_root::sea_orm::ActiveValue::Set(create_user.username),
                        display_username: #seaorm_root::sea_orm::ActiveValue::Set(create_user.display_username),
                        two_factor_enabled: #seaorm_root::sea_orm::ActiveValue::Set(false),
                        role: #seaorm_root::sea_orm::ActiveValue::Set(create_user.role),
                        banned: #seaorm_root::sea_orm::ActiveValue::Set(false),
                        ban_reason: #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::None),
                        ban_expires: #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::None),
                        metadata: #seaorm_root::sea_orm::ActiveValue::Set(create_user.metadata.unwrap_or(::serde_json::json!({}))),
                        created_at: #seaorm_root::sea_orm::ActiveValue::Set(now),
                        updated_at: #seaorm_root::sea_orm::ActiveValue::Set(now),
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
                    if let ::std::option::Option::Some(username) = update.username {
                        active.username = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(username));
                    }
                    if let ::std::option::Option::Some(display_username) = update.display_username {
                        active.display_username = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(display_username));
                    }
                    if let ::std::option::Option::Some(role) = update.role {
                        active.role = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(role));
                    }
                    if let ::std::option::Option::Some(two_factor_enabled) = update.two_factor_enabled {
                        active.two_factor_enabled = #seaorm_root::sea_orm::ActiveValue::Set(two_factor_enabled);
                    }
                    if let ::std::option::Option::Some(metadata) = update.metadata {
                        active.metadata = #seaorm_root::sea_orm::ActiveValue::Set(metadata);
                    }
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
                    active.updated_at = #seaorm_root::sea_orm::ActiveValue::Set(now);
                }
            }
        },
        Role::Session => quote! {
            impl #core_root::entity::AuthSession for #ident {
                fn id(&self) -> ::std::borrow::Cow<'_, str> { ::std::borrow::Cow::Borrowed(&self.id) }
                fn expires_at(&self) -> ::chrono::DateTime<::chrono::Utc> { self.expires_at }
                fn token(&self) -> &str { &self.token }
                fn created_at(&self) -> ::chrono::DateTime<::chrono::Utc> { self.created_at }
                fn updated_at(&self) -> ::chrono::DateTime<::chrono::Utc> { self.updated_at }
                fn ip_address(&self) -> Option<&str> { self.ip_address.as_deref() }
                fn user_agent(&self) -> Option<&str> { self.user_agent.as_deref() }
                fn user_id(&self) -> ::std::borrow::Cow<'_, str> { ::std::borrow::Cow::Borrowed(&self.user_id) }
                fn impersonated_by(&self) -> Option<&str> { self.impersonated_by.as_deref() }
                fn active_organization_id(&self) -> Option<&str> { self.active_organization_id.as_deref() }
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
                        impersonated_by: #seaorm_root::sea_orm::ActiveValue::Set(create_session.impersonated_by),
                        active_organization_id: #seaorm_root::sea_orm::ActiveValue::Set(create_session.active_organization_id),
                        active: #seaorm_root::sea_orm::ActiveValue::Set(true),
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

                fn set_active_organization_id(
                    active: &mut Self::ActiveModel,
                    organization_id: ::std::option::Option<::std::string::String>,
                ) {
                    active.active_organization_id = #seaorm_root::sea_orm::ActiveValue::Set(organization_id);
                }
            }
        },
        Role::Account => quote! {
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
        },
        Role::Verification => quote! {
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
                    }
                }
            }
        },
    }
}

fn parse_role(input: &DeriveInput) -> Result<Role, syn::Error> {
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
                    "user" => Role::User,
                    "session" => Role::Session,
                    "account" => Role::Account,
                    "verification" => Role::Verification,
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

fn required_fields(role: Role) -> &'static [&'static str] {
    match role {
        Role::User => &[
            "id",
            "name",
            "email",
            "email_verified",
            "image",
            "username",
            "display_username",
            "two_factor_enabled",
            "role",
            "banned",
            "ban_reason",
            "ban_expires",
            "metadata",
            "created_at",
            "updated_at",
        ],
        Role::Session => &[
            "id",
            "expires_at",
            "token",
            "created_at",
            "updated_at",
            "ip_address",
            "user_agent",
            "user_id",
            "impersonated_by",
            "active_organization_id",
            "active",
        ],
        Role::Account => &[
            "id",
            "account_id",
            "provider_id",
            "user_id",
            "access_token",
            "refresh_token",
            "id_token",
            "access_token_expires_at",
            "refresh_token_expires_at",
            "scope",
            "password",
            "created_at",
            "updated_at",
        ],
        Role::Verification => &[
            "id",
            "identifier",
            "value",
            "expires_at",
            "created_at",
            "updated_at",
        ],
    }
}
