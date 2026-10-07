use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use better_auth::plugins::{
    AccountManagementPlugin, EmailPasswordPlugin, PasswordManagementPlugin, SessionManagementPlugin,
};
use better_auth::prelude::{
    AuthAccount, AuthRequest, AuthResponse, AuthSession, AuthUser, AuthVerification, CreateSession,
    CreateUser, HttpMethod, UpdateUser,
};
use better_auth::seaorm::sea_orm;
use better_auth::seaorm::sea_orm::entity::prelude::*;
use better_auth::seaorm::sea_orm::{
    ActiveValue::NotSet, ActiveValue::Set, ConnectionTrait, Iden, Iterable, ModelTrait, Schema,
};
use better_auth::seaorm::{
    Database, DatabaseConnection, SeaOrmAccountModel, SeaOrmSessionModel, SeaOrmStore,
    SeaOrmUserModel, SeaOrmVerificationModel,
};
use better_auth::{
    Argon2PasswordHasher, AuthConfig, AuthError, AuthRecordFields, AuthResult, AuthSchema,
    BetterAuth, FieldDate, FieldMap, FieldValue,
};
use chrono::{DateTime, Utc};
use rand::rngs::OsRng;
use serde_json::json;

fn model_fields<M: ModelTrait>(model: &M) -> AuthResult<FieldMap> {
    <M::Entity as EntityTrait>::Column::iter()
        .map(|column| {
            Ok((
                column.to_string(),
                better_auth::seaorm::field_value::from_column(model.get(column))?,
            ))
        })
        .collect()
}

fn stored_date(date: FieldDate) -> AuthResult<DateTime<Utc>> {
    date.to_datetime()?
        .ok_or_else(|| AuthError::internal("The typed model requires a valid Date"))
}

mod user {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "users")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub name: Option<String>,
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        pub username: Option<String>,
        pub display_username: Option<String>,
        pub two_factor_enabled: bool,
        pub role: Option<String>,
        pub banned: bool,
        pub ban_reason: Option<String>,
        pub ban_expires: Option<DateTimeUtc>,
        pub metadata: Json,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        pub tenant_id: i64,
        pub locale: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}

    impl AuthRecordFields for Model {
        fn field_values(&self) -> AuthResult<FieldMap> {
            model_fields(self)
        }
    }

    impl AuthUser for Model {
        const PLUGIN_FIELDS: &'static [&'static str] = &[
            "username",
            "display_username",
            "two_factor_enabled",
            "role",
            "banned",
            "ban_reason",
            "ban_expires",
            "metadata",
        ];
        fn id(&self) -> better_auth_core::SchemaValue<Cow<'_, str>> {
            better_auth_core::SchemaValue::Typed(Cow::Owned(self.id.to_string()))
        }

        fn email(&self) -> Option<&str> {
            self.email.as_deref()
        }

        fn email_verified(&self) -> bool {
            self.email_verified
        }

        fn created_at(&self) -> FieldDate {
            self.created_at.into()
        }

        fn updated_at(&self) -> FieldDate {
            self.updated_at.into()
        }

        fn username(&self) -> Option<&str> {
            self.username.as_deref()
        }

        fn display_username(&self) -> Option<&str> {
            self.display_username.as_deref()
        }

        fn two_factor_enabled(&self) -> bool {
            self.two_factor_enabled
        }

        fn role(&self) -> Option<&str> {
            self.role.as_deref()
        }

        fn banned(&self) -> bool {
            self.banned
        }

        fn ban_reason(&self) -> Option<&str> {
            self.ban_reason.as_deref()
        }

        fn ban_expires(&self) -> Option<FieldDate> {
            self.ban_expires.map(Into::into)
        }
    }

    impl SeaOrmUserModel for Model {
        fn field_column(name: &str) -> AuthResult<Column> {
            match name {
                "id" => Ok(Column::Id),
                "name" => Ok(Column::Name),
                "email" => Ok(Column::Email),
                "email_verified" | "emailVerified" => Ok(Column::EmailVerified),
                "image" => Ok(Column::Image),
                "username" => Ok(Column::Username),
                "display_username" | "displayUsername" => Ok(Column::DisplayUsername),
                "two_factor_enabled" | "twoFactorEnabled" => Ok(Column::TwoFactorEnabled),
                "role" => Ok(Column::Role),
                "banned" => Ok(Column::Banned),
                "ban_reason" | "banReason" => Ok(Column::BanReason),
                "ban_expires" | "banExpires" => Ok(Column::BanExpires),
                "metadata" => Ok(Column::Metadata),
                "created_at" | "createdAt" => Ok(Column::CreatedAt),
                "updated_at" | "updatedAt" => Ok(Column::UpdatedAt),
                "tenant_id" | "tenantId" => Ok(Column::TenantId),
                "locale" => Ok(Column::Locale),
                _ => Err(AuthError::config(format!("Unknown model field: {name}"))),
            }
        }

        fn extra_insert_columns() -> Vec<Column> {
            vec![Column::TenantId, Column::Locale]
        }

        type Id = i32;
        type Entity = Entity;
        type ActiveModel = ActiveModel;
        type Column = Column;

        fn id_column() -> Self::Column {
            Column::Id
        }

        fn email_column() -> Self::Column {
            Column::Email
        }

        fn username_column() -> Option<Self::Column> {
            Some(Column::Username)
        }

        fn name_column() -> Self::Column {
            Column::Name
        }

        fn created_at_column() -> Self::Column {
            Column::CreatedAt
        }

        fn parse_id(id: &str) -> AuthResult<Self::Id> {
            id.parse()
                .map_err(|_| AuthError::bad_request("Invalid user id"))
        }

        fn new_active(
            id: Option<Self::Id>,
            create_user: CreateUser,
            now: DateTime<Utc>,
        ) -> AuthResult<Self::ActiveModel> {
            Ok(ActiveModel {
                id: id.map_or(NotSet, Set),
                name: match create_user.name.into_field_value() {
                    FieldValue::Undefined => NotSet,
                    value => Set(value.decode()?),
                },
                email: Set(create_user.email),
                email_verified: Set(create_user.email_verified.unwrap_or(false)),
                image: match create_user.image.into_field_value() {
                    FieldValue::Undefined => NotSet,
                    value => Set(value.decode()?),
                },
                username: Set(create_user.username.flatten()),
                display_username: Set(create_user.display_username.flatten()),
                two_factor_enabled: Set(false),
                role: Set(create_user.role),
                banned: Set(create_user.banned.unwrap_or(false)),
                ban_reason: Set(create_user.ban_reason),
                ban_expires: Set(create_user.ban_expires.map(stored_date).transpose()?),
                metadata: Set(better_auth::seaorm::field_value::decode_column(
                    create_user
                        .metadata
                        .unwrap_or_else(|| FieldValue::from(FieldMap::new())),
                )?),
                created_at: Set(now),
                updated_at: Set(now),
                tenant_id: Set(1),
                locale: Set("en".to_string()),
            })
        }

        fn apply_update(
            active: &mut Self::ActiveModel,
            update: UpdateUser,
            now: DateTime<Utc>,
        ) -> AuthResult<()> {
            let value = update.name.into_field_value();
            if !value.is_undefined() {
                active.name = Set(value.decode()?);
            }
            let value = update.image.into_field_value();
            if !value.is_undefined() {
                active.image = Set(value.decode()?);
            }
            if let Some(email) = update.email {
                active.email = Set(Some(email));
            }
            if let Some(email_verified) = update.email_verified {
                active.email_verified = Set(email_verified);
            }
            if let Some(username) = update.username {
                active.username = Set(username);
            }
            if let Some(display_username) = update.display_username {
                active.display_username = Set(display_username);
            }
            if let Some(role) = update.role {
                active.role = Set(Some(role));
            }
            if let Some(two_factor_enabled) = update.two_factor_enabled {
                active.two_factor_enabled = Set(two_factor_enabled);
            }
            if let Some(metadata) = update.metadata {
                active.metadata = Set(better_auth::seaorm::field_value::decode_column(metadata)?);
            }
            if let Some(banned) = update.banned {
                active.banned = Set(banned);
            }
            if let Some(ban_reason) = update.ban_reason {
                active.ban_reason = Set(ban_reason);
            }
            if let Some(ban_expires) = update.ban_expires {
                active.ban_expires = Set(ban_expires.map(stored_date).transpose()?);
            }
            active.updated_at = Set(now);
            Ok(())
        }
    }
}

mod session {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "sessions")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub expires_at: DateTimeUtc,
        pub token: String,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        pub ip_address: Option<String>,
        pub user_agent: Option<String>,
        pub user_id: i32,
        pub impersonated_by: Option<String>,
        pub active_organization_id: Option<String>,
        pub active: bool,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}

    impl AuthRecordFields for Model {
        fn field_values(&self) -> AuthResult<FieldMap> {
            model_fields(self)
        }
    }

    impl AuthSession for Model {
        const PLUGIN_FIELDS: &'static [&'static str] =
            &["impersonated_by", "active_organization_id"];
        fn id(&self) -> better_auth_core::SchemaValue<Cow<'_, str>> {
            better_auth_core::SchemaValue::Typed(Cow::Owned(self.id.to_string()))
        }

        fn expires_at(&self) -> FieldDate {
            self.expires_at.into()
        }

        fn token(&self) -> &str {
            &self.token
        }

        fn created_at(&self) -> FieldDate {
            self.created_at.into()
        }

        fn updated_at(&self) -> FieldDate {
            self.updated_at.into()
        }

        fn ip_address(&self) -> Option<&str> {
            self.ip_address.as_deref()
        }

        fn user_agent(&self) -> Option<&str> {
            self.user_agent.as_deref()
        }

        fn user_id(&self) -> better_auth_core::SchemaValue<Cow<'_, str>> {
            better_auth_core::SchemaValue::Typed(Cow::Owned(self.user_id.to_string()))
        }

        fn impersonated_by(&self) -> Option<&str> {
            self.impersonated_by.as_deref()
        }

        fn active_organization_id(&self) -> Option<&str> {
            self.active_organization_id.as_deref()
        }

        fn active(&self) -> bool {
            self.active
        }
    }

    impl SeaOrmSessionModel for Model {
        fn field_column(name: &str) -> AuthResult<Column> {
            match name {
                "id" => Ok(Column::Id),
                "expires_at" | "expiresAt" => Ok(Column::ExpiresAt),
                "token" => Ok(Column::Token),
                "created_at" | "createdAt" => Ok(Column::CreatedAt),
                "updated_at" | "updatedAt" => Ok(Column::UpdatedAt),
                "ip_address" | "ipAddress" => Ok(Column::IpAddress),
                "user_agent" | "userAgent" => Ok(Column::UserAgent),
                "user_id" | "userId" => Ok(Column::UserId),
                "impersonated_by" | "impersonatedBy" => Ok(Column::ImpersonatedBy),
                "active_organization_id" | "activeOrganizationId" => {
                    Ok(Column::ActiveOrganizationId)
                }
                "active" => Ok(Column::Active),
                _ => Err(AuthError::config(format!("Unknown model field: {name}"))),
            }
        }

        fn apply_update(
            active: &mut Self::ActiveModel,
            update: better_auth::seaorm::SessionUpdate,
        ) -> AuthResult<()> {
            if let Some(id) = update.id {
                active.id = Set(Self::parse_id(&id)?);
            }
            if let Some(id) = update.user_id {
                active.user_id = Set(Self::parse_user_id(&id)?);
            }
            if let Some(value) = update.token {
                active.token = Set(value);
            }
            if let Some(value) = update.expires_at {
                active.expires_at = Set(stored_date(value)?);
            }
            if let Some(value) = update.created_at {
                active.created_at = Set(stored_date(value)?);
            }
            if let Some(value) = update.updated_at {
                active.updated_at = Set(stored_date(value)?);
            }
            if let Some(value) = update.ip_address {
                active.ip_address = Set(value);
            }
            if let Some(value) = update.user_agent {
                active.user_agent = Set(value);
            }
            if let Some(value) = update.impersonated_by {
                active.impersonated_by = Set(value);
            }
            if let Some(value) = update.active_organization_id {
                active.active_organization_id = Set(value);
            }
            Ok(())
        }

        type Id = i32;
        type UserId = i32;
        type Entity = Entity;
        type ActiveModel = ActiveModel;
        type Column = Column;

        fn id_column() -> Self::Column {
            Column::Id
        }

        fn token_column() -> Self::Column {
            Column::Token
        }

        fn user_id_column() -> Self::Column {
            Column::UserId
        }

        fn active_column() -> Option<Self::Column> {
            Some(Column::Active)
        }

        fn expires_at_column() -> Self::Column {
            Column::ExpiresAt
        }

        fn created_at_column() -> Self::Column {
            Column::CreatedAt
        }

        fn parse_id(id: &str) -> AuthResult<Self::Id> {
            id.parse()
                .map_err(|_| AuthError::bad_request("Invalid session id"))
        }

        fn parse_user_id(user_id: &str) -> AuthResult<Self::UserId> {
            user_id
                .parse()
                .map_err(|_| AuthError::bad_request("Invalid session user id"))
        }

        fn new_active(
            id: Option<Self::Id>,
            token: String,
            create_session: CreateSession,
            now: DateTime<Utc>,
        ) -> AuthResult<Self::ActiveModel> {
            let user_id = create_session.user_id.as_str().map(|id| {
                id.parse()
                    .expect("session user ids come from validated auth user identifiers")
            });
            Ok(ActiveModel {
                id: id.map_or(NotSet, Set),
                expires_at: NotSet,
                token: Set(token),
                created_at: Set(now),
                updated_at: Set(now),
                ip_address: Set(create_session.ip_address),
                user_agent: Set(create_session.user_agent),
                user_id: user_id.map_or(NotSet, Set),
                impersonated_by: Set(create_session.impersonated_by),
                active_organization_id: Set(create_session.active_organization_id),
                active: Set(true),
            })
        }

        fn set_expires_at(active: &mut Self::ActiveModel, expires_at: DateTime<Utc>) {
            active.expires_at = Set(expires_at);
        }

        fn set_updated_at(active: &mut Self::ActiveModel, updated_at: DateTime<Utc>) {
            active.updated_at = Set(updated_at);
        }

        fn set_active_organization_id(
            active: &mut Self::ActiveModel,
            organization_id: Option<String>,
        ) {
            active.active_organization_id = Set(organization_id);
        }
    }
}

mod account {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "accounts")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub account_id: String,
        pub provider_id: String,
        pub user_id: i32,
        pub access_token: Option<String>,
        pub refresh_token: Option<String>,
        pub id_token: Option<String>,
        pub access_token_expires_at: Option<DateTimeUtc>,
        pub refresh_token_expires_at: Option<DateTimeUtc>,
        pub scope: Option<String>,
        pub password: Option<String>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}

    impl AuthRecordFields for Model {
        fn field_values(&self) -> AuthResult<FieldMap> {
            model_fields(self)
        }
    }

    impl AuthAccount for Model {
        fn id(&self) -> Cow<'_, str> {
            Cow::Owned(self.id.to_string())
        }

        fn account_id(&self) -> &str {
            &self.account_id
        }

        fn provider_id(&self) -> &str {
            &self.provider_id
        }

        fn user_id(&self) -> Cow<'_, str> {
            Cow::Owned(self.user_id.to_string())
        }

        fn access_token(&self) -> Option<&str> {
            self.access_token.as_deref()
        }

        fn refresh_token(&self) -> Option<&str> {
            self.refresh_token.as_deref()
        }

        fn id_token(&self) -> Option<&str> {
            self.id_token.as_deref()
        }

        fn access_token_expires_at(&self) -> Option<FieldDate> {
            self.access_token_expires_at.map(Into::into)
        }

        fn refresh_token_expires_at(&self) -> Option<FieldDate> {
            self.refresh_token_expires_at.map(Into::into)
        }

        fn scope(&self) -> Option<&str> {
            self.scope.as_deref()
        }

        fn password(&self) -> Option<&str> {
            self.password.as_deref()
        }

        fn created_at(&self) -> FieldDate {
            self.created_at.into()
        }

        fn updated_at(&self) -> FieldDate {
            self.updated_at.into()
        }
    }

    impl SeaOrmAccountModel for Model {
        type Id = i32;
        type Entity = Entity;
        type ActiveModel = ActiveModel;
        type Column = Column;
        type UserId = i32;
        fn id_column() -> Self::Column {
            Column::Id
        }
        fn provider_id_column() -> Self::Column {
            Column::ProviderId
        }
        fn account_id_column() -> Self::Column {
            Column::AccountId
        }
        fn user_id_column() -> Self::Column {
            Column::UserId
        }
        fn created_at_column() -> Self::Column {
            Column::CreatedAt
        }
        fn parse_id(id: &str) -> AuthResult<Self::Id> {
            id.parse()
                .map_err(|_| AuthError::bad_request("Invalid account id"))
        }
        fn parse_user_id(id: &str) -> AuthResult<Self::UserId> {
            id.parse()
                .map_err(|_| AuthError::bad_request("Invalid account user id"))
        }
        fn field_column(name: &str) -> AuthResult<Column> {
            match name {
                "id" => Ok(Column::Id),
                "account_id" | "accountId" => Ok(Column::AccountId),
                "provider_id" | "providerId" => Ok(Column::ProviderId),
                "user_id" | "userId" => Ok(Column::UserId),
                "access_token" | "accessToken" => Ok(Column::AccessToken),
                "refresh_token" | "refreshToken" => Ok(Column::RefreshToken),
                "id_token" | "idToken" => Ok(Column::IdToken),
                "access_token_expires_at" | "accessTokenExpiresAt" => {
                    Ok(Column::AccessTokenExpiresAt)
                }
                "refresh_token_expires_at" | "refreshTokenExpiresAt" => {
                    Ok(Column::RefreshTokenExpiresAt)
                }
                "scope" => Ok(Column::Scope),
                "password" => Ok(Column::Password),
                "created_at" | "createdAt" => Ok(Column::CreatedAt),
                "updated_at" | "updatedAt" => Ok(Column::UpdatedAt),
                _ => Err(AuthError::config(format!(
                    "Unknown application field: {name}"
                ))),
            }
        }
        fn native_json_field(_name: &str) -> bool {
            false
        }
        fn new_active(id: Option<Self::Id>, _fields: &FieldMap) -> AuthResult<Self::ActiveModel> {
            Ok(ActiveModel {
                id: id.map_or(NotSet, Set),
                ..Default::default()
            })
        }
        fn apply_fields(active: &mut Self::ActiveModel, fields: FieldMap) -> AuthResult<()> {
            for (name, value) in fields {
                match Self::field_column(&name)? {
                    Column::Id => {
                        active.id = Set(Self::parse_id(
                            &better_auth::SchemaValue::<String>::from_field(value)
                                .display_string()?,
                        )?)
                    }
                    Column::AccountId => active.account_id = Set(value.decode()?),
                    Column::ProviderId => active.provider_id = Set(value.decode()?),
                    Column::UserId => {
                        active.user_id = Set(Self::parse_user_id(
                            &better_auth::SchemaValue::<String>::from_field(value)
                                .display_string()?,
                        )?)
                    }
                    Column::AccessToken => active.access_token = Set(value.decode()?),
                    Column::RefreshToken => active.refresh_token = Set(value.decode()?),
                    Column::IdToken => active.id_token = Set(value.decode()?),
                    Column::AccessTokenExpiresAt => {
                        active.access_token_expires_at = Set(value
                            .decode::<Option<FieldDate>>()?
                            .map(stored_date)
                            .transpose()?)
                    }
                    Column::RefreshTokenExpiresAt => {
                        active.refresh_token_expires_at = Set(value
                            .decode::<Option<FieldDate>>()?
                            .map(stored_date)
                            .transpose()?)
                    }
                    Column::Scope => active.scope = Set(value.decode()?),
                    Column::Password => active.password = Set(value.decode()?),
                    Column::CreatedAt => active.created_at = Set(stored_date(value.decode()?)?),
                    Column::UpdatedAt => active.updated_at = Set(stored_date(value.decode()?)?),
                }
            }
            Ok(())
        }
        fn record_fields(
            &self,
            fields: &better_auth::config::UserConfig,
        ) -> AuthResult<better_auth_core::user_fields::AdapterRecord> {
            let mut storage = FieldMap::new();
            for (logical, field) in fields.fields() {
                if logical == "id" {
                    continue;
                }
                let key = field.field_name.as_deref().unwrap_or(logical);
                let value = better_auth::seaorm::field_value::from_column(
                    self.get(Self::field_column(key)?),
                )?;
                let _ = storage.insert(key.to_owned(), value);
            }
            let core = FieldMap::from([("id".into(), FieldValue::String(self.id.to_string()))]);
            Ok(better_auth_core::user_fields::AdapterRecord::new(
                core, storage,
            ))
        }
    }
}

mod verification {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "verifications")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub identifier: String,
        pub value: String,
        pub expires_at: DateTimeUtc,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}

    impl AuthRecordFields for Model {
        fn field_values(&self) -> AuthResult<FieldMap> {
            model_fields(self)
        }
    }

    impl AuthVerification for Model {
        fn id(&self) -> Cow<'_, str> {
            Cow::Owned(self.id.to_string())
        }

        fn identifier(&self) -> &str {
            &self.identifier
        }

        fn value(&self) -> &str {
            &self.value
        }

        fn expires_at(&self) -> FieldDate {
            self.expires_at.into()
        }

        fn created_at(&self) -> FieldDate {
            self.created_at.into()
        }

        fn updated_at(&self) -> FieldDate {
            self.updated_at.into()
        }
    }

    impl SeaOrmVerificationModel for Model {
        type Id = i32;
        type Entity = Entity;
        type ActiveModel = ActiveModel;
        type Column = Column;
        fn id_column() -> Self::Column {
            Column::Id
        }
        fn identifier_column() -> Self::Column {
            Column::Identifier
        }
        fn value_column() -> Self::Column {
            Column::Value
        }
        fn expires_at_column() -> Self::Column {
            Column::ExpiresAt
        }
        fn created_at_column() -> Self::Column {
            Column::CreatedAt
        }
        fn parse_id(id: &str) -> AuthResult<Self::Id> {
            id.parse()
                .map_err(|_| AuthError::bad_request("Invalid verification id"))
        }
        fn field_column(name: &str) -> AuthResult<Column> {
            match name {
                "id" => Ok(Column::Id),
                "identifier" => Ok(Column::Identifier),
                "value" => Ok(Column::Value),
                "expires_at" | "expiresAt" => Ok(Column::ExpiresAt),
                "created_at" | "createdAt" => Ok(Column::CreatedAt),
                "updated_at" | "updatedAt" => Ok(Column::UpdatedAt),
                _ => Err(AuthError::config(format!(
                    "Unknown application field: {name}"
                ))),
            }
        }
        fn native_json_field(_name: &str) -> bool {
            false
        }
        fn new_active(id: Option<Self::Id>, _fields: &FieldMap) -> AuthResult<Self::ActiveModel> {
            Ok(ActiveModel {
                id: id.map_or(NotSet, Set),
                ..Default::default()
            })
        }
        fn apply_fields(active: &mut Self::ActiveModel, fields: FieldMap) -> AuthResult<()> {
            for (name, value) in fields {
                match Self::field_column(&name)? {
                    Column::Id => {
                        active.id = Set(Self::parse_id(
                            &better_auth::SchemaValue::<String>::from_field(value)
                                .display_string()?,
                        )?)
                    }
                    Column::Identifier => active.identifier = Set(value.decode()?),
                    Column::Value => active.value = Set(value.decode()?),
                    Column::ExpiresAt => active.expires_at = Set(stored_date(value.decode()?)?),
                    Column::CreatedAt => active.created_at = Set(stored_date(value.decode()?)?),
                    Column::UpdatedAt => active.updated_at = Set(stored_date(value.decode()?)?),
                }
            }
            Ok(())
        }
        fn record_fields(
            &self,
            fields: &better_auth::config::UserConfig,
        ) -> AuthResult<better_auth_core::user_fields::AdapterRecord> {
            let mut storage = FieldMap::new();
            for (logical, field) in fields.fields() {
                if logical == "id" {
                    continue;
                }
                let key = field.field_name.as_deref().unwrap_or(logical);
                let value = better_auth::seaorm::field_value::from_column(
                    self.get(Self::field_column(key)?),
                )?;
                let _ = storage.insert(key.to_owned(), value);
            }
            let core = FieldMap::from([("id".into(), FieldValue::String(self.id.to_string()))]);
            Ok(better_auth_core::user_fields::AdapterRecord::new(
                core, storage,
            ))
        }
    }
}

pub struct AppSchema;

impl AuthSchema for AppSchema {
    type User = crate::user::Model;
    type Session = crate::session::Model;
    type Account = crate::account::Model;
    type Verification = crate::verification::Model;
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Better Auth PostgreSQL Example\n");

    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgresql://better_auth:password@localhost:5432/better_auth".to_string()
    });

    println!("Connecting to database: {}", hide_password(&database_url));

    let database = Database::connect(&database_url).await?;
    run_app_migrations(&database).await?;
    println!("Database connection established\n");

    let mut config = AuthConfig::new("your-very-secure-secret-key-at-least-32-chars-long")
        .base_url("http://localhost:3000")
        .password_min_length(8);
    config.advanced.database.generate_id = Some(better_auth::config::IdGeneration::Serial);
    let store = SeaOrmStore::<AppSchema>::new(config.clone(), database.clone());

    let auth = BetterAuth::<AppSchema>::new(config)
        .store(store)
        .plugin(
            EmailPasswordPlugin::new()
                .enable_signup(true)
                .password_hasher(Arc::new(Argon2PasswordHasher)),
        )
        .plugin(PasswordManagementPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .plugin(AccountManagementPlugin::new())
        .build()
        .await?;

    println!("BetterAuth instance created");
    println!("Registered plugins: {:?}\n", auth.plugin_names());

    seed_legacy_user(&database).await?;

    println!("=== Legacy user sign in ===");
    let legacy_signin_body = serde_json::json!({
        "email": "legacy@example.com",
        "password": "legacy_password_123"
    });
    let legacy_signin = send(
        &auth,
        HttpMethod::Post,
        "/sign-in/email",
        Some(&legacy_signin_body),
        None,
    )
    .await?;
    println!("Status: {}", legacy_signin.status);
    let legacy_data = parse_body(&legacy_signin.body.bytes()?);
    println!(
        "Legacy DB user id: {}\n",
        legacy_data["user"]["id"].as_str().unwrap_or("<missing>")
    );

    println!("=== Sign up ===");
    let signup_body = serde_json::json!({
        "email": "postgres_user@example.com",
        "password": "secure_password_123",
        "name": "PostgreSQL Test User",
        "username": "pg_user"
    });

    let signup_response = send(
        &auth,
        HttpMethod::Post,
        "/sign-up/email",
        Some(&signup_body),
        None,
    )
    .await?;
    println!("Status: {}", signup_response.status);
    let signup_data = parse_body(&signup_response.body.bytes()?);
    let token = signup_data
        .get("token")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    println!(
        "New DB user id: {}",
        signup_data["user"]["id"].as_str().unwrap_or("<missing>")
    );
    println!(
        "Locale defaulted to: {}",
        user::Entity::find()
            .filter(user::Column::Email.eq("postgres_user@example.com"))
            .one(&database)
            .await?
            .map(|user| user.locale)
            .unwrap_or_else(|| "<missing>".to_string())
    );
    println!();

    println!("=== Get session ===");
    let response = send(&auth, HttpMethod::Get, "/get-session", None, Some(&token)).await?;
    println!("Status: {}", response.status);
    let data = parse_body(&response.body.bytes()?);
    println!(
        "Session user: {}\n",
        data.get("user")
            .and_then(|user| user.get("email"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("<missing>")
    );

    println!("=== List accounts ===");
    let response = send(&auth, HttpMethod::Get, "/list-accounts", None, Some(&token)).await?;
    println!("Status: {}\n", response.status);

    println!("PostgreSQL example completed successfully!");

    Ok(())
}

async fn run_app_migrations(database: &DatabaseConnection) -> Result<(), sea_orm::DbErr> {
    let schema = Schema::new(database.get_database_backend());
    for statement in [
        schema
            .create_table_from_entity(user::Entity)
            .if_not_exists()
            .to_owned(),
        schema
            .create_table_from_entity(session::Entity)
            .if_not_exists()
            .to_owned(),
        schema
            .create_table_from_entity(account::Entity)
            .if_not_exists()
            .to_owned(),
        schema
            .create_table_from_entity(verification::Entity)
            .if_not_exists()
            .to_owned(),
    ] {
        let _ = database.execute(&statement).await?;
    }
    Ok(())
}

async fn seed_legacy_user(database: &DatabaseConnection) -> Result<(), Box<dyn std::error::Error>> {
    if user::Entity::find()
        .filter(user::Column::Email.eq("legacy@example.com"))
        .one(database)
        .await?
        .is_some()
    {
        return Ok(());
    }

    let now = Utc::now();
    let password_hash = hash_seed_password("legacy_password_123")
        .map_err(|error| format!("failed to hash seeded password: {error}"))?;
    let legacy_user = user::ActiveModel {
        id: NotSet,
        name: Set(Some("Legacy User".to_string())),
        email: Set(Some("legacy@example.com".to_string())),
        email_verified: Set(true),
        image: Set(None),
        username: Set(Some("legacy_user".to_string())),
        display_username: Set(Some("legacy_user".to_string())),
        two_factor_enabled: Set(false),
        role: Set(Some("user".to_string())),
        banned: Set(false),
        ban_reason: Set(None),
        ban_expires: Set(None),
        metadata: Set(json!({ "imported": true })),
        created_at: Set(now),
        updated_at: Set(now),
        tenant_id: Set(42),
        locale: Set("fr".to_string()),
    }
    .insert(database)
    .await?;

    let _ = account::ActiveModel {
        id: NotSet,
        account_id: Set(legacy_user.id.to_string()),
        provider_id: Set("credential".to_string()),
        user_id: Set(legacy_user.id),
        access_token: Set(None),
        refresh_token: Set(None),
        id_token: Set(None),
        access_token_expires_at: Set(None),
        refresh_token_expires_at: Set(None),
        scope: Set(None),
        password: Set(Some(password_hash)),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(database)
    .await?;

    Ok(())
}

async fn send(
    auth: &BetterAuth<AppSchema>,
    method: HttpMethod,
    path: &str,
    body: Option<&serde_json::Value>,
    bearer_token: Option<&str>,
) -> Result<AuthResponse, better_auth::AuthError> {
    let mut headers = HashMap::new();
    if body.is_some() {
        let _ = headers.insert("content-type".to_string(), "application/json".to_string());
    }
    if let Some(token) = bearer_token {
        let _ = headers.insert("authorization".to_string(), format!("Bearer {}", token));
    }

    let request = AuthRequest::from_parts(
        method,
        path.to_string(),
        headers,
        body.map(|b| b.to_string().into_bytes()),
        None,
    );

    auth.handle_request(request).await
}

fn parse_body(body: &[u8]) -> serde_json::Value {
    serde_json::from_slice(body).unwrap_or(serde_json::Value::Null)
}

fn hide_password(url: &str) -> String {
    if let Some(at_pos) = url.find('@')
        && let Some(colon_pos) = url[..at_pos].rfind(':')
        && let Some(slash_pos) = url[..colon_pos].rfind('/')
    {
        let before_password = &url[..slash_pos + 1];
        let after_password = &url[at_pos..];
        return format!("{}****{}", before_password, after_password);
    }
    url.to_string()
}

fn hash_seed_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
}
