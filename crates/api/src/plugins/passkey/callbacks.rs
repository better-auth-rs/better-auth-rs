//! Typed callback inputs. User writes use the active registration transaction.

use async_trait::async_trait;
use better_auth_core::{
    AuthConfig, AuthContext, AuthRequest, AuthResult, AuthSchema, CreateUser, RuntimeExtensions,
    plugin::MetadataMap, store::AuthTransaction, wire::UserView,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// User operations exposed to application registration callbacks.
#[async_trait]
pub trait PasskeyUsers: Send + Sync {
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<UserView>>;
    async fn create_user(&self, user: CreateUser) -> AuthResult<UserView>;
    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<UserView>>;
    async fn update_user(
        &self,
        id: &str,
        update: better_auth_core::UpdateUser,
    ) -> AuthResult<UserView>;
    async fn delete_user(&self, id: &str) -> AuthResult<()>;
}
/// Endpoint data and the active user adapter.
#[derive(Clone, Copy)]
pub struct PasskeyEndpoint<'a> {
    pub request: &'a AuthRequest,
    pub body: &'a Value,
    pub auth_config: &'a AuthConfig,
    pub extensions: &'a RuntimeExtensions,
    pub metadata: &'a MetadataMap,
    pub users: &'a dyn PasskeyUsers,
}
pub(super) struct Users<'a, S: AuthSchema> {
    pub ctx: &'a AuthContext<S>,
    pub transaction: Option<&'a dyn AuthTransaction<S>>,
}
#[async_trait]
impl<S: AuthSchema> PasskeyUsers for Users<'_, S> {
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<UserView>> {
        let user = match self.transaction {
            Some(tx) => tx.get_user_by_id(id).await?,
            None => self.ctx.database.get_user_by_id(id).await?,
        };
        user.map(|user| self.ctx.internal_user_view(&user))
            .transpose()
    }
    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<UserView>> {
        let user = match self.transaction {
            Some(tx) => tx.get_user_by_email(email).await?,
            None => self.ctx.database.get_user_by_email(email).await?,
        };
        user.map(|user| self.ctx.internal_user_view(&user))
            .transpose()
    }
    async fn update_user(
        &self,
        id: &str,
        update: better_auth_core::UpdateUser,
    ) -> AuthResult<UserView> {
        let user = match self.transaction {
            Some(tx) => tx.update_user(id, update).await?,
            None => self.ctx.database.update_user(id, update).await?,
        };
        self.ctx.internal_user_view(&user)
    }
    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        match self.transaction {
            Some(tx) => tx.delete_user(id).await,
            None => self.ctx.database.delete_user(id).await,
        }
    }
    async fn create_user(&self, mut user: CreateUser) -> AuthResult<UserView> {
        crate::plugins::helpers::apply_default_role(self.ctx, &mut user);
        let user = match self.transaction {
            Some(tx) => tx.create_user(user).await?,
            None => self.ctx.database.create_user(user).await?,
        };
        self.ctx.internal_user_view(&user)
    }
}
impl<'a> PasskeyEndpoint<'a> {
    pub(super) fn new<S: AuthSchema>(
        ctx: &'a AuthContext<S>,
        request: &'a AuthRequest,
        body: &'a Value,
        users: &'a dyn PasskeyUsers,
    ) -> Self {
        Self {
            request,
            body,
            auth_config: &ctx.config,
            extensions: &ctx.extensions,
            metadata: &ctx.metadata,
            users,
        }
    }
}
/// Account identity retained with the registration challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyRegistrationUser {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}
/// A verified public-key credential.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyCredential {
    pub id: String,
    pub public_key: Vec<u8>,
    pub counter: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}
/// Information from a cryptographically verified registration.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyRegistrationInfo {
    pub fmt: String,
    pub aaguid: String,
    pub credential: PasskeyCredential,
    pub credential_type: &'static str,
    pub attestation_object: Vec<u8>,
    pub user_verified: bool,
    pub credential_device_type: &'static str,
    pub credential_backed_up: bool,
    pub origin: String,
    #[serde(rename = "rpID")]
    pub rp_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_extension_results: Option<Value>,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyRegistrationVerification {
    pub verified: bool,
    pub registration_info: PasskeyRegistrationInfo,
}
/// Information from a cryptographically verified assertion.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyAuthenticationInfo {
    #[serde(rename = "credentialID")]
    pub credential_id: String,
    pub new_counter: u64,
    pub user_verified: bool,
    pub credential_device_type: &'static str,
    pub credential_backed_up: bool,
    pub origin: String,
    #[serde(rename = "rpID")]
    pub rp_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_extension_results: Option<Value>,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyAuthenticationVerification {
    pub verified: bool,
    pub authentication_info: PasskeyAuthenticationInfo,
}
/// Overrides applied after successful registration verification.
#[derive(Debug, Clone, Default)]
pub struct PasskeyRegistrationResult {
    pub user_id: Option<String>,
    pub name: Option<String>,
}
#[async_trait]
pub trait PasskeyUserResolver: Send + Sync {
    async fn resolve(
        &self,
        ctx: PasskeyEndpoint<'_>,
        context: Option<&str>,
    ) -> AuthResult<PasskeyRegistrationUser>;
}
#[async_trait]
pub trait PasskeyExtensionsResolver: Send + Sync {
    async fn extensions(&self, ctx: PasskeyEndpoint<'_>) -> AuthResult<Option<Map<String, Value>>>;
}
#[async_trait]
pub trait PasskeyRegistrationHook: Send + Sync {
    async fn after_verification(
        &self,
        ctx: PasskeyEndpoint<'_>,
        verification: &PasskeyRegistrationVerification,
        user: &PasskeyRegistrationUser,
        client_data: &Value,
        context: Option<&str>,
    ) -> AuthResult<PasskeyRegistrationResult>;
}
#[async_trait]
pub trait PasskeyAuthenticationHook: Send + Sync {
    async fn after_verification(
        &self,
        ctx: PasskeyEndpoint<'_>,
        verification: &PasskeyAuthenticationVerification,
        client_data: &Value,
    ) -> AuthResult<()>;
}
