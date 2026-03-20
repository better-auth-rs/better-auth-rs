use async_trait::async_trait;
use std::any::Any;
use std::future::Future;
use std::pin::Pin;

pub mod cache;

use crate::error::{AuthError, AuthResult};
use crate::schema::AuthSchema;
use crate::types::{
    ApiKey, CreateAccount, CreateApiKey, CreateInvitation, CreateMember, CreateOrganization,
    CreatePasskey, CreateSession, CreateTwoFactor, CreateUser, CreateVerification, Invitation,
    InvitationStatus, ListUsersParams, Member, Organization, Passkey, TwoFactor, UpdateAccount,
    UpdateApiKey, UpdateOrganization, UpdateUser,
};

pub use cache::{CacheAdapter, MemoryCacheAdapter};

#[cfg(feature = "redis-cache")]
pub use cache::RedisAdapter;

pub type BoxedTransactionValue = Box<dyn Any + Send>;
pub type TransactionFuture<'a> =
    Pin<Box<dyn Future<Output = AuthResult<BoxedTransactionValue>> + Send + 'a>>;
pub type TypedTransactionFuture<'a, T> = Pin<Box<dyn Future<Output = AuthResult<T>> + Send + 'a>>;
pub type TransactionWork<S> =
    dyn for<'tx> FnOnce(&'tx dyn AuthTransaction<S>) -> TransactionFuture<'tx> + Send;

#[async_trait]
pub trait AuthTransaction<S: AuthSchema>: Send + Sync {
    async fn create_user(&self, create_user: CreateUser) -> AuthResult<S::User>;
    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<S::Account>;
    async fn create_session(&self, create_session: CreateSession) -> AuthResult<S::Session>;
}

#[async_trait]
pub trait UserStore<S: AuthSchema>: Send + Sync {
    async fn create_user(&self, create_user: CreateUser) -> AuthResult<S::User>;
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<S::User>>;
    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<S::User>>;
    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<S::User>>;
    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<S::User>;
    async fn delete_user(&self, id: &str) -> AuthResult<()>;
    async fn list_users(&self, params: ListUsersParams) -> AuthResult<(Vec<S::User>, usize)>;
}

#[async_trait]
pub trait SessionStore<S: AuthSchema>: Send + Sync {
    async fn create_session(&self, create_session: CreateSession) -> AuthResult<S::Session>;
    async fn get_session(&self, token: &str) -> AuthResult<Option<S::Session>>;
    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<S::Session>>;
    async fn update_session_expiry(
        &self,
        token: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<()>;
    async fn delete_session(&self, token: &str) -> AuthResult<()>;
    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()>;
    async fn delete_expired_sessions(&self) -> AuthResult<usize>;
    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<S::Session>;
}

#[async_trait]
pub trait AccountStore<S: AuthSchema>: Send + Sync {
    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<S::Account>;
    async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<S::Account>>;
    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<S::Account>>;
    async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<S::Account>;
    async fn delete_account(&self, id: &str) -> AuthResult<()>;
}

#[async_trait]
pub trait VerificationStore<S: AuthSchema>: Send + Sync {
    async fn create_verification(
        &self,
        verification: CreateVerification,
    ) -> AuthResult<S::Verification>;
    async fn get_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<S::Verification>>;
    async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<S::Verification>>;
    async fn get_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>>;
    async fn consume_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<S::Verification>>;
    async fn delete_verification(&self, id: &str) -> AuthResult<()>;
    async fn delete_expired_verifications(&self) -> AuthResult<usize>;
}

#[async_trait]
pub trait OrganizationStore: Send + Sync {
    async fn create_organization(&self, org: CreateOrganization) -> AuthResult<Organization>;
    async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<Organization>>;
    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Organization>>;
    async fn update_organization(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Organization>;
    async fn delete_organization(&self, id: &str) -> AuthResult<()>;
    async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<Organization>>;
}

#[async_trait]
pub trait MemberStore: Send + Sync {
    async fn create_member(&self, member: CreateMember) -> AuthResult<Member>;
    async fn get_member(&self, organization_id: &str, user_id: &str) -> AuthResult<Option<Member>>;
    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<Member>>;
    async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<Member>;
    async fn delete_member(&self, member_id: &str) -> AuthResult<()>;
    async fn list_organization_members(&self, org_id: &str) -> AuthResult<Vec<Member>>;
    async fn count_organization_members(&self, org_id: &str) -> AuthResult<i64>;
    async fn count_organization_owners(&self, org_id: &str) -> AuthResult<i64>;
}

#[async_trait]
pub trait InvitationStore: Send + Sync {
    async fn create_invitation(&self, invitation: CreateInvitation) -> AuthResult<Invitation>;
    async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<Invitation>>;
    async fn get_pending_invitation(
        &self,
        org_id: &str,
        email: &str,
    ) -> AuthResult<Option<Invitation>>;
    async fn update_invitation_status(
        &self,
        id: &str,
        status: InvitationStatus,
    ) -> AuthResult<Invitation>;
    async fn list_organization_invitations(&self, org_id: &str) -> AuthResult<Vec<Invitation>>;
    async fn list_user_invitations(&self, email: &str) -> AuthResult<Vec<Invitation>>;
}

#[async_trait]
pub trait TwoFactorStore: Send + Sync {
    async fn create_two_factor(&self, two_factor: CreateTwoFactor) -> AuthResult<TwoFactor>;
    async fn get_two_factor_by_user_id(&self, user_id: &str) -> AuthResult<Option<TwoFactor>>;
    async fn update_two_factor_backup_codes(
        &self,
        user_id: &str,
        backup_codes: &str,
    ) -> AuthResult<TwoFactor>;
    async fn delete_two_factor(&self, user_id: &str) -> AuthResult<()>;
}

#[async_trait]
pub trait ApiKeyStore: Send + Sync {
    async fn create_api_key(&self, input: CreateApiKey) -> AuthResult<ApiKey>;
    async fn get_api_key_by_id(&self, id: &str) -> AuthResult<Option<ApiKey>>;
    async fn get_api_key_by_hash(&self, hash: &str) -> AuthResult<Option<ApiKey>>;
    async fn list_api_keys_by_user(&self, user_id: &str) -> AuthResult<Vec<ApiKey>>;
    async fn update_api_key(&self, id: &str, update: UpdateApiKey) -> AuthResult<ApiKey>;
    async fn delete_api_key(&self, id: &str) -> AuthResult<()>;
    async fn delete_expired_api_keys(&self) -> AuthResult<usize>;
}

#[async_trait]
pub trait PasskeyStore: Send + Sync {
    async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<Passkey>;
    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<Passkey>>;
    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AuthResult<Option<Passkey>>;
    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<Passkey>>;
    async fn update_passkey_counter(&self, id: &str, counter: u64) -> AuthResult<Passkey>;
    async fn update_passkey_name(&self, id: &str, name: &str) -> AuthResult<Passkey>;
    async fn delete_passkey(&self, id: &str) -> AuthResult<()>;
}

#[async_trait]
pub trait TransactionStore<S: AuthSchema>: Send + Sync {
    async fn transaction_boxed(
        &self,
        work: Box<TransactionWork<S>>,
    ) -> AuthResult<BoxedTransactionValue>;
}

pub trait AuthStore<S: AuthSchema>:
    UserStore<S>
    + SessionStore<S>
    + AccountStore<S>
    + VerificationStore<S>
    + OrganizationStore
    + MemberStore
    + InvitationStore
    + TwoFactorStore
    + ApiKeyStore
    + PasskeyStore
    + TransactionStore<S>
    + Send
    + Sync
{
}

impl<S, T> AuthStore<S> for T
where
    S: AuthSchema,
    T: UserStore<S>
        + SessionStore<S>
        + AccountStore<S>
        + VerificationStore<S>
        + OrganizationStore
        + MemberStore
        + InvitationStore
        + TwoFactorStore
        + ApiKeyStore
        + PasskeyStore
        + TransactionStore<S>
        + Send
        + Sync,
{
}

pub async fn transaction<S, T, F>(store: &dyn AuthStore<S>, work: F) -> AuthResult<T>
where
    S: AuthSchema,
    T: Send + 'static,
    F: for<'tx> FnOnce(&'tx dyn AuthTransaction<S>) -> TypedTransactionFuture<'tx, T>
        + Send
        + 'static,
{
    let value = store
        .transaction_boxed(Box::new(move |tx| {
            Box::pin(async move { Ok(Box::new(work(tx).await?) as BoxedTransactionValue) })
        }))
        .await?;

    value
        .downcast::<T>()
        .map(|boxed| *boxed)
        .map_err(|_| AuthError::internal("store returned an invalid transaction payload"))
}
