use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::entity::{
    AuthAccount, AuthApiKey, AuthInvitation, AuthMember, AuthOrganization, AuthPasskey,
    AuthSession, AuthTwoFactor, AuthUser, AuthVerification,
};
use crate::error::AuthResult;
use crate::types::{
    CreateAccount, CreateApiKey, CreateInvitation, CreateMember, CreateOrganization, CreatePasskey,
    CreateSession, CreateTwoFactor, CreateUser, CreateVerification, InvitationStatus,
    ListUsersParams, UpdateAccount, UpdateApiKey, UpdateOrganization, UpdateUser,
};

/// User persistence operations.
#[async_trait]
pub trait UserOps: Send + Sync + 'static {
    type User: AuthUser;

    async fn create_user(&self, user: CreateUser) -> AuthResult<Self::User>;
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<Self::User>>;
    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<Self::User>>;
    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<Self::User>>;
    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<Self::User>;
    async fn delete_user(&self, id: &str) -> AuthResult<()>;
    /// List users with optional filtering, sorting, and pagination.
    /// Returns `(users, total_count)`.
    async fn list_users(&self, params: ListUsersParams) -> AuthResult<(Vec<Self::User>, usize)>;
}

/// Session persistence operations.
#[async_trait]
pub trait SessionOps: Send + Sync + 'static {
    type Session: AuthSession;

    async fn create_session(&self, session: CreateSession) -> AuthResult<Self::Session>;
    async fn get_session(&self, token: &str) -> AuthResult<Option<Self::Session>>;
    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<Self::Session>>;
    async fn update_session_expiry(&self, token: &str, expires_at: DateTime<Utc>)
    -> AuthResult<()>;
    async fn delete_session(&self, token: &str) -> AuthResult<()>;
    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()>;
    async fn delete_expired_sessions(&self) -> AuthResult<usize>;
    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<Self::Session>;
}

/// Account (OAuth provider linking) persistence operations.
#[async_trait]
pub trait AccountOps: Send + Sync + 'static {
    type Account: AuthAccount;

    async fn create_account(&self, account: CreateAccount) -> AuthResult<Self::Account>;
    async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<Self::Account>>;
    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<Self::Account>>;
    async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<Self::Account>;
    async fn delete_account(&self, id: &str) -> AuthResult<()>;
}

/// Verification token persistence operations.
#[async_trait]
pub trait VerificationOps: Send + Sync + 'static {
    type Verification: AuthVerification;

    async fn create_verification(
        &self,
        verification: CreateVerification,
    ) -> AuthResult<Self::Verification>;
    async fn get_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<Self::Verification>>;
    async fn get_verification_by_value(
        &self,
        value: &str,
    ) -> AuthResult<Option<Self::Verification>>;
    async fn get_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<Self::Verification>> {
        let _ = identifier;
        Ok(None)
    }
    /// Atomically consume a verification token identified by `(identifier, value)`.
    ///
    /// Implementations should remove the token if it exists and is valid, then
    /// return the removed record. This prevents replay and race windows from
    /// split read-then-delete flows.
    async fn consume_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<Self::Verification>>;
    async fn delete_verification(&self, id: &str) -> AuthResult<()>;
    async fn delete_expired_verifications(&self) -> AuthResult<usize>;
}

/// Organization persistence operations.
#[async_trait]
pub trait OrganizationOps: Send + Sync + 'static {
    type Organization: AuthOrganization;

    async fn create_organization(&self, org: CreateOrganization) -> AuthResult<Self::Organization>;
    async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<Self::Organization>>;
    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Self::Organization>>;
    async fn update_organization(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Self::Organization>;
    async fn delete_organization(&self, id: &str) -> AuthResult<()>;
    async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<Self::Organization>>;
}

/// Organization member persistence operations.
#[async_trait]
pub trait MemberOps: Send + Sync + 'static {
    type Member: AuthMember;

    async fn create_member(&self, member: CreateMember) -> AuthResult<Self::Member>;
    async fn get_member(
        &self,
        organization_id: &str,
        user_id: &str,
    ) -> AuthResult<Option<Self::Member>>;
    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<Self::Member>>;
    async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<Self::Member>;
    async fn delete_member(&self, member_id: &str) -> AuthResult<()>;
    async fn list_organization_members(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<Self::Member>>;
    async fn count_organization_members(&self, organization_id: &str) -> AuthResult<usize>;
    async fn count_organization_owners(&self, organization_id: &str) -> AuthResult<usize>;
}

/// Invitation persistence operations.
#[async_trait]
pub trait InvitationOps: Send + Sync + 'static {
    type Invitation: AuthInvitation;

    async fn create_invitation(&self, invitation: CreateInvitation)
    -> AuthResult<Self::Invitation>;
    async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<Self::Invitation>>;
    async fn get_pending_invitation(
        &self,
        organization_id: &str,
        email: &str,
    ) -> AuthResult<Option<Self::Invitation>>;
    async fn update_invitation_status(
        &self,
        id: &str,
        status: InvitationStatus,
    ) -> AuthResult<Self::Invitation>;
    async fn list_organization_invitations(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<Self::Invitation>>;
    async fn list_user_invitations(&self, email: &str) -> AuthResult<Vec<Self::Invitation>>;
}

/// Two-factor authentication persistence operations.
#[async_trait]
pub trait TwoFactorOps: Send + Sync + 'static {
    type TwoFactor: AuthTwoFactor;

    async fn create_two_factor(&self, two_factor: CreateTwoFactor) -> AuthResult<Self::TwoFactor>;
    async fn get_two_factor_by_user_id(&self, user_id: &str)
    -> AuthResult<Option<Self::TwoFactor>>;
    async fn update_two_factor_backup_codes(
        &self,
        user_id: &str,
        backup_codes: &str,
    ) -> AuthResult<Self::TwoFactor>;
    async fn delete_two_factor(&self, user_id: &str) -> AuthResult<()>;
}

/// API key persistence operations.
#[async_trait]
pub trait ApiKeyOps: Send + Sync + 'static {
    type ApiKey: AuthApiKey;

    async fn create_api_key(&self, input: CreateApiKey) -> AuthResult<Self::ApiKey>;
    async fn get_api_key_by_id(&self, id: &str) -> AuthResult<Option<Self::ApiKey>>;
    async fn get_api_key_by_hash(&self, hash: &str) -> AuthResult<Option<Self::ApiKey>>;
    async fn list_api_keys_by_user(&self, user_id: &str) -> AuthResult<Vec<Self::ApiKey>>;
    async fn update_api_key(&self, id: &str, update: UpdateApiKey) -> AuthResult<Self::ApiKey>;
    async fn delete_api_key(&self, id: &str) -> AuthResult<()>;
    /// Delete all API keys whose `expires_at` is in the past. Returns the count of deleted keys.
    async fn delete_expired_api_keys(&self) -> AuthResult<usize>;
}

/// Passkey persistence operations.
#[async_trait]
pub trait PasskeyOps: Send + Sync + 'static {
    type Passkey: AuthPasskey;

    async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<Self::Passkey>;
    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<Self::Passkey>>;
    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AuthResult<Option<Self::Passkey>>;
    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<Self::Passkey>>;
    async fn update_passkey_counter(&self, id: &str, counter: u64) -> AuthResult<Self::Passkey>;
    async fn update_passkey_name(&self, id: &str, name: &str) -> AuthResult<Self::Passkey>;
    async fn delete_passkey(&self, id: &str) -> AuthResult<()>;
}
