use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::config::AuthConfig;
use crate::error::{AuthError, AuthResult};
use crate::schema::AuthSchema;
use crate::store::{
    AccountStore, ApiKeyStore, AuthStore, AuthTransaction, ConsumeApiKeyResult, DeviceCodeStore,
    InvitationStore, ListOrganizationMembersParams, MemberStore, OrganizationStore, PasskeyStore,
    SessionStore, TransactionStore, TwoFactorStore, UserStore, VerificationStore,
};
use crate::types::{
    ApiKey, CreateAccount, CreateApiKey, CreateDeviceCode, CreateInvitation, CreateMember,
    CreateOrganization, CreatePasskey, CreateSession, CreateTwoFactor, CreateUser,
    CreateVerification, DeviceCode, Invitation, InvitationStatus, ListUsersParams, Member,
    Organization, Passkey, TwoFactor, UpdateAccount, UpdateApiKey, UpdateDeviceCode,
    UpdateOrganization, UpdatePasskeyAuthentication, UpdateUser,
};
use crate::wire::{AccountView, SessionView, UserView, VerificationView};

pub(crate) struct BundledSchema;

impl AuthSchema for BundledSchema {
    type User = UserView;
    type Session = SessionView;
    type Account = AccountView;
    type Verification = VerificationView;
}

#[derive(Default)]
struct State {
    users: HashMap<String, UserView>,
    sessions: HashMap<String, SessionView>,
    accounts: HashMap<String, AccountView>,
    verifications: HashMap<String, VerificationView>,
    device_codes: HashMap<String, DeviceCode>,
}

#[derive(Default)]
pub(crate) struct MemoryStore {
    state: Mutex<State>,
}

impl MemoryStore {
    pub(crate) fn new(_config: Arc<AuthConfig>) -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

struct MemoryTransaction<'a> {
    store: &'a MemoryStore,
}

#[async_trait]
impl AuthTransaction<BundledSchema> for MemoryTransaction<'_> {
    async fn create_user(&self, create_user: CreateUser) -> AuthResult<UserView> {
        self.store.create_user(create_user).await
    }

    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<AccountView> {
        self.store.create_account(create_account).await
    }

    async fn create_session(&self, create_session: CreateSession) -> AuthResult<SessionView> {
        self.store.create_session(create_session).await
    }
}

#[async_trait]
impl UserStore<BundledSchema> for MemoryStore {
    async fn create_user(&self, create_user: CreateUser) -> AuthResult<UserView> {
        let now = Utc::now();
        let id = create_user
            .id
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let username = create_user.username.map(|username| username.to_lowercase());
        let user = UserView {
            id: id.clone(),
            name: create_user.name,
            email: create_user.email.map(|email| email.to_lowercase()),
            email_verified: create_user.email_verified.unwrap_or(false),
            image: create_user.image,
            created_at: now,
            updated_at: now,
            username,
            display_username: create_user.display_username,
            two_factor_enabled: false,
            role: create_user.role,
            banned: false,
            ban_reason: None,
            ban_expires: None,
            metadata: create_user
                .metadata
                .unwrap_or_else(|| serde_json::json!({})),
        };
        self.lock().users.insert(id, user.clone());
        Ok(user)
    }

    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<UserView>> {
        Ok(self.lock().users.get(id).cloned())
    }

    async fn list_users_by_ids(&self, ids: &[String]) -> AuthResult<Vec<UserView>> {
        let state = self.lock();
        Ok(ids
            .iter()
            .filter_map(|id| state.users.get(id).cloned())
            .collect())
    }

    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<UserView>> {
        Ok(self
            .lock()
            .users
            .values()
            .find(|user| user.email.as_deref() == Some(&email.to_lowercase()))
            .cloned())
    }

    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<UserView>> {
        let normalized = username.to_lowercase();
        Ok(self
            .lock()
            .users
            .values()
            .find(|user| user.username.as_deref() == Some(&normalized))
            .cloned())
    }

    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<UserView> {
        let mut state = self.lock();
        let user = state.users.get_mut(id).ok_or(AuthError::UserNotFound)?;
        if let Some(email) = update.email {
            user.email = Some(email.to_lowercase());
        }
        if let Some(name) = update.name {
            user.name = Some(name);
        }
        if let Some(image) = update.image {
            user.image = Some(image);
        }
        if let Some(email_verified) = update.email_verified {
            user.email_verified = email_verified;
        }
        if let Some(username) = update.username {
            user.username = Some(username.to_lowercase());
        }
        if let Some(display_username) = update.display_username {
            user.display_username = Some(display_username);
        }
        if let Some(role) = update.role {
            user.role = Some(role);
        }
        if let Some(banned) = update.banned {
            user.banned = banned;
            if !banned {
                user.ban_reason = None;
                user.ban_expires = None;
            }
        }
        if let Some(ban_reason) = update.ban_reason {
            user.ban_reason = Some(ban_reason);
        }
        if let Some(ban_expires) = update.ban_expires {
            user.ban_expires = Some(ban_expires);
        }
        if let Some(two_factor_enabled) = update.two_factor_enabled {
            user.two_factor_enabled = two_factor_enabled;
        }
        if let Some(metadata) = update.metadata {
            user.metadata = metadata;
        }
        user.updated_at = Utc::now();
        Ok(user.clone())
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        self.lock().users.remove(id);
        Ok(())
    }

    async fn list_users(&self, _params: ListUsersParams) -> AuthResult<(Vec<UserView>, usize)> {
        let users: Vec<_> = self.lock().users.values().cloned().collect();
        Ok(crate::user_query::apply_list_users(users, &_params))
    }
}

#[async_trait]
impl SessionStore<BundledSchema> for MemoryStore {
    async fn create_session(&self, create_session: CreateSession) -> AuthResult<SessionView> {
        let now = Utc::now();
        let token = format!("session_{}", uuid::Uuid::new_v4());
        let session = SessionView {
            id: uuid::Uuid::new_v4().to_string(),
            expires_at: create_session.expires_at,
            token: token.clone(),
            created_at: now,
            updated_at: now,
            ip_address: create_session.ip_address.or_else(|| Some(String::new())),
            user_agent: create_session.user_agent.or_else(|| Some(String::new())),
            user_id: create_session.user_id,
            impersonated_by: create_session.impersonated_by,
            active_organization_id: create_session.active_organization_id,
            active: true,
        };
        self.lock().sessions.insert(token, session.clone());
        Ok(session)
    }

    async fn get_session(&self, token: &str) -> AuthResult<Option<SessionView>> {
        Ok(self.lock().sessions.get(token).cloned())
    }

    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<SessionView>> {
        Ok(self
            .lock()
            .sessions
            .values()
            .filter(|session| session.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn update_session_expiry(
        &self,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<()> {
        if let Some(session) = self.lock().sessions.get_mut(token) {
            session.expires_at = expires_at;
            session.updated_at = Utc::now();
            Ok(())
        } else {
            Err(AuthError::SessionNotFound)
        }
    }

    async fn delete_session(&self, token: &str) -> AuthResult<()> {
        self.lock().sessions.remove(token);
        Ok(())
    }

    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        self.lock()
            .sessions
            .retain(|_, session| session.user_id != user_id);
        Ok(())
    }

    async fn delete_expired_sessions(&self) -> AuthResult<usize> {
        let now = Utc::now();
        let mut state = self.lock();
        let before = state.sessions.len();
        state
            .sessions
            .retain(|_, session| session.expires_at > now && session.active);
        Ok(before - state.sessions.len())
    }

    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<SessionView> {
        let mut state = self.lock();
        let session = state
            .sessions
            .get_mut(token)
            .ok_or(AuthError::SessionNotFound)?;
        session.active_organization_id = organization_id.map(str::to_owned);
        session.updated_at = Utc::now();
        Ok(session.clone())
    }
}

#[async_trait]
impl AccountStore<BundledSchema> for MemoryStore {
    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<AccountView> {
        let now = Utc::now();
        let account = AccountView {
            id: uuid::Uuid::new_v4().to_string(),
            account_id: create_account.account_id,
            provider_id: create_account.provider_id,
            user_id: create_account.user_id,
            access_token: create_account.access_token,
            refresh_token: create_account.refresh_token,
            id_token: create_account.id_token,
            access_token_expires_at: create_account.access_token_expires_at,
            refresh_token_expires_at: create_account.refresh_token_expires_at,
            scope: create_account.scope,
            password: create_account.password,
            created_at: now,
            updated_at: now,
        };
        self.lock()
            .accounts
            .insert(account.id.clone(), account.clone());
        Ok(account)
    }

    async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<AccountView>> {
        Ok(self
            .lock()
            .accounts
            .values()
            .find(|account| {
                account.provider_id == provider && account.account_id == provider_account_id
            })
            .cloned())
    }

    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<AccountView>> {
        Ok(self
            .lock()
            .accounts
            .values()
            .filter(|account| account.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<AccountView> {
        let mut state = self.lock();
        let account = state
            .accounts
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Account not found"))?;
        if let Some(access_token) = update.access_token {
            account.access_token = Some(access_token);
        }
        if let Some(refresh_token) = update.refresh_token {
            account.refresh_token = Some(refresh_token);
        }
        if let Some(id_token) = update.id_token {
            account.id_token = Some(id_token);
        }
        if let Some(access_token_expires_at) = update.access_token_expires_at {
            account.access_token_expires_at = Some(access_token_expires_at);
        }
        if let Some(refresh_token_expires_at) = update.refresh_token_expires_at {
            account.refresh_token_expires_at = Some(refresh_token_expires_at);
        }
        if let Some(scope) = update.scope {
            account.scope = Some(scope);
        }
        if let Some(password) = update.password {
            account.password = Some(password);
        }
        account.updated_at = Utc::now();
        Ok(account.clone())
    }

    async fn delete_account(&self, id: &str) -> AuthResult<()> {
        self.lock().accounts.remove(id);
        Ok(())
    }
}

#[async_trait]
impl VerificationStore<BundledSchema> for MemoryStore {
    async fn create_verification(
        &self,
        verification: CreateVerification,
    ) -> AuthResult<VerificationView> {
        let now = Utc::now();
        let verification = VerificationView {
            id: uuid::Uuid::new_v4().to_string(),
            identifier: verification.identifier,
            value: verification.value,
            expires_at: verification.expires_at,
            created_at: now,
            updated_at: now,
        };
        self.lock()
            .verifications
            .insert(verification.id.clone(), verification.clone());
        Ok(verification)
    }

    async fn get_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<VerificationView>> {
        Ok(self
            .lock()
            .verifications
            .values()
            .find(|verification| {
                verification.identifier == identifier && verification.value == value
            })
            .cloned())
    }

    async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<VerificationView>> {
        Ok(self
            .lock()
            .verifications
            .values()
            .find(|verification| verification.value == value)
            .cloned())
    }

    async fn get_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        Ok(self
            .lock()
            .verifications
            .values()
            .find(|verification| verification.identifier == identifier)
            .cloned())
    }

    async fn consume_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<VerificationView>> {
        let mut state = self.lock();
        let found = state
            .verifications
            .values()
            .find(|verification| {
                verification.identifier == identifier && verification.value == value
            })
            .cloned();
        if let Some(verification) = &found {
            state.verifications.remove(&verification.id);
        }
        Ok(found)
    }

    async fn delete_verification(&self, id: &str) -> AuthResult<()> {
        self.lock().verifications.remove(id);
        Ok(())
    }

    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        let now = Utc::now();
        let mut state = self.lock();
        let before = state.verifications.len();
        state
            .verifications
            .retain(|_, verification| verification.expires_at > now);
        Ok(before - state.verifications.len())
    }
}

#[async_trait]
impl OrganizationStore for MemoryStore {
    async fn create_organization(&self, _org: CreateOrganization) -> AuthResult<Organization> {
        Err(AuthError::internal("unsupported test-store operation"))
    }
    async fn get_organization_by_id(&self, _id: &str) -> AuthResult<Option<Organization>> {
        Ok(None)
    }
    async fn get_organization_by_slug(&self, _slug: &str) -> AuthResult<Option<Organization>> {
        Ok(None)
    }
    async fn list_organizations_by_ids(&self, _ids: &[String]) -> AuthResult<Vec<Organization>> {
        Ok(Vec::new())
    }
    async fn update_organization(
        &self,
        _id: &str,
        _update: UpdateOrganization,
    ) -> AuthResult<Organization> {
        Err(AuthError::internal("unsupported test-store operation"))
    }
    async fn delete_organization(&self, _id: &str) -> AuthResult<()> {
        Ok(())
    }
    async fn list_user_organizations(&self, _user_id: &str) -> AuthResult<Vec<Organization>> {
        Ok(Vec::new())
    }
}

#[async_trait]
impl MemberStore for MemoryStore {
    async fn create_member(&self, _member: CreateMember) -> AuthResult<Member> {
        Err(AuthError::internal("unsupported test-store operation"))
    }
    async fn get_member(
        &self,
        _organization_id: &str,
        _user_id: &str,
    ) -> AuthResult<Option<Member>> {
        Ok(None)
    }
    async fn get_member_by_id(&self, _id: &str) -> AuthResult<Option<Member>> {
        Ok(None)
    }
    async fn update_member_role(&self, _member_id: &str, _role: &str) -> AuthResult<Member> {
        Err(AuthError::internal("unsupported test-store operation"))
    }
    async fn delete_member(&self, _member_id: &str) -> AuthResult<()> {
        Ok(())
    }
    async fn list_organization_members(&self, _org_id: &str) -> AuthResult<Vec<Member>> {
        Ok(Vec::new())
    }
    async fn query_organization_members(
        &self,
        _params: &ListOrganizationMembersParams,
    ) -> AuthResult<(Vec<Member>, usize)> {
        Ok((Vec::new(), 0))
    }
    async fn count_organization_members(&self, _org_id: &str) -> AuthResult<i64> {
        Ok(0)
    }
    async fn count_organization_owners(&self, _org_id: &str) -> AuthResult<i64> {
        Ok(0)
    }
}

#[async_trait]
impl InvitationStore for MemoryStore {
    async fn create_invitation(&self, _invitation: CreateInvitation) -> AuthResult<Invitation> {
        Err(AuthError::internal("unsupported test-store operation"))
    }
    async fn get_invitation_by_id(&self, _id: &str) -> AuthResult<Option<Invitation>> {
        Ok(None)
    }
    async fn get_pending_invitation(
        &self,
        _org_id: &str,
        _email: &str,
    ) -> AuthResult<Option<Invitation>> {
        Ok(None)
    }
    async fn update_invitation_status(
        &self,
        _id: &str,
        _status: InvitationStatus,
    ) -> AuthResult<Invitation> {
        Err(AuthError::internal("unsupported test-store operation"))
    }
    async fn list_organization_invitations(&self, _org_id: &str) -> AuthResult<Vec<Invitation>> {
        Ok(Vec::new())
    }
    async fn count_pending_organization_invitations(&self, _org_id: &str) -> AuthResult<i64> {
        Ok(0)
    }
    async fn list_user_invitations(&self, _email: &str) -> AuthResult<Vec<Invitation>> {
        Ok(Vec::new())
    }
}

#[async_trait]
impl TwoFactorStore for MemoryStore {
    async fn create_two_factor(&self, _two_factor: CreateTwoFactor) -> AuthResult<TwoFactor> {
        Err(AuthError::internal("unsupported test-store operation"))
    }
    async fn get_two_factor_by_user_id(&self, _user_id: &str) -> AuthResult<Option<TwoFactor>> {
        Ok(None)
    }
    async fn update_two_factor_backup_codes(
        &self,
        _user_id: &str,
        _backup_codes: &str,
    ) -> AuthResult<TwoFactor> {
        Err(AuthError::internal("unsupported test-store operation"))
    }
    async fn delete_two_factor(&self, _user_id: &str) -> AuthResult<()> {
        Ok(())
    }
}

#[async_trait]
impl ApiKeyStore for MemoryStore {
    async fn create_api_key(&self, _input: CreateApiKey) -> AuthResult<ApiKey> {
        Err(AuthError::internal("unsupported test-store operation"))
    }
    async fn get_api_key_by_id(&self, _id: &str) -> AuthResult<Option<ApiKey>> {
        Ok(None)
    }
    async fn get_api_key_by_hash(&self, _hash: &str) -> AuthResult<Option<ApiKey>> {
        Ok(None)
    }
    async fn list_api_keys_by_user(&self, _user_id: &str) -> AuthResult<Vec<ApiKey>> {
        Ok(Vec::new())
    }
    async fn update_api_key(&self, _id: &str, _update: UpdateApiKey) -> AuthResult<ApiKey> {
        Err(AuthError::internal("unsupported test-store operation"))
    }
    async fn delete_api_key(&self, _id: &str) -> AuthResult<()> {
        Ok(())
    }
    async fn delete_expired_api_keys(&self) -> AuthResult<usize> {
        Ok(0)
    }
    async fn consume_api_key_usage(
        &self,
        _id: &str,
        _global_rate_limit_enabled: bool,
    ) -> AuthResult<ConsumeApiKeyResult> {
        Err(AuthError::internal("unsupported test-store operation"))
    }
}

#[async_trait]
impl PasskeyStore for MemoryStore {
    async fn create_passkey(&self, _input: CreatePasskey) -> AuthResult<Passkey> {
        Err(AuthError::internal("unsupported test-store operation"))
    }
    async fn get_passkey_by_id(&self, _id: &str) -> AuthResult<Option<Passkey>> {
        Ok(None)
    }
    async fn get_passkey_by_credential_id(
        &self,
        _credential_id: &str,
    ) -> AuthResult<Option<Passkey>> {
        Ok(None)
    }
    async fn list_passkeys_by_user(&self, _user_id: &str) -> AuthResult<Vec<Passkey>> {
        Ok(Vec::new())
    }
    async fn update_passkey_authentication(
        &self,
        _id: &str,
        _update: UpdatePasskeyAuthentication,
    ) -> AuthResult<Passkey> {
        Err(AuthError::internal("unsupported test-store operation"))
    }
    async fn update_passkey_name(&self, _id: &str, _name: &str) -> AuthResult<Passkey> {
        Err(AuthError::internal("unsupported test-store operation"))
    }
    async fn delete_passkey(&self, _id: &str) -> AuthResult<()> {
        Ok(())
    }
}

#[async_trait]
impl DeviceCodeStore for MemoryStore {
    async fn create_device_code(&self, input: CreateDeviceCode) -> AuthResult<DeviceCode> {
        let device_code = DeviceCode {
            id: uuid::Uuid::new_v4().to_string(),
            device_code: input.device_code,
            user_code: input.user_code,
            user_id: input.user_id,
            expires_at: input.expires_at,
            status: input.status,
            last_polled_at: input.last_polled_at,
            polling_interval: input.polling_interval,
            client_id: input.client_id,
            scope: input.scope,
        };
        self.lock()
            .device_codes
            .insert(device_code.id.clone(), device_code.clone());
        Ok(device_code)
    }

    async fn get_device_code_by_device_code(
        &self,
        device_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        Ok(self
            .lock()
            .device_codes
            .values()
            .find(|value| value.device_code == device_code)
            .cloned())
    }

    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        Ok(self
            .lock()
            .device_codes
            .values()
            .find(|value| value.user_code == user_code)
            .cloned())
    }

    async fn update_device_code(
        &self,
        id: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<DeviceCode> {
        let mut state = self.lock();
        let device_code = state
            .device_codes
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Device code not found"))?;

        if let Some(status) = update.status {
            device_code.status = status;
        }
        if let Some(user_id) = update.user_id {
            device_code.user_id = user_id;
        }
        if let Some(last_polled_at) = update.last_polled_at {
            device_code.last_polled_at = last_polled_at;
        }

        Ok(device_code.clone())
    }

    async fn update_device_code_if_status(
        &self,
        id: &str,
        current_status: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<bool> {
        let mut state = self.lock();
        let Some(device_code) = state.device_codes.get_mut(id) else {
            return Ok(false);
        };

        if device_code.status != current_status {
            return Ok(false);
        }

        if let Some(status) = update.status {
            device_code.status = status;
        }
        if let Some(user_id) = update.user_id {
            device_code.user_id = user_id;
        }
        if let Some(last_polled_at) = update.last_polled_at {
            device_code.last_polled_at = last_polled_at;
        }

        Ok(true)
    }

    async fn delete_device_code(&self, id: &str) -> AuthResult<()> {
        self.lock().device_codes.remove(id);
        Ok(())
    }

    async fn delete_device_code_if_status(&self, id: &str, status: &str) -> AuthResult<bool> {
        let mut state = self.lock();
        let should_delete = state
            .device_codes
            .get(id)
            .is_some_and(|device_code| device_code.status == status);

        if should_delete {
            state.device_codes.remove(id);
        }

        Ok(should_delete)
    }
}

#[async_trait]
impl TransactionStore<BundledSchema> for MemoryStore {
    async fn transaction_boxed(
        &self,
        work: Box<crate::store::TransactionWork<BundledSchema>>,
    ) -> AuthResult<crate::store::BoxedTransactionValue> {
        let tx = MemoryTransaction { store: self };
        work(&tx).await
    }
}

pub(crate) fn test_config() -> Arc<AuthConfig> {
    Arc::new(AuthConfig::new("test-secret-min-32-chars-1234567"))
}

pub(crate) async fn test_database() -> Arc<dyn AuthStore<BundledSchema>> {
    Arc::new(MemoryStore::new(test_config()))
}
