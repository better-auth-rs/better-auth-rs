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
#[path = "test_store_fields.rs"]
mod fields;
#[path = "test_store_organization.rs"]
mod organization;
#[path = "test_store_sessions.rs"]
mod sessions;
#[path = "test_store_teams.rs"]
mod teams;

pub(crate) struct BundledSchema;

impl AuthSchema for BundledSchema {
    type User = UserView;
    type Session = SessionView;
    type Account = AccountView;
    type Verification = VerificationView;
}

#[derive(Default)]
struct State {
    organizations: HashMap<String, Organization>,
    members: HashMap<String, Member>,
    invitations: HashMap<String, Invitation>,
    teams: HashMap<String, crate::Team>,
    team_members: Vec<crate::TeamMember>,
    organization_roles: HashMap<String, crate::OrganizationRole>,
    jwks: Vec<crate::Jwk>,
    users: HashMap<String, UserView>,
    wallets: Vec<crate::types::WalletAddress>,
    sessions: HashMap<String, SessionView>,
    accounts: HashMap<String, AccountView>,
    verifications: HashMap<String, VerificationView>,
    two_factors: HashMap<String, TwoFactor>,
    device_codes: HashMap<String, DeviceCode>,
}

#[async_trait]
impl crate::store::JwksStore for MemoryStore {
    async fn list_jwks(&self) -> AuthResult<Vec<crate::Jwk>> {
        Ok(self.lock().jwks.clone())
    }

    async fn create_jwk(&self, input: crate::CreateJwk) -> AuthResult<crate::Jwk> {
        let key = crate::Jwk {
            id: uuid::Uuid::new_v4().to_string(),
            public_key: input.public_key,
            private_key: input.private_key,
            created_at: Utc::now(),
            expires_at: input.expires_at,
            alg: Some(input.alg),
            crv: input.crv,
        };
        self.lock().jwks.push(key.clone());
        Ok(key)
    }
}

#[derive(Default)]
pub(crate) struct MemoryStore {
    state: Mutex<State>,
    verification_lock: tokio::sync::Mutex<()>,
    session_config: crate::config::SessionConfig,
    organization_fields: std::sync::RwLock<crate::organization_fields::OrganizationFields>,
}

impl MemoryStore {
    pub(crate) fn new(config: Arc<AuthConfig>) -> Self {
        Self {
            session_config: config.session.clone(),
            ..Self::default()
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    async fn verify_unproven_user(
        &self,
        user_id: &str,
        database_sessions: bool,
        session_cleanup: Option<&dyn crate::store::VerificationSessionCleanup>,
    ) -> AuthResult<Option<UserView>> {
        let _verification = self.verification_lock.lock().await;
        let user = self.lock().users.get(user_id).cloned();
        let Some(user) = user else {
            return Ok(None);
        };
        if user.email_verified {
            return Ok(Some(user));
        }
        if let Some(cleanup) = session_cleanup {
            cleanup.revoke().await?;
        }
        let mut state = self.lock();
        state
            .accounts
            .retain(|_, account| account.user_id != user_id);
        if database_sessions {
            state
                .sessions
                .retain(|_, session| session.user_id != user_id);
        }
        if let Some(user) = state.users.get_mut(user_id) {
            user.email_verified = true;
            user.updated_at = Utc::now();
        }
        Ok(state.users.get(user_id).cloned())
    }
}

impl MemoryStore {
    fn organization_fields(&self) -> crate::organization_fields::OrganizationFields {
        self.organization_fields
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
    fn output_organization(&self, value: Organization) -> AuthResult<Organization> {
        let metadata = value.metadata.clone();
        let mut output: Organization =
            self.output_record(better_auth_schema_registry::EntityRole::Organization, value)?;
        if !self
            .organization_fields()
            .organization
            .additional_fields
            .contains_key("metadata")
        {
            output.metadata = metadata;
        }
        Ok(output)
    }
    fn output_member(&self, value: Member) -> AuthResult<Member> {
        self.output_record(better_auth_schema_registry::EntityRole::Member, value)
    }
    fn output_invitation(&self, value: Invitation) -> AuthResult<Invitation> {
        self.output_record(better_auth_schema_registry::EntityRole::Invitation, value)
    }
    fn output_team(&self, value: crate::Team) -> AuthResult<crate::Team> {
        self.output_record(better_auth_schema_registry::EntityRole::Team, value)
    }
    fn output_organization_role(
        &self,
        value: crate::OrganizationRole,
    ) -> AuthResult<crate::OrganizationRole> {
        self.output_record(
            better_auth_schema_registry::EntityRole::OrganizationRole,
            value,
        )
    }
}

struct MemoryTransaction<'a> {
    store: &'a MemoryStore,
}

#[async_trait]
impl AuthTransaction<BundledSchema> for MemoryTransaction<'_> {
    async fn create_verification(&self, input: CreateVerification) -> AuthResult<VerificationView> {
        self.store.create_verification(input).await
    }
    async fn get_verification_including_expired(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        self.store
            .get_verification_including_expired(identifier)
            .await
    }
    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        self.store.delete_expired_verifications().await
    }
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<UserView>> {
        self.store.get_user_by_id(id).await
    }
    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<UserView>> {
        self.store.get_user_by_email(email).await
    }
    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<UserView> {
        self.store.update_user(id, update).await
    }
    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        self.store.delete_user(id).await
    }
    async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<Passkey> {
        self.store.create_passkey(input).await
    }
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
    async fn verify_user_with_cleanup(
        &self,
        user_id: &str,
        cleanup: crate::store::VerificationCleanup,
        sessions: Option<&dyn crate::store::VerificationSessionCleanup>,
    ) -> AuthResult<Option<UserView>> {
        self.verify_unproven_user(
            user_id,
            matches!(
                cleanup,
                crate::store::VerificationCleanup::AccountsAndSessions
            ),
            sessions,
        )
        .await
    }

    async fn verify_user_and_revoke_unproven_access(
        &self,
        user_id: &str,
    ) -> AuthResult<Option<UserView>> {
        self.verify_unproven_user(user_id, true, None).await
    }
    async fn create_user(&self, create_user: CreateUser) -> AuthResult<UserView> {
        let now = Utc::now();
        let id = create_user
            .id
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let username = create_user.username.map(|username| username.to_lowercase());
        let user = UserView {
            additional_fields: Default::default(),
            visible_fields: None,
            id: id.clone(),
            name: create_user.name,
            email: create_user.email.map(|email| email.to_lowercase()),
            email_verified: create_user.email_verified.unwrap_or(false),
            image: create_user.image,
            created_at: now,
            updated_at: now,
            is_anonymous: create_user.is_anonymous,
            phone_number: create_user.phone_number,
            phone_number_verified: create_user.phone_number_verified,
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
    async fn get_user_by_id_value(&self, id: &serde_json::Value) -> AuthResult<Option<UserView>> {
        Ok(self
            .lock()
            .users
            .values()
            .find(|user| serde_json::json!(user.id) == *id)
            .cloned())
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

    async fn get_user_by_phone_number(&self, phone_number: &str) -> AuthResult<Option<UserView>> {
        Ok(self
            .lock()
            .users
            .values()
            .find(|user| user.phone_number.as_deref() == Some(phone_number))
            .cloned())
    }

    async fn update_user(&self, id: &str, mut update: UpdateUser) -> AuthResult<UserView> {
        let mut state = self.lock();
        let user = state.users.get_mut(id).ok_or(AuthError::UserNotFound)?;
        if update.phone_number == Some(None) {
            update.phone_number_verified = Some(false);
        }
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
        if let Some(value) = update.is_anonymous {
            user.is_anonymous = Some(value);
        }
        if let Some(value) = update.phone_number {
            user.phone_number = value;
        }
        if let Some(value) = update.phone_number_verified {
            user.phone_number_verified = Some(value);
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
    async fn reserve_verification(
        &self,
        id: &str,
        verification: CreateVerification,
    ) -> AuthResult<bool> {
        let mut state = self.lock();
        if state.verifications.contains_key(id) {
            return Ok(false);
        }
        let now = Utc::now();
        let _ = state.verifications.insert(
            id.to_owned(),
            VerificationView {
                id: id.to_owned(),
                identifier: verification.identifier,
                value: verification.value,
                expires_at: verification.expires_at,
                created_at: now,
                updated_at: now,
            },
        );
        Ok(true)
    }

    async fn get_verification_including_expired(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        Ok(self
            .lock()
            .verifications
            .values()
            .filter(|row| row.identifier == identifier)
            .max_by_key(|row| row.created_at)
            .cloned())
    }
    async fn update_verification_by_identifier(
        &self,
        identifier: &str,
        value: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> AuthResult<()> {
        for row in self
            .lock()
            .verifications
            .values_mut()
            .filter(|row| row.identifier == identifier)
        {
            if let Some(value) = &value {
                row.value.clone_from(value);
            }
            if let Some(expires_at) = expires_at {
                row.expires_at = expires_at;
            }
            row.updated_at = Utc::now();
        }
        Ok(())
    }
    async fn delete_verification_by_identifier(&self, identifier: &str) -> AuthResult<()> {
        self.lock()
            .verifications
            .retain(|_, row| row.identifier != identifier);
        Ok(())
    }
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
            .filter(|verification| verification.identifier == identifier)
            .max_by_key(|verification| verification.created_at)
            .filter(|verification| verification.value == value)
            .cloned();
        if found.is_some() {
            state
                .verifications
                .retain(|_, verification| verification.identifier != identifier);
        }
        Ok(found.filter(|verification| verification.expires_at >= Utc::now()))
    }

    async fn consume_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        Ok(self
            .consume_verification_including_expired(identifier)
            .await?
            .filter(|value| value.expires_at >= Utc::now()))
    }

    async fn consume_verification_including_expired(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        let mut state = self.lock();
        let found = state
            .verifications
            .values()
            .filter(|verification| verification.identifier == identifier)
            .max_by_key(|verification| verification.created_at)
            .cloned();
        state
            .verifications
            .retain(|_, verification| verification.identifier != identifier);
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
impl TwoFactorStore for MemoryStore {
    async fn update_two_factor(
        &self,
        id: &str,
        update: crate::types::UpdateTwoFactor,
    ) -> AuthResult<TwoFactor> {
        let mut state = self.lock();
        let factor = state
            .two_factors
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Two-factor settings not found"))?;
        if let Some(secret) = update.secret {
            factor.secret = secret;
        }
        if let Some(codes) = update.backup_codes {
            factor.backup_codes = codes;
        }
        if let Some(verified) = update.verified {
            factor.verified = verified;
        }
        factor.updated_at = Utc::now();
        Ok(factor.clone())
    }
    async fn compare_exchange_two_factor_backup_codes(
        &self,
        id: &str,
        previous: &str,
        replacement: &str,
    ) -> AuthResult<bool> {
        let mut state = self.lock();
        let Some(factor) = state
            .two_factors
            .get_mut(id)
            .filter(|factor| factor.backup_codes == previous)
        else {
            return Ok(false);
        };
        factor.backup_codes = replacement.to_owned();
        factor.updated_at = Utc::now();
        Ok(true)
    }
    async fn record_two_factor_failure(
        &self,
        id: &str,
        max_attempts: i64,
        locked_until: chrono::DateTime<Utc>,
    ) -> AuthResult<()> {
        if let Some(factor) = self.lock().two_factors.get_mut(id) {
            factor.failed_verification_count += 1;
            if factor.failed_verification_count >= max_attempts {
                factor.locked_until = Some(locked_until);
            }
        }
        Ok(())
    }
    async fn reset_two_factor_failures(
        &self,
        id: &str,
        locked_before: Option<chrono::DateTime<Utc>>,
    ) -> AuthResult<()> {
        if let Some(factor) = self.lock().two_factors.get_mut(id).filter(|factor| {
            locked_before
                .is_none_or(|before| factor.locked_until.is_some_and(|until| until <= before))
        }) {
            factor.failed_verification_count = 0;
            factor.locked_until = None;
        }
        Ok(())
    }
    async fn create_two_factor(&self, input: CreateTwoFactor) -> AuthResult<TwoFactor> {
        let factor = TwoFactor {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: input.user_id,
            secret: input.secret,
            backup_codes: input.backup_codes,
            verified: input.verified,
            failed_verification_count: 0,
            locked_until: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let _ = self
            .lock()
            .two_factors
            .insert(factor.id.clone(), factor.clone());
        Ok(factor)
    }
    async fn get_two_factor_by_user_id(&self, user_id: &str) -> AuthResult<Option<TwoFactor>> {
        Ok(self
            .lock()
            .two_factors
            .values()
            .find(|factor| factor.user_id == user_id)
            .cloned())
    }
    async fn update_two_factor_backup_codes(
        &self,
        user_id: &str,
        backup_codes: &str,
    ) -> AuthResult<TwoFactor> {
        let mut state = self.lock();
        let factor = state
            .two_factors
            .values_mut()
            .find(|factor| factor.user_id == user_id)
            .ok_or_else(|| AuthError::not_found("Two-factor settings not found"))?;
        factor.backup_codes = backup_codes.to_owned();
        factor.updated_at = Utc::now();
        Ok(factor.clone())
    }
    async fn delete_two_factor(&self, user_id: &str) -> AuthResult<()> {
        self.lock()
            .two_factors
            .retain(|_, factor| factor.user_id != user_id);
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
    async fn list_api_keys_by_reference(&self, _user_id: &str) -> AuthResult<Vec<ApiKey>> {
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

    async fn claim_device_code(&self, id: &str, user_id: &str) -> AuthResult<bool> {
        let mut state = self.lock();
        let Some(device_code) = state.device_codes.get_mut(id) else {
            return Ok(false);
        };

        if device_code.status != "pending" || device_code.user_id.is_some() {
            return Ok(false);
        }

        device_code.user_id = Some(user_id.to_string());
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
    let mut config = AuthConfig::new("test-secret-min-32-chars-1234567");
    config.session.bearer = Some(crate::config::BearerConfig::default());
    Arc::new(config)
}

pub(crate) async fn test_database() -> Arc<dyn AuthStore<BundledSchema>> {
    Arc::new(MemoryStore::new(test_config()))
}

#[async_trait]
impl crate::store::WalletStore for MemoryStore {
    async fn get_wallet_address(
        &self,
        address: &str,
        chain_id: Option<i64>,
    ) -> AuthResult<Option<crate::types::WalletAddress>> {
        Ok(self
            .lock()
            .wallets
            .iter()
            .find(|wallet| {
                wallet.address == address && chain_id.is_none_or(|chain| chain == wallet.chain_id)
            })
            .cloned())
    }
    async fn create_wallet_address(
        &self,
        value: crate::types::WalletAddress,
    ) -> AuthResult<crate::types::WalletAddress> {
        self.lock().wallets.push(value.clone());
        Ok(value)
    }
}
