use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use crate::entity::{
    AuthAccount, AuthInvitation, AuthMember, AuthOrganization, AuthSession, AuthUser,
    AuthVerification,
};
use crate::error::{AuthError, AuthResult};
use crate::types::{
    Account, CreateAccount, CreateInvitation, CreateMember, CreateOrganization, CreateSession,
    CreateUser, CreateVerification, Invitation, InvitationStatus, Member, Organization, Session,
    UpdateOrganization, UpdateUser, User, Verification,
};

use super::DatabaseAdapter;

// ─── Memory entity traits ──────────────────────────────────────────────
//
// These traits extend the read-only `Auth*` entity traits with construction
// and mutation methods needed by `MemoryDatabaseAdapter`. Implement these
// on your custom entity types to use them with the in-memory adapter.

/// Construction and mutation for user entities stored in memory.
pub trait MemoryUser: AuthUser {
    /// Construct a new user from creation data.
    fn from_create(id: String, create: &CreateUser, now: DateTime<Utc>) -> Self;
    /// Apply an update in place.
    fn apply_update(&mut self, update: &UpdateUser);
}

/// Construction and mutation for session entities stored in memory.
pub trait MemorySession: AuthSession {
    /// Construct a new session from creation data.
    fn from_create(id: String, token: String, create: &CreateSession, now: DateTime<Utc>) -> Self;
    fn set_expires_at(&mut self, at: DateTime<Utc>);
    fn set_active_organization_id(&mut self, org_id: Option<String>);
    fn set_updated_at(&mut self, at: DateTime<Utc>);
}

/// Construction for account entities stored in memory.
pub trait MemoryAccount: AuthAccount {
    fn from_create(id: String, create: &CreateAccount, now: DateTime<Utc>) -> Self;
}

/// Construction for verification entities stored in memory.
pub trait MemoryVerification: AuthVerification {
    fn from_create(id: String, create: &CreateVerification, now: DateTime<Utc>) -> Self;
}

/// Construction and mutation for organization entities stored in memory.
pub trait MemoryOrganization: AuthOrganization {
    fn from_create(id: String, create: &CreateOrganization, now: DateTime<Utc>) -> Self;
    fn apply_update(&mut self, update: &UpdateOrganization);
}

/// Construction and mutation for member entities stored in memory.
pub trait MemoryMember: AuthMember {
    fn from_create(id: String, create: &CreateMember, now: DateTime<Utc>) -> Self;
    fn set_role(&mut self, role: String);
}

/// Construction and mutation for invitation entities stored in memory.
pub trait MemoryInvitation: AuthInvitation {
    fn from_create(id: String, create: &CreateInvitation, now: DateTime<Utc>) -> Self;
    fn set_status(&mut self, status: InvitationStatus);
}

// ─── Default implementations for built-in types ─────────────────────────

impl MemoryUser for User {
    fn from_create(id: String, create: &CreateUser, now: DateTime<Utc>) -> Self {
        User {
            id,
            name: create.name.clone(),
            email: create.email.clone(),
            email_verified: create.email_verified.unwrap_or(false),
            image: create.image.clone(),
            created_at: now,
            updated_at: now,
            username: create.username.clone(),
            display_username: create.display_username.clone(),
            two_factor_enabled: false,
            role: create.role.clone(),
            banned: false,
            ban_reason: None,
            ban_expires: None,
            metadata: create.metadata.clone().unwrap_or(serde_json::json!({})),
        }
    }

    fn apply_update(&mut self, update: &UpdateUser) {
        if let Some(email) = &update.email {
            self.email = Some(email.clone());
        }
        if let Some(name) = &update.name {
            self.name = Some(name.clone());
        }
        if let Some(image) = &update.image {
            self.image = Some(image.clone());
        }
        if let Some(email_verified) = update.email_verified {
            self.email_verified = email_verified;
        }
        if let Some(username) = &update.username {
            self.username = Some(username.clone());
        }
        if let Some(display_username) = &update.display_username {
            self.display_username = Some(display_username.clone());
        }
        if let Some(role) = &update.role {
            self.role = Some(role.clone());
        }
        if let Some(banned) = update.banned {
            self.banned = banned;
        }
        if let Some(ban_reason) = &update.ban_reason {
            self.ban_reason = Some(ban_reason.clone());
        }
        if let Some(ban_expires) = update.ban_expires {
            self.ban_expires = Some(ban_expires);
        }
        if let Some(two_factor_enabled) = update.two_factor_enabled {
            self.two_factor_enabled = two_factor_enabled;
        }
        if let Some(metadata) = &update.metadata {
            self.metadata = metadata.clone();
        }
        self.updated_at = Utc::now();
    }
}

impl MemorySession for Session {
    fn from_create(id: String, token: String, create: &CreateSession, now: DateTime<Utc>) -> Self {
        Session {
            id,
            token,
            expires_at: create.expires_at,
            created_at: now,
            updated_at: now,
            ip_address: create.ip_address.clone(),
            user_agent: create.user_agent.clone(),
            user_id: create.user_id.clone(),
            impersonated_by: create.impersonated_by.clone(),
            active_organization_id: create.active_organization_id.clone(),
            active: true,
        }
    }

    fn set_expires_at(&mut self, at: DateTime<Utc>) {
        self.expires_at = at;
    }

    fn set_active_organization_id(&mut self, org_id: Option<String>) {
        self.active_organization_id = org_id;
    }

    fn set_updated_at(&mut self, at: DateTime<Utc>) {
        self.updated_at = at;
    }
}

impl MemoryAccount for Account {
    fn from_create(id: String, create: &CreateAccount, now: DateTime<Utc>) -> Self {
        Account {
            id,
            account_id: create.account_id.clone(),
            provider_id: create.provider_id.clone(),
            user_id: create.user_id.clone(),
            access_token: create.access_token.clone(),
            refresh_token: create.refresh_token.clone(),
            id_token: create.id_token.clone(),
            access_token_expires_at: create.access_token_expires_at,
            refresh_token_expires_at: create.refresh_token_expires_at,
            scope: create.scope.clone(),
            password: create.password.clone(),
            created_at: now,
            updated_at: now,
        }
    }
}

impl MemoryVerification for Verification {
    fn from_create(id: String, create: &CreateVerification, now: DateTime<Utc>) -> Self {
        Verification {
            id,
            identifier: create.identifier.clone(),
            value: create.value.clone(),
            expires_at: create.expires_at,
            created_at: now,
            updated_at: now,
        }
    }
}

impl MemoryOrganization for Organization {
    fn from_create(id: String, create: &CreateOrganization, now: DateTime<Utc>) -> Self {
        Organization {
            id,
            name: create.name.clone(),
            slug: create.slug.clone(),
            logo: create.logo.clone(),
            metadata: create.metadata.clone(),
            created_at: now,
            updated_at: now,
        }
    }

    fn apply_update(&mut self, update: &UpdateOrganization) {
        if let Some(name) = &update.name {
            self.name = name.clone();
        }
        if let Some(slug) = &update.slug {
            self.slug = slug.clone();
        }
        if let Some(logo) = &update.logo {
            self.logo = Some(logo.clone());
        }
        if let Some(metadata) = &update.metadata {
            self.metadata = Some(metadata.clone());
        }
        self.updated_at = Utc::now();
    }
}

impl MemoryMember for Member {
    fn from_create(id: String, create: &CreateMember, now: DateTime<Utc>) -> Self {
        Member {
            id,
            organization_id: create.organization_id.clone(),
            user_id: create.user_id.clone(),
            role: create.role.clone(),
            created_at: now,
        }
    }

    fn set_role(&mut self, role: String) {
        self.role = role;
    }
}

impl MemoryInvitation for Invitation {
    fn from_create(id: String, create: &CreateInvitation, now: DateTime<Utc>) -> Self {
        Invitation {
            id,
            organization_id: create.organization_id.clone(),
            email: create.email.clone(),
            role: create.role.clone(),
            status: InvitationStatus::Pending,
            inviter_id: create.inviter_id.clone(),
            expires_at: create.expires_at,
            created_at: now,
        }
    }

    fn set_status(&mut self, status: InvitationStatus) {
        self.status = status;
    }
}

// ─── Generic in-memory adapter ──────────────────────────────────────────

/// In-memory database adapter for testing and development.
///
/// Generic over entity types — use default type parameters for the built-in
/// types, or supply your own custom structs that implement the `Memory*`
/// traits.
///
/// ```rust,ignore
/// // Using built-in types (no turbofish needed):
/// let adapter = MemoryDatabaseAdapter::new();
///
/// // Using custom types:
/// let adapter = MemoryDatabaseAdapter::<MyUser, MySession, MyAccount,
///     MyOrg, MyMember, MyInvitation, MyVerification>::new();
/// ```
pub struct MemoryDatabaseAdapter<
    U = User,
    S = Session,
    A = Account,
    O = Organization,
    M = Member,
    I = Invitation,
    V = Verification,
> {
    users: Arc<Mutex<HashMap<String, U>>>,
    sessions: Arc<Mutex<HashMap<String, S>>>,
    accounts: Arc<Mutex<HashMap<String, A>>>,
    verifications: Arc<Mutex<HashMap<String, V>>>,
    email_index: Arc<Mutex<HashMap<String, String>>>,
    username_index: Arc<Mutex<HashMap<String, String>>>,
    organizations: Arc<Mutex<HashMap<String, O>>>,
    members: Arc<Mutex<HashMap<String, M>>>,
    invitations: Arc<Mutex<HashMap<String, I>>>,
    slug_index: Arc<Mutex<HashMap<String, String>>>,
}

/// Constructor for the default (built-in) entity types.
/// Use `Default::default()` for custom type parameterizations.
impl MemoryDatabaseAdapter {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<U, S, A, O, M, I, V> Default for MemoryDatabaseAdapter<U, S, A, O, M, I, V> {
    fn default() -> Self {
        Self {
            users: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            accounts: Arc::new(Mutex::new(HashMap::new())),
            verifications: Arc::new(Mutex::new(HashMap::new())),
            email_index: Arc::new(Mutex::new(HashMap::new())),
            username_index: Arc::new(Mutex::new(HashMap::new())),
            organizations: Arc::new(Mutex::new(HashMap::new())),
            members: Arc::new(Mutex::new(HashMap::new())),
            invitations: Arc::new(Mutex::new(HashMap::new())),
            slug_index: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl<U, S, A, O, M, I, V> DatabaseAdapter for MemoryDatabaseAdapter<U, S, A, O, M, I, V>
where
    U: MemoryUser,
    S: MemorySession,
    A: MemoryAccount,
    O: MemoryOrganization,
    M: MemoryMember,
    I: MemoryInvitation,
    V: MemoryVerification,
{
    type User = U;
    type Session = S;
    type Account = A;
    type Organization = O;
    type Member = M;
    type Invitation = I;
    type Verification = V;

    // ── User operations ──

    async fn create_user(&self, create_user: CreateUser) -> AuthResult<U> {
        let mut users = self.users.lock().unwrap();
        let mut email_index = self.email_index.lock().unwrap();
        let mut username_index = self.username_index.lock().unwrap();

        let id = create_user
            .id
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        if let Some(email) = &create_user.email
            && email_index.contains_key(email)
        {
            return Err(AuthError::config("Email already exists"));
        }

        if let Some(username) = &create_user.username
            && username_index.contains_key(username)
        {
            return Err(AuthError::conflict(
                "A user with this username already exists",
            ));
        }

        let now = Utc::now();
        let user = U::from_create(id.clone(), &create_user, now);

        users.insert(id.clone(), user.clone());

        if let Some(email) = &create_user.email {
            email_index.insert(email.clone(), id.clone());
        }
        if let Some(username) = &create_user.username {
            username_index.insert(username.clone(), id);
        }

        Ok(user)
    }

    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<U>> {
        let users = self.users.lock().unwrap();
        Ok(users.get(id).cloned())
    }

    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<U>> {
        let email_index = self.email_index.lock().unwrap();
        let users = self.users.lock().unwrap();

        if let Some(user_id) = email_index.get(email) {
            Ok(users.get(user_id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<U>> {
        let username_index = self.username_index.lock().unwrap();
        let users = self.users.lock().unwrap();

        if let Some(user_id) = username_index.get(username) {
            Ok(users.get(user_id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<U> {
        let mut users = self.users.lock().unwrap();
        let mut email_index = self.email_index.lock().unwrap();
        let mut username_index = self.username_index.lock().unwrap();

        let user = users.get_mut(id).ok_or(AuthError::UserNotFound)?;

        // Update indices BEFORE mutation (read old values via trait getters)
        if let Some(new_email) = &update.email {
            if let Some(old_email) = user.email() {
                email_index.remove(old_email);
            }
            email_index.insert(new_email.clone(), id.to_string());
        }

        if let Some(ref new_username) = update.username {
            if let Some(old_username) = user.username() {
                username_index.remove(old_username);
            }
            username_index.insert(new_username.clone(), id.to_string());
        }

        user.apply_update(&update);
        Ok(user.clone())
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        let mut users = self.users.lock().unwrap();
        let mut email_index = self.email_index.lock().unwrap();
        let mut username_index = self.username_index.lock().unwrap();

        if let Some(user) = users.remove(id) {
            if let Some(email) = user.email() {
                email_index.remove(email);
            }
            if let Some(username) = user.username() {
                username_index.remove(username);
            }
        }

        Ok(())
    }

    // ── Session operations ──

    async fn create_session(&self, create_session: CreateSession) -> AuthResult<S> {
        let mut sessions = self.sessions.lock().unwrap();

        let id = Uuid::new_v4().to_string();
        let token = format!("session_{}", Uuid::new_v4());
        let now = Utc::now();
        let session = S::from_create(id, token.clone(), &create_session, now);

        sessions.insert(token, session.clone());
        Ok(session)
    }

    async fn get_session(&self, token: &str) -> AuthResult<Option<S>> {
        let sessions = self.sessions.lock().unwrap();
        Ok(sessions.get(token).cloned())
    }

    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<S>> {
        let sessions = self.sessions.lock().unwrap();
        Ok(sessions
            .values()
            .filter(|s| s.user_id() == user_id && s.active())
            .cloned()
            .collect())
    }

    async fn update_session_expiry(
        &self,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<()> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(token) {
            session.set_expires_at(expires_at);
        }
        Ok(())
    }

    async fn delete_session(&self, token: &str) -> AuthResult<()> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(token);
        Ok(())
    }

    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, s| s.user_id() != user_id);
        Ok(())
    }

    async fn delete_expired_sessions(&self) -> AuthResult<usize> {
        let mut sessions = self.sessions.lock().unwrap();
        let now = Utc::now();
        let initial_count = sessions.len();
        sessions.retain(|_, s| s.expires_at() > now && s.active());
        Ok(initial_count - sessions.len())
    }

    // ── Account operations ──

    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<A> {
        let mut accounts = self.accounts.lock().unwrap();

        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let account = A::from_create(id.clone(), &create_account, now);

        accounts.insert(id, account.clone());
        Ok(account)
    }

    async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<A>> {
        let accounts = self.accounts.lock().unwrap();
        Ok(accounts
            .values()
            .find(|acc| acc.provider_id() == provider && acc.account_id() == provider_account_id)
            .cloned())
    }

    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<A>> {
        let accounts = self.accounts.lock().unwrap();
        Ok(accounts
            .values()
            .filter(|acc| acc.user_id() == user_id)
            .cloned()
            .collect())
    }

    async fn delete_account(&self, id: &str) -> AuthResult<()> {
        let mut accounts = self.accounts.lock().unwrap();
        accounts.remove(id);
        Ok(())
    }

    // ── Verification operations ──

    async fn create_verification(&self, create_verification: CreateVerification) -> AuthResult<V> {
        let mut verifications = self.verifications.lock().unwrap();

        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let verification = V::from_create(id.clone(), &create_verification, now);

        verifications.insert(id, verification.clone());
        Ok(verification)
    }

    async fn get_verification(&self, identifier: &str, value: &str) -> AuthResult<Option<V>> {
        let verifications = self.verifications.lock().unwrap();
        let now = Utc::now();
        Ok(verifications
            .values()
            .find(|v| v.identifier() == identifier && v.value() == value && v.expires_at() > now)
            .cloned())
    }

    async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<V>> {
        let verifications = self.verifications.lock().unwrap();
        let now = Utc::now();
        Ok(verifications
            .values()
            .find(|v| v.value() == value && v.expires_at() > now)
            .cloned())
    }

    async fn delete_verification(&self, id: &str) -> AuthResult<()> {
        let mut verifications = self.verifications.lock().unwrap();
        verifications.remove(id);
        Ok(())
    }

    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        let mut verifications = self.verifications.lock().unwrap();
        let now = Utc::now();
        let initial_count = verifications.len();
        verifications.retain(|_, v| v.expires_at() > now);
        Ok(initial_count - verifications.len())
    }

    // ── Organization operations ──

    async fn create_organization(&self, create_org: CreateOrganization) -> AuthResult<O> {
        let mut organizations = self.organizations.lock().unwrap();
        let mut slug_index = self.slug_index.lock().unwrap();

        if slug_index.contains_key(&create_org.slug) {
            return Err(AuthError::conflict("Organization slug already exists"));
        }

        let id = create_org
            .id
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let now = Utc::now();
        let organization = O::from_create(id.clone(), &create_org, now);

        organizations.insert(id.clone(), organization.clone());
        slug_index.insert(create_org.slug.clone(), id);

        Ok(organization)
    }

    async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<O>> {
        let organizations = self.organizations.lock().unwrap();
        Ok(organizations.get(id).cloned())
    }

    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<O>> {
        let slug_index = self.slug_index.lock().unwrap();
        let organizations = self.organizations.lock().unwrap();

        if let Some(org_id) = slug_index.get(slug) {
            Ok(organizations.get(org_id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn update_organization(&self, id: &str, update: UpdateOrganization) -> AuthResult<O> {
        let mut organizations = self.organizations.lock().unwrap();
        let mut slug_index = self.slug_index.lock().unwrap();

        let org = organizations
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Organization not found"))?;

        // Update slug index BEFORE mutation
        if let Some(new_slug) = &update.slug {
            let current_slug = org.slug().to_string();
            if *new_slug != current_slug {
                if slug_index.contains_key(new_slug.as_str()) {
                    return Err(AuthError::conflict("Organization slug already exists"));
                }
                slug_index.remove(&current_slug);
                slug_index.insert(new_slug.clone(), id.to_string());
            }
        }

        org.apply_update(&update);
        Ok(org.clone())
    }

    async fn delete_organization(&self, id: &str) -> AuthResult<()> {
        let mut organizations = self.organizations.lock().unwrap();
        let mut slug_index = self.slug_index.lock().unwrap();
        let mut members = self.members.lock().unwrap();
        let mut invitations = self.invitations.lock().unwrap();

        if let Some(org) = organizations.remove(id) {
            slug_index.remove(org.slug());
        }

        members.retain(|_, m| m.organization_id() != id);
        invitations.retain(|_, i| i.organization_id() != id);

        Ok(())
    }

    async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<O>> {
        let members = self.members.lock().unwrap();
        let organizations = self.organizations.lock().unwrap();

        let org_ids: Vec<String> = members
            .values()
            .filter(|m| m.user_id() == user_id)
            .map(|m| m.organization_id().to_string())
            .collect();

        let orgs = org_ids
            .iter()
            .filter_map(|id| organizations.get(id).cloned())
            .collect();

        Ok(orgs)
    }

    // ── Member operations ──

    async fn create_member(&self, create_member: CreateMember) -> AuthResult<M> {
        let mut members = self.members.lock().unwrap();

        let exists = members.values().any(|m| {
            m.organization_id() == create_member.organization_id
                && m.user_id() == create_member.user_id
        });

        if exists {
            return Err(AuthError::conflict(
                "User is already a member of this organization",
            ));
        }

        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let member = M::from_create(id.clone(), &create_member, now);

        members.insert(id, member.clone());
        Ok(member)
    }

    async fn get_member(&self, organization_id: &str, user_id: &str) -> AuthResult<Option<M>> {
        let members = self.members.lock().unwrap();
        Ok(members
            .values()
            .find(|m| m.organization_id() == organization_id && m.user_id() == user_id)
            .cloned())
    }

    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<M>> {
        let members = self.members.lock().unwrap();
        Ok(members.get(id).cloned())
    }

    async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<M> {
        let mut members = self.members.lock().unwrap();
        let member = members
            .get_mut(member_id)
            .ok_or_else(|| AuthError::not_found("Member not found"))?;
        member.set_role(role.to_string());
        Ok(member.clone())
    }

    async fn delete_member(&self, member_id: &str) -> AuthResult<()> {
        let mut members = self.members.lock().unwrap();
        members.remove(member_id);
        Ok(())
    }

    async fn list_organization_members(&self, organization_id: &str) -> AuthResult<Vec<M>> {
        let members = self.members.lock().unwrap();
        Ok(members
            .values()
            .filter(|m| m.organization_id() == organization_id)
            .cloned()
            .collect())
    }

    async fn count_organization_members(&self, organization_id: &str) -> AuthResult<usize> {
        let members = self.members.lock().unwrap();
        Ok(members
            .values()
            .filter(|m| m.organization_id() == organization_id)
            .count())
    }

    async fn count_organization_owners(&self, organization_id: &str) -> AuthResult<usize> {
        let members = self.members.lock().unwrap();
        Ok(members
            .values()
            .filter(|m| m.organization_id() == organization_id && m.role() == "owner")
            .count())
    }

    // ── Invitation operations ──

    async fn create_invitation(&self, create_inv: CreateInvitation) -> AuthResult<I> {
        let mut invitations = self.invitations.lock().unwrap();

        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let invitation = I::from_create(id.clone(), &create_inv, now);

        invitations.insert(id, invitation.clone());
        Ok(invitation)
    }

    async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<I>> {
        let invitations = self.invitations.lock().unwrap();
        Ok(invitations.get(id).cloned())
    }

    async fn get_pending_invitation(
        &self,
        organization_id: &str,
        email: &str,
    ) -> AuthResult<Option<I>> {
        let invitations = self.invitations.lock().unwrap();
        Ok(invitations
            .values()
            .find(|i| {
                i.organization_id() == organization_id
                    && i.email().to_lowercase() == email.to_lowercase()
                    && *i.status() == InvitationStatus::Pending
            })
            .cloned())
    }

    async fn update_invitation_status(&self, id: &str, status: InvitationStatus) -> AuthResult<I> {
        let mut invitations = self.invitations.lock().unwrap();
        let invitation = invitations
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Invitation not found"))?;
        invitation.set_status(status);
        Ok(invitation.clone())
    }

    async fn list_organization_invitations(&self, organization_id: &str) -> AuthResult<Vec<I>> {
        let invitations = self.invitations.lock().unwrap();
        Ok(invitations
            .values()
            .filter(|i| i.organization_id() == organization_id)
            .cloned()
            .collect())
    }

    async fn list_user_invitations(&self, email: &str) -> AuthResult<Vec<I>> {
        let invitations = self.invitations.lock().unwrap();
        let now = Utc::now();
        Ok(invitations
            .values()
            .filter(|i| {
                i.email().to_lowercase() == email.to_lowercase()
                    && *i.status() == InvitationStatus::Pending
                    && i.expires_at() > now
            })
            .cloned()
            .collect())
    }

    // ── Session–organization support ──

    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<S> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions.get_mut(token).ok_or(AuthError::SessionNotFound)?;
        session.set_active_organization_id(organization_id.map(|s| s.to_string()));
        session.set_updated_at(Utc::now());
        Ok(session.clone())
    }
}
