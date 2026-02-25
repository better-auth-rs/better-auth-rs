use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use crate::error::{AuthError, AuthResult};
use crate::types::{
    Account, ApiKey, CreateAccount, CreateApiKey, CreateInvitation, CreateMember,
    CreateOrganization, CreatePasskey, CreateSession, CreateTwoFactor, CreateUser,
    CreateVerification, Invitation, InvitationStatus, ListUsersParams, Member, Organization,
    Passkey, Session, TwoFactor, UpdateAccount, UpdateApiKey, UpdateOrganization, UpdateUser, User,
    Verification,
};

pub use super::memory_traits::{
    MemoryAccount, MemoryApiKey, MemoryInvitation, MemoryMember, MemoryOrganization, MemoryPasskey,
    MemorySession, MemoryTwoFactor, MemoryUser, MemoryVerification,
};

use super::traits::{
    AccountOps, ApiKeyOps, InvitationOps, MemberOps, OrganizationOps, PasskeyOps, SessionOps,
    TwoFactorOps, UserOps, VerificationOps,
};

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
    P = Passkey,
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
    two_factors: Arc<Mutex<HashMap<String, TwoFactor>>>,
    api_keys: Arc<Mutex<HashMap<String, ApiKey>>>,
    passkeys: Arc<Mutex<HashMap<String, P>>>,
    passkey_credential_index: Arc<Mutex<HashMap<String, String>>>,
}

/// Constructor for the default (built-in) entity types.
/// Use `Default::default()` for custom type parameterizations.
impl MemoryDatabaseAdapter {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<U, S, A, O, M, I, V, P> Default for MemoryDatabaseAdapter<U, S, A, O, M, I, V, P> {
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
            two_factors: Arc::new(Mutex::new(HashMap::new())),
            api_keys: Arc::new(Mutex::new(HashMap::new())),
            passkeys: Arc::new(Mutex::new(HashMap::new())),
            passkey_credential_index: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

// -- UserOps --

#[async_trait]
impl<U, S, A, O, M, I, V, P> UserOps for MemoryDatabaseAdapter<U, S, A, O, M, I, V, P>
where
    U: MemoryUser,
    S: MemorySession,
    A: MemoryAccount,
    O: MemoryOrganization,
    M: MemoryMember,
    I: MemoryInvitation,
    V: MemoryVerification,
    P: MemoryPasskey,
{
    type User = U;

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

    async fn list_users(&self, params: ListUsersParams) -> AuthResult<(Vec<U>, usize)> {
        let users = self.users.lock().unwrap();
        let mut result: Vec<U> = users.values().cloned().collect();

        // Apply search filter
        if let Some(search_value) = &params.search_value {
            let field = params.search_field.as_deref().unwrap_or("email");
            let op = params.search_operator.as_deref().unwrap_or("contains");
            let sv = search_value.to_lowercase();
            result.retain(|u| {
                let field_val = match field {
                    "name" => u.name().unwrap_or("").to_lowercase(),
                    _ => u.email().unwrap_or("").to_lowercase(),
                };
                match op {
                    "starts_with" => field_val.starts_with(&sv),
                    "ends_with" => field_val.ends_with(&sv),
                    _ => field_val.contains(&sv),
                }
            });
        }

        // Apply filter
        if let Some(filter_value) = &params.filter_value {
            let field = params.filter_field.as_deref().unwrap_or("email");
            let op = params.filter_operator.as_deref().unwrap_or("eq");
            let fv = filter_value.to_lowercase();
            result.retain(|u| {
                let field_val = match field {
                    "name" => u.name().unwrap_or("").to_lowercase(),
                    "role" => u.role().unwrap_or("").to_lowercase(),
                    _ => u.email().unwrap_or("").to_lowercase(),
                };
                match op {
                    "contains" => field_val.contains(&fv),
                    "starts_with" => field_val.starts_with(&fv),
                    "ends_with" => field_val.ends_with(&fv),
                    "ne" => field_val != fv,
                    _ => field_val == fv,
                }
            });
        }

        // Apply sort
        if let Some(sort_by) = &params.sort_by {
            let desc = params.sort_direction.as_deref() == Some("desc");
            result.sort_by(|a, b| {
                let av = match sort_by.as_str() {
                    "name" => a.name().unwrap_or("").to_string(),
                    "createdAt" => a.created_at().to_rfc3339(),
                    _ => a.email().unwrap_or("").to_string(),
                };
                let bv = match sort_by.as_str() {
                    "name" => b.name().unwrap_or("").to_string(),
                    "createdAt" => b.created_at().to_rfc3339(),
                    _ => b.email().unwrap_or("").to_string(),
                };
                if desc { bv.cmp(&av) } else { av.cmp(&bv) }
            });
        }

        let total = result.len();
        let offset = params.offset.unwrap_or(0);
        let limit = params.limit.unwrap_or(100);
        let paged: Vec<U> = result.into_iter().skip(offset).take(limit).collect();

        Ok((paged, total))
    }
}

// -- SessionOps --

#[async_trait]
impl<U, S, A, O, M, I, V, P> SessionOps for MemoryDatabaseAdapter<U, S, A, O, M, I, V, P>
where
    U: MemoryUser,
    S: MemorySession,
    A: MemoryAccount,
    O: MemoryOrganization,
    M: MemoryMember,
    I: MemoryInvitation,
    V: MemoryVerification,
    P: MemoryPasskey,
{
    type Session = S;

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

// -- AccountOps --

#[async_trait]
impl<U, S, A, O, M, I, V, P> AccountOps for MemoryDatabaseAdapter<U, S, A, O, M, I, V, P>
where
    U: MemoryUser,
    S: MemorySession,
    A: MemoryAccount,
    O: MemoryOrganization,
    M: MemoryMember,
    I: MemoryInvitation,
    V: MemoryVerification,
    P: MemoryPasskey,
{
    type Account = A;

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

    async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<A> {
        let mut accounts = self.accounts.lock().unwrap();
        let account = accounts
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Account not found"))?;
        account.apply_update(&update);
        Ok(account.clone())
    }

    async fn delete_account(&self, id: &str) -> AuthResult<()> {
        let mut accounts = self.accounts.lock().unwrap();
        accounts.remove(id);
        Ok(())
    }
}

// -- VerificationOps --

#[async_trait]
impl<U, S, A, O, M, I, V, P> VerificationOps for MemoryDatabaseAdapter<U, S, A, O, M, I, V, P>
where
    U: MemoryUser,
    S: MemorySession,
    A: MemoryAccount,
    O: MemoryOrganization,
    M: MemoryMember,
    I: MemoryInvitation,
    V: MemoryVerification,
    P: MemoryPasskey,
{
    type Verification = V;

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

    async fn get_verification_by_identifier(&self, identifier: &str) -> AuthResult<Option<V>> {
        let verifications = self.verifications.lock().unwrap();
        let now = Utc::now();
        Ok(verifications
            .values()
            .find(|v| v.identifier() == identifier && v.expires_at() > now)
            .cloned())
    }

    async fn consume_verification(&self, identifier: &str, value: &str) -> AuthResult<Option<V>> {
        let mut verifications = self.verifications.lock().unwrap();
        let now = Utc::now();

        let matched_id = verifications
            .iter()
            .filter_map(|(id, verification)| {
                if verification.identifier() == identifier
                    && verification.value() == value
                    && verification.expires_at() > now
                {
                    Some((id, verification.created_at()))
                } else {
                    None
                }
            })
            .max_by_key(|(_, created_at)| *created_at)
            .map(|(id, _)| id.clone());

        if let Some(id) = matched_id {
            Ok(verifications.remove(&id))
        } else {
            Ok(None)
        }
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
}

// -- OrganizationOps --

#[async_trait]
impl<U, S, A, O, M, I, V, P> OrganizationOps for MemoryDatabaseAdapter<U, S, A, O, M, I, V, P>
where
    U: MemoryUser,
    S: MemorySession,
    A: MemoryAccount,
    O: MemoryOrganization,
    M: MemoryMember,
    I: MemoryInvitation,
    V: MemoryVerification,
    P: MemoryPasskey,
{
    type Organization = O;

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
}

// -- MemberOps --

#[async_trait]
impl<U, S, A, O, M, I, V, P> MemberOps for MemoryDatabaseAdapter<U, S, A, O, M, I, V, P>
where
    U: MemoryUser,
    S: MemorySession,
    A: MemoryAccount,
    O: MemoryOrganization,
    M: MemoryMember,
    I: MemoryInvitation,
    V: MemoryVerification,
    P: MemoryPasskey,
{
    type Member = M;

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
}

// -- InvitationOps --

#[async_trait]
impl<U, S, A, O, M, I, V, P> InvitationOps for MemoryDatabaseAdapter<U, S, A, O, M, I, V, P>
where
    U: MemoryUser,
    S: MemorySession,
    A: MemoryAccount,
    O: MemoryOrganization,
    M: MemoryMember,
    I: MemoryInvitation,
    V: MemoryVerification,
    P: MemoryPasskey,
{
    type Invitation = I;

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
}

// -- TwoFactorOps --

#[async_trait]
impl<U, S, A, O, M, I, V, P> TwoFactorOps for MemoryDatabaseAdapter<U, S, A, O, M, I, V, P>
where
    U: MemoryUser,
    S: MemorySession,
    A: MemoryAccount,
    O: MemoryOrganization,
    M: MemoryMember,
    I: MemoryInvitation,
    V: MemoryVerification,
    P: MemoryPasskey,
{
    type TwoFactor = TwoFactor;

    async fn create_two_factor(&self, create: CreateTwoFactor) -> AuthResult<TwoFactor> {
        let mut two_factors = self.two_factors.lock().unwrap();

        // Check if user already has 2FA
        if two_factors.values().any(|tf| tf.user_id == create.user_id) {
            return Err(AuthError::conflict(
                "Two-factor authentication already enabled for this user",
            ));
        }

        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let two_factor: TwoFactor = MemoryTwoFactor::from_create(id.clone(), &create, now);

        two_factors.insert(id, two_factor.clone());
        Ok(two_factor)
    }

    async fn get_two_factor_by_user_id(&self, user_id: &str) -> AuthResult<Option<TwoFactor>> {
        let two_factors = self.two_factors.lock().unwrap();
        Ok(two_factors
            .values()
            .find(|tf| tf.user_id == user_id)
            .cloned())
    }

    async fn update_two_factor_backup_codes(
        &self,
        user_id: &str,
        backup_codes: &str,
    ) -> AuthResult<TwoFactor> {
        let mut two_factors = self.two_factors.lock().unwrap();
        let two_factor = two_factors
            .values_mut()
            .find(|tf| tf.user_id == user_id)
            .ok_or_else(|| AuthError::not_found("Two-factor record not found"))?;
        two_factor.set_backup_codes(backup_codes.to_string());
        Ok(two_factor.clone())
    }

    async fn delete_two_factor(&self, user_id: &str) -> AuthResult<()> {
        let mut two_factors = self.two_factors.lock().unwrap();
        two_factors.retain(|_, tf| tf.user_id != user_id);
        Ok(())
    }
}

// -- ApiKeyOps --

#[async_trait]
impl<U, S, A, O, M, I, V, P> ApiKeyOps for MemoryDatabaseAdapter<U, S, A, O, M, I, V, P>
where
    U: MemoryUser,
    S: MemorySession,
    A: MemoryAccount,
    O: MemoryOrganization,
    M: MemoryMember,
    I: MemoryInvitation,
    V: MemoryVerification,
    P: MemoryPasskey,
{
    type ApiKey = ApiKey;

    async fn create_api_key(&self, input: CreateApiKey) -> AuthResult<ApiKey> {
        let mut api_keys = self.api_keys.lock().unwrap();

        if api_keys.values().any(|k| k.key_hash == input.key_hash) {
            return Err(AuthError::conflict("API key already exists"));
        }

        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let api_key: ApiKey = MemoryApiKey::from_create(id.clone(), &input, now);

        api_keys.insert(id, api_key.clone());
        Ok(api_key)
    }

    async fn get_api_key_by_id(&self, id: &str) -> AuthResult<Option<ApiKey>> {
        let api_keys = self.api_keys.lock().unwrap();
        Ok(api_keys.get(id).cloned())
    }

    async fn get_api_key_by_hash(&self, hash: &str) -> AuthResult<Option<ApiKey>> {
        let api_keys = self.api_keys.lock().unwrap();
        Ok(api_keys.values().find(|k| k.key_hash == hash).cloned())
    }

    async fn list_api_keys_by_user(&self, user_id: &str) -> AuthResult<Vec<ApiKey>> {
        let api_keys = self.api_keys.lock().unwrap();
        let mut keys: Vec<ApiKey> = api_keys
            .values()
            .filter(|k| k.user_id == user_id)
            .cloned()
            .collect();
        keys.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(keys)
    }

    async fn update_api_key(&self, id: &str, update: UpdateApiKey) -> AuthResult<ApiKey> {
        let mut api_keys = self.api_keys.lock().unwrap();
        let api_key = api_keys
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("API key not found"))?;
        api_key.apply_update(&update);
        Ok(api_key.clone())
    }

    async fn delete_api_key(&self, id: &str) -> AuthResult<()> {
        let mut api_keys = self.api_keys.lock().unwrap();
        api_keys.remove(id);
        Ok(())
    }
}

// -- PasskeyOps --

#[async_trait]
impl<U, S, A, O, M, I, V, P> PasskeyOps for MemoryDatabaseAdapter<U, S, A, O, M, I, V, P>
where
    U: MemoryUser,
    S: MemorySession,
    A: MemoryAccount,
    O: MemoryOrganization,
    M: MemoryMember,
    I: MemoryInvitation,
    V: MemoryVerification,
    P: MemoryPasskey,
{
    type Passkey = P;

    async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<P> {
        let mut credential_index = self.passkey_credential_index.lock().unwrap();
        let mut passkeys = self.passkeys.lock().unwrap();

        if credential_index.contains_key(&input.credential_id) {
            return Err(AuthError::conflict(
                "A passkey with this credential ID already exists",
            ));
        }

        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let passkey = P::from_create(id.clone(), &input, now);

        credential_index.insert(input.credential_id.clone(), id.clone());
        passkeys.insert(id, passkey.clone());
        Ok(passkey)
    }

    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<P>> {
        let passkeys = self.passkeys.lock().unwrap();
        Ok(passkeys.get(id).cloned())
    }

    async fn get_passkey_by_credential_id(&self, credential_id: &str) -> AuthResult<Option<P>> {
        let passkey_id = {
            let credential_index = self.passkey_credential_index.lock().unwrap();
            credential_index.get(credential_id).cloned()
        };

        let passkeys = self.passkeys.lock().unwrap();

        if let Some(id) = passkey_id {
            Ok(passkeys.get(&id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<P>> {
        let passkeys = self.passkeys.lock().unwrap();
        let mut matched: Vec<P> = passkeys
            .values()
            .filter(|p| p.user_id() == user_id)
            .cloned()
            .collect();
        matched.sort_by_key(|p| std::cmp::Reverse(p.created_at()));
        Ok(matched)
    }

    async fn update_passkey_counter(&self, id: &str, counter: u64) -> AuthResult<P> {
        let mut passkeys = self.passkeys.lock().unwrap();
        let passkey = passkeys
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Passkey not found"))?;
        passkey.set_counter(counter);
        Ok(passkey.clone())
    }

    async fn update_passkey_name(&self, id: &str, name: &str) -> AuthResult<P> {
        let mut passkeys = self.passkeys.lock().unwrap();
        let passkey = passkeys
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Passkey not found"))?;
        passkey.set_name(name.to_string());
        Ok(passkey.clone())
    }

    async fn delete_passkey(&self, id: &str) -> AuthResult<()> {
        let mut credential_index = self.passkey_credential_index.lock().unwrap();
        let mut passkeys = self.passkeys.lock().unwrap();

        if let Some(passkey) = passkeys.remove(id) {
            credential_index.remove(passkey.credential_id());
        }
        Ok(())
    }
}
