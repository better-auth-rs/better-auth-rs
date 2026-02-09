use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use crate::error::{AuthError, AuthResult};
use crate::types::{
    Account, CreateAccount, CreateInvitation, CreateMember, CreateOrganization, CreateSession,
    CreateUser, CreateVerification, Invitation, InvitationStatus, Member, MemberUser,
    MemberWithUser, Organization, Session, UpdateOrganization, UpdateUser, User, Verification,
};

/// Database adapter trait for persistence
#[async_trait]
pub trait DatabaseAdapter: Send + Sync {
    // User operations
    async fn create_user(&self, user: CreateUser) -> AuthResult<User>;
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<User>>;
    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<User>>;
    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<User>>;
    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<User>;
    async fn delete_user(&self, id: &str) -> AuthResult<()>;

    // Session operations
    async fn create_session(&self, session: CreateSession) -> AuthResult<Session>;
    async fn get_session(&self, token: &str) -> AuthResult<Option<Session>>;
    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<Session>>;
    async fn update_session_expiry(&self, token: &str, expires_at: DateTime<Utc>)
    -> AuthResult<()>;
    async fn delete_session(&self, token: &str) -> AuthResult<()>;
    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()>;
    async fn delete_expired_sessions(&self) -> AuthResult<usize>;

    // Account operations (for OAuth)
    async fn create_account(&self, account: CreateAccount) -> AuthResult<Account>;
    async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<Account>>;
    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<Account>>;
    async fn delete_account(&self, id: &str) -> AuthResult<()>;

    // Verification token operations
    async fn create_verification(
        &self,
        verification: CreateVerification,
    ) -> AuthResult<Verification>;
    async fn get_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<Verification>>;
    async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<Verification>>;
    async fn delete_verification(&self, id: &str) -> AuthResult<()>;
    async fn delete_expired_verifications(&self) -> AuthResult<usize>;

    // Organization operations
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

    // Member operations
    async fn create_member(&self, member: CreateMember) -> AuthResult<Member>;
    async fn get_member(&self, organization_id: &str, user_id: &str) -> AuthResult<Option<Member>>;
    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<MemberWithUser>>;
    async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<Member>;
    async fn delete_member(&self, member_id: &str) -> AuthResult<()>;
    async fn list_organization_members(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<MemberWithUser>>;
    async fn count_organization_members(&self, organization_id: &str) -> AuthResult<usize>;
    async fn count_organization_owners(&self, organization_id: &str) -> AuthResult<usize>;

    // Invitation operations
    async fn create_invitation(&self, invitation: CreateInvitation) -> AuthResult<Invitation>;
    async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<Invitation>>;
    async fn get_pending_invitation(
        &self,
        organization_id: &str,
        email: &str,
    ) -> AuthResult<Option<Invitation>>;
    async fn update_invitation_status(
        &self,
        id: &str,
        status: InvitationStatus,
    ) -> AuthResult<Invitation>;
    async fn list_organization_invitations(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<Invitation>>;
    async fn list_user_invitations(&self, email: &str) -> AuthResult<Vec<Invitation>>;

    // Session organization support
    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<Session>;
}

/// In-memory database adapter for testing and development
pub struct MemoryDatabaseAdapter {
    users: Arc<Mutex<HashMap<String, User>>>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    accounts: Arc<Mutex<HashMap<String, Account>>>,
    verifications: Arc<Mutex<HashMap<String, Verification>>>,
    email_index: Arc<Mutex<HashMap<String, String>>>, // email -> user_id
    username_index: Arc<Mutex<HashMap<String, String>>>, // username -> user_id
    // Organization data
    organizations: Arc<Mutex<HashMap<String, Organization>>>,
    members: Arc<Mutex<HashMap<String, Member>>>,
    invitations: Arc<Mutex<HashMap<String, Invitation>>>,
    slug_index: Arc<Mutex<HashMap<String, String>>>, // slug -> organization_id
}

impl MemoryDatabaseAdapter {
    pub fn new() -> Self {
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

impl Default for MemoryDatabaseAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DatabaseAdapter for MemoryDatabaseAdapter {
    async fn create_user(&self, create_user: CreateUser) -> AuthResult<User> {
        let mut users = self.users.lock().unwrap();
        let mut email_index = self.email_index.lock().unwrap();
        let mut username_index = self.username_index.lock().unwrap();

        let id = create_user.id.unwrap_or_else(|| Uuid::new_v4().to_string());

        // Check if email already exists
        if let Some(email) = &create_user.email
            && email_index.contains_key(email)
        {
            return Err(AuthError::config("Email already exists"));
        }

        // Check if username already exists
        if let Some(username) = &create_user.username
            && username_index.contains_key(username)
        {
            return Err(AuthError::conflict(
                "A user with this username already exists",
            ));
        }

        let now = Utc::now();
        let user = User {
            id: id.clone(),
            name: create_user.name,
            email: create_user.email.clone(),
            email_verified: create_user.email_verified.unwrap_or(false),
            image: create_user.image,
            created_at: now,
            updated_at: now,
            username: create_user.username.clone(),
            display_username: create_user.display_username,
            two_factor_enabled: false,
            role: create_user.role,
            banned: false,
            ban_reason: None,
            ban_expires: None,
            metadata: create_user.metadata.unwrap_or_default(),
        };

        users.insert(id.clone(), user.clone());

        if let Some(email) = &create_user.email {
            email_index.insert(email.clone(), id.clone());
        }

        if let Some(username) = &create_user.username {
            username_index.insert(username.clone(), id);
        }

        Ok(user)
    }

    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<User>> {
        let users = self.users.lock().unwrap();
        Ok(users.get(id).cloned())
    }

    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<User>> {
        let email_index = self.email_index.lock().unwrap();
        let users = self.users.lock().unwrap();

        if let Some(user_id) = email_index.get(email) {
            Ok(users.get(user_id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<User>> {
        let username_index = self.username_index.lock().unwrap();
        let users = self.users.lock().unwrap();

        if let Some(user_id) = username_index.get(username) {
            Ok(users.get(user_id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<User> {
        let mut users = self.users.lock().unwrap();
        let mut email_index = self.email_index.lock().unwrap();
        let mut username_index = self.username_index.lock().unwrap();

        let user = users.get_mut(id).ok_or(AuthError::UserNotFound)?;

        // Update email index if email changed
        if let Some(new_email) = &update.email {
            if let Some(old_email) = &user.email {
                email_index.remove(old_email);
            }
            email_index.insert(new_email.clone(), id.to_string());
            user.email = Some(new_email.clone());
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

        if let Some(ref username) = update.username {
            // Update username index
            if let Some(old_username) = &user.username {
                username_index.remove(old_username);
            }
            username_index.insert(username.clone(), id.to_string());
            user.username = Some(username.clone());
        }

        if let Some(display_username) = update.display_username {
            user.display_username = Some(display_username);
        }

        if let Some(role) = update.role {
            user.role = Some(role);
        }

        if let Some(banned) = update.banned {
            user.banned = banned;
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
        let mut users = self.users.lock().unwrap();
        let mut email_index = self.email_index.lock().unwrap();
        let mut username_index = self.username_index.lock().unwrap();

        if let Some(user) = users.remove(id) {
            if let Some(email) = &user.email {
                email_index.remove(email);
            }
            if let Some(username) = &user.username {
                username_index.remove(username);
            }
        }

        Ok(())
    }

    async fn create_session(&self, create_session: CreateSession) -> AuthResult<Session> {
        let mut sessions = self.sessions.lock().unwrap();

        let token = format!("session_{}", Uuid::new_v4());
        let now = Utc::now();
        let session = Session {
            id: Uuid::new_v4().to_string(),
            expires_at: create_session.expires_at,
            token: token.clone(),
            created_at: now,
            updated_at: now,
            ip_address: create_session.ip_address,
            user_agent: create_session.user_agent,
            user_id: create_session.user_id,
            impersonated_by: create_session.impersonated_by,
            active_organization_id: create_session.active_organization_id,
            active: true,
        };

        sessions.insert(token, session.clone());
        Ok(session)
    }

    async fn get_session(&self, token: &str) -> AuthResult<Option<Session>> {
        let sessions = self.sessions.lock().unwrap();
        Ok(sessions.get(token).cloned())
    }

    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<Session>> {
        let sessions = self.sessions.lock().unwrap();
        Ok(sessions
            .values()
            .filter(|session| session.user_id == user_id && session.active)
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
            session.expires_at = expires_at;
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
        sessions.retain(|_, session| session.user_id != user_id);
        Ok(())
    }

    async fn delete_expired_sessions(&self) -> AuthResult<usize> {
        let mut sessions = self.sessions.lock().unwrap();
        let now = Utc::now();
        let initial_count = sessions.len();

        sessions.retain(|_, session| session.expires_at > now && session.active);

        Ok(initial_count - sessions.len())
    }

    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<Account> {
        let mut accounts = self.accounts.lock().unwrap();

        let now = Utc::now();
        let account = Account {
            id: Uuid::new_v4().to_string(),
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

        accounts.insert(account.id.clone(), account.clone());
        Ok(account)
    }

    async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<Account>> {
        let accounts = self.accounts.lock().unwrap();
        Ok(accounts
            .values()
            .find(|acc| acc.provider_id == provider && acc.account_id == provider_account_id)
            .cloned())
    }

    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<Account>> {
        let accounts = self.accounts.lock().unwrap();
        Ok(accounts
            .values()
            .filter(|acc| acc.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn delete_account(&self, id: &str) -> AuthResult<()> {
        let mut accounts = self.accounts.lock().unwrap();
        accounts.remove(id);
        Ok(())
    }

    async fn create_verification(
        &self,
        create_verification: CreateVerification,
    ) -> AuthResult<Verification> {
        let mut verifications = self.verifications.lock().unwrap();

        let now = Utc::now();
        let verification = Verification {
            id: Uuid::new_v4().to_string(),
            identifier: create_verification.identifier,
            value: create_verification.value.clone(),
            expires_at: create_verification.expires_at,
            created_at: now,
            updated_at: now,
        };

        verifications.insert(verification.id.clone(), verification.clone());
        Ok(verification)
    }

    async fn get_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<Verification>> {
        let verifications = self.verifications.lock().unwrap();
        let now = Utc::now();

        Ok(verifications
            .values()
            .find(|v| v.identifier == identifier && v.value == value && v.expires_at > now)
            .cloned())
    }

    async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<Verification>> {
        let verifications = self.verifications.lock().unwrap();
        let now = Utc::now();

        Ok(verifications
            .values()
            .find(|v| v.value == value && v.expires_at > now)
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

        verifications.retain(|_, verification| verification.expires_at > now);

        Ok(initial_count - verifications.len())
    }

    // Organization operations
    async fn create_organization(
        &self,
        create_org: CreateOrganization,
    ) -> AuthResult<Organization> {
        let mut organizations = self.organizations.lock().unwrap();
        let mut slug_index = self.slug_index.lock().unwrap();

        // Check if slug already exists
        if slug_index.contains_key(&create_org.slug) {
            return Err(AuthError::conflict("Organization slug already exists"));
        }

        let id = create_org.id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let now = Utc::now();

        let organization = Organization {
            id: id.clone(),
            name: create_org.name,
            slug: create_org.slug.clone(),
            logo: create_org.logo,
            metadata: create_org.metadata,
            created_at: now,
            updated_at: now,
        };

        organizations.insert(id.clone(), organization.clone());
        slug_index.insert(create_org.slug, id);

        Ok(organization)
    }

    async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<Organization>> {
        let organizations = self.organizations.lock().unwrap();
        Ok(organizations.get(id).cloned())
    }

    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Organization>> {
        let slug_index = self.slug_index.lock().unwrap();
        let organizations = self.organizations.lock().unwrap();

        if let Some(org_id) = slug_index.get(slug) {
            Ok(organizations.get(org_id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn update_organization(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Organization> {
        let mut organizations = self.organizations.lock().unwrap();
        let mut slug_index = self.slug_index.lock().unwrap();

        let org = organizations
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Organization not found"))?;

        // Update slug index if slug changed
        if let Some(new_slug) = &update.slug
            && new_slug != &org.slug
        {
            // Check if new slug already exists
            if slug_index.contains_key(new_slug) {
                return Err(AuthError::conflict("Organization slug already exists"));
            }
            slug_index.remove(&org.slug);
            slug_index.insert(new_slug.clone(), id.to_string());
            org.slug = new_slug.clone();
        }

        if let Some(name) = update.name {
            org.name = name;
        }
        if let Some(logo) = update.logo {
            org.logo = Some(logo);
        }
        if let Some(metadata) = update.metadata {
            org.metadata = Some(metadata);
        }

        org.updated_at = Utc::now();

        Ok(org.clone())
    }

    async fn delete_organization(&self, id: &str) -> AuthResult<()> {
        let mut organizations = self.organizations.lock().unwrap();
        let mut slug_index = self.slug_index.lock().unwrap();
        let mut members = self.members.lock().unwrap();
        let mut invitations = self.invitations.lock().unwrap();

        if let Some(org) = organizations.remove(id) {
            slug_index.remove(&org.slug);
        }

        // Delete all related members and invitations
        members.retain(|_, m| m.organization_id != id);
        invitations.retain(|_, i| i.organization_id != id);

        Ok(())
    }

    async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<Organization>> {
        let members = self.members.lock().unwrap();
        let organizations = self.organizations.lock().unwrap();

        let org_ids: Vec<String> = members
            .values()
            .filter(|m| m.user_id == user_id)
            .map(|m| m.organization_id.clone())
            .collect();

        let orgs = org_ids
            .iter()
            .filter_map(|id| organizations.get(id).cloned())
            .collect();

        Ok(orgs)
    }

    // Member operations
    async fn create_member(&self, create_member: CreateMember) -> AuthResult<Member> {
        let mut members = self.members.lock().unwrap();

        // Check if member already exists
        let exists = members.values().any(|m| {
            m.organization_id == create_member.organization_id && m.user_id == create_member.user_id
        });

        if exists {
            return Err(AuthError::conflict(
                "User is already a member of this organization",
            ));
        }

        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let member = Member {
            id: id.clone(),
            organization_id: create_member.organization_id,
            user_id: create_member.user_id,
            role: create_member.role,
            created_at: now,
        };

        members.insert(id, member.clone());

        Ok(member)
    }

    async fn get_member(&self, organization_id: &str, user_id: &str) -> AuthResult<Option<Member>> {
        let members = self.members.lock().unwrap();

        let member = members
            .values()
            .find(|m| m.organization_id == organization_id && m.user_id == user_id)
            .cloned();

        Ok(member)
    }

    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<MemberWithUser>> {
        let members = self.members.lock().unwrap();
        let users = self.users.lock().unwrap();

        if let Some(member) = members.get(id)
            && let Some(user) = users.get(&member.user_id)
        {
            return Ok(Some(MemberWithUser {
                id: member.id.clone(),
                organization_id: member.organization_id.clone(),
                user_id: member.user_id.clone(),
                role: member.role.clone(),
                created_at: member.created_at,
                user: MemberUser {
                    id: user.id.clone(),
                    email: user.email.clone(),
                    name: user.name.clone(),
                    image: user.image.clone(),
                },
            }));
        }

        Ok(None)
    }

    async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<Member> {
        let mut members = self.members.lock().unwrap();

        let member = members
            .get_mut(member_id)
            .ok_or_else(|| AuthError::not_found("Member not found"))?;

        member.role = role.to_string();

        Ok(member.clone())
    }

    async fn delete_member(&self, member_id: &str) -> AuthResult<()> {
        let mut members = self.members.lock().unwrap();
        members.remove(member_id);
        Ok(())
    }

    async fn list_organization_members(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<MemberWithUser>> {
        let members = self.members.lock().unwrap();
        let users = self.users.lock().unwrap();

        let members_with_users = members
            .values()
            .filter(|m| m.organization_id == organization_id)
            .filter_map(|member| {
                users.get(&member.user_id).map(|user| MemberWithUser {
                    id: member.id.clone(),
                    organization_id: member.organization_id.clone(),
                    user_id: member.user_id.clone(),
                    role: member.role.clone(),
                    created_at: member.created_at,
                    user: MemberUser {
                        id: user.id.clone(),
                        email: user.email.clone(),
                        name: user.name.clone(),
                        image: user.image.clone(),
                    },
                })
            })
            .collect();

        Ok(members_with_users)
    }

    async fn count_organization_members(&self, organization_id: &str) -> AuthResult<usize> {
        let members = self.members.lock().unwrap();
        let count = members
            .values()
            .filter(|m| m.organization_id == organization_id)
            .count();
        Ok(count)
    }

    async fn count_organization_owners(&self, organization_id: &str) -> AuthResult<usize> {
        let members = self.members.lock().unwrap();
        let count = members
            .values()
            .filter(|m| m.organization_id == organization_id && m.role == "owner")
            .count();
        Ok(count)
    }

    // Invitation operations
    async fn create_invitation(&self, create_inv: CreateInvitation) -> AuthResult<Invitation> {
        let mut invitations = self.invitations.lock().unwrap();

        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let invitation = Invitation {
            id: id.clone(),
            organization_id: create_inv.organization_id,
            email: create_inv.email,
            role: create_inv.role,
            status: InvitationStatus::Pending,
            inviter_id: create_inv.inviter_id,
            expires_at: create_inv.expires_at,
            created_at: now,
        };

        invitations.insert(id, invitation.clone());

        Ok(invitation)
    }

    async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<Invitation>> {
        let invitations = self.invitations.lock().unwrap();
        Ok(invitations.get(id).cloned())
    }

    async fn get_pending_invitation(
        &self,
        organization_id: &str,
        email: &str,
    ) -> AuthResult<Option<Invitation>> {
        let invitations = self.invitations.lock().unwrap();

        let invitation = invitations
            .values()
            .find(|i| {
                i.organization_id == organization_id
                    && i.email.to_lowercase() == email.to_lowercase()
                    && i.status == InvitationStatus::Pending
            })
            .cloned();

        Ok(invitation)
    }

    async fn update_invitation_status(
        &self,
        id: &str,
        status: InvitationStatus,
    ) -> AuthResult<Invitation> {
        let mut invitations = self.invitations.lock().unwrap();

        let invitation = invitations
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Invitation not found"))?;

        invitation.status = status;

        Ok(invitation.clone())
    }

    async fn list_organization_invitations(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<Invitation>> {
        let invitations = self.invitations.lock().unwrap();

        let org_invitations = invitations
            .values()
            .filter(|i| i.organization_id == organization_id)
            .cloned()
            .collect();

        Ok(org_invitations)
    }

    async fn list_user_invitations(&self, email: &str) -> AuthResult<Vec<Invitation>> {
        let invitations = self.invitations.lock().unwrap();
        let now = Utc::now();

        let user_invitations = invitations
            .values()
            .filter(|i| {
                i.email.to_lowercase() == email.to_lowercase()
                    && i.status == InvitationStatus::Pending
                    && i.expires_at > now
            })
            .cloned()
            .collect();

        Ok(user_invitations)
    }

    // Session organization support
    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<Session> {
        let mut sessions = self.sessions.lock().unwrap();

        let session = sessions.get_mut(token).ok_or(AuthError::SessionNotFound)?;

        session.active_organization_id = organization_id.map(|s| s.to_string());
        session.updated_at = Utc::now();

        Ok(session.clone())
    }
}

#[cfg(feature = "sqlx-postgres")]
pub mod sqlx_adapter {
    use super::*;
    use sqlx::PgPool;

    pub struct SqlxAdapter {
        pool: PgPool,
    }

    impl SqlxAdapter {
        pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
            let pool = PgPool::connect(database_url).await?;
            Ok(Self { pool })
        }

        /// Create adapter with custom pool configuration
        pub async fn with_config(
            database_url: &str,
            config: PoolConfig,
        ) -> Result<Self, sqlx::Error> {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(config.max_connections)
                .min_connections(config.min_connections)
                .acquire_timeout(config.acquire_timeout)
                .idle_timeout(config.idle_timeout)
                .max_lifetime(config.max_lifetime)
                .connect(database_url)
                .await?;
            Ok(Self { pool })
        }

        pub fn from_pool(pool: PgPool) -> Self {
            Self { pool }
        }

        /// Test database connection
        pub async fn test_connection(&self) -> Result<(), sqlx::Error> {
            sqlx::query("SELECT 1").execute(&self.pool).await?;
            Ok(())
        }

        /// Get connection pool statistics
        pub fn pool_stats(&self) -> PoolStats {
            PoolStats {
                size: self.pool.size(),
                idle: self.pool.num_idle(),
            }
        }

        /// Close the connection pool
        pub async fn close(&self) {
            self.pool.close().await;
        }
    }

    /// Database connection pool configuration
    #[derive(Debug, Clone)]
    pub struct PoolConfig {
        pub max_connections: u32,
        pub min_connections: u32,
        pub acquire_timeout: std::time::Duration,
        pub idle_timeout: Option<std::time::Duration>,
        pub max_lifetime: Option<std::time::Duration>,
    }

    impl Default for PoolConfig {
        fn default() -> Self {
            Self {
                max_connections: 10,
                min_connections: 0,
                acquire_timeout: std::time::Duration::from_secs(30),
                idle_timeout: Some(std::time::Duration::from_secs(600)), // 10 minutes
                max_lifetime: Some(std::time::Duration::from_secs(1800)), // 30 minutes
            }
        }
    }

    /// Connection pool statistics
    #[derive(Debug, Clone)]
    pub struct PoolStats {
        pub size: u32,
        pub idle: usize,
    }

    #[async_trait]
    impl DatabaseAdapter for SqlxAdapter {
        async fn create_user(&self, create_user: CreateUser) -> AuthResult<User> {
            let id = create_user.id.unwrap_or_else(|| Uuid::new_v4().to_string());
            let now = Utc::now();

            let user = sqlx::query_as::<_, User>(
                r#"
                INSERT INTO users (id, email, name, image, email_verified, created_at, updated_at, metadata)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING id, email, name, image, email_verified, created_at, updated_at, metadata
                "#
            )
            .bind(&id)
            .bind(&create_user.email)
            .bind(&create_user.name)
            .bind(&create_user.image)
            .bind(false)
            .bind(&now)
            .bind(&now)
            .bind(sqlx::types::Json(create_user.metadata.unwrap_or_default()))
            .fetch_one(&self.pool)
            .await?;

            Ok(user)
        }

        async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<User>> {
            let user = sqlx::query_as::<_, User>(
                r#"
                SELECT id, email, name, image, email_verified, created_at, updated_at, metadata
                FROM users WHERE id = $1
                "#,
            )
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

            Ok(user)
        }

        async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<User>> {
            let user = sqlx::query_as::<_, User>(
                r#"
                SELECT id, email, name, image, email_verified, created_at, updated_at, metadata
                FROM users WHERE email = $1
                "#,
            )
            .bind(email)
            .fetch_optional(&self.pool)
            .await?;

            Ok(user)
        }

        async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<User>> {
            let user = sqlx::query_as::<_, User>(
                r#"
                SELECT id, email, name, image, email_verified, created_at, updated_at, metadata
                FROM users WHERE username = $1
                "#,
            )
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;

            Ok(user)
        }

        async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<User> {
            let mut query = sqlx::QueryBuilder::new("UPDATE users SET updated_at = NOW()");
            let mut has_updates = false;

            if let Some(email) = &update.email {
                query.push(", email = ");
                query.push_bind(email);
                has_updates = true;
            }

            if let Some(name) = &update.name {
                query.push(", name = ");
                query.push_bind(name);
                has_updates = true;
            }

            if let Some(image) = &update.image {
                query.push(", image = ");
                query.push_bind(image);
                has_updates = true;
            }

            if let Some(email_verified) = update.email_verified {
                query.push(", email_verified = ");
                query.push_bind(email_verified);
                has_updates = true;
            }

            if let Some(metadata) = &update.metadata {
                query.push(", metadata = ");
                query.push_bind(sqlx::types::Json(metadata.clone()));
                has_updates = true;
            }

            if !has_updates {
                // If no updates, just return the current user
                return self
                    .get_user_by_id(id)
                    .await?
                    .ok_or(AuthError::UserNotFound);
            }

            query.push(" WHERE id = ");
            query.push_bind(id);
            query.push(" RETURNING id, email, name, image, email_verified, created_at, updated_at, metadata");

            let user = query.build_query_as::<User>().fetch_one(&self.pool).await?;

            Ok(user)
        }

        async fn delete_user(&self, id: &str) -> AuthResult<()> {
            sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await?;

            Ok(())
        }

        async fn create_session(&self, create_session: CreateSession) -> AuthResult<Session> {
            let id = Uuid::new_v4().to_string();
            let token = format!("session_{}", Uuid::new_v4());
            let now = Utc::now();

            let session = sqlx::query_as::<_, Session>(
                r#"
                INSERT INTO sessions (id, user_id, token, expires_at, created_at, ip_address, user_agent, active)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING id, user_id, token, expires_at, created_at, ip_address, user_agent, active
                "#
            )
            .bind(&id)
            .bind(&create_session.user_id)
            .bind(&token)
            .bind(&create_session.expires_at)
            .bind(&now)
            .bind(&create_session.ip_address)
            .bind(&create_session.user_agent)
            .bind(true)
            .fetch_one(&self.pool)
            .await?;

            Ok(session)
        }

        async fn get_session(&self, token: &str) -> AuthResult<Option<Session>> {
            let session = sqlx::query_as::<_, Session>(
                r#"
                SELECT id, user_id, token, expires_at, created_at, updated_at, ip_address, user_agent, active, impersonated_by, active_organization_id
                FROM sessions 
                WHERE token = $1 AND active = true
                "#
            )
            .bind(token)
            .fetch_optional(&self.pool)
            .await?;

            Ok(session)
        }

        async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<Session>> {
            let sessions = sqlx::query_as::<_, Session>(
                r#"
                SELECT id, user_id, token, expires_at, created_at, updated_at, ip_address, user_agent, active, impersonated_by, active_organization_id
                FROM sessions 
                WHERE user_id = $1 AND active = true
                ORDER BY created_at DESC
                "#
            )
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;

            Ok(sessions)
        }

        async fn update_session_expiry(
            &self,
            token: &str,
            expires_at: DateTime<Utc>,
        ) -> AuthResult<()> {
            sqlx::query(
                r#"
                UPDATE sessions 
                SET expires_at = $1 
                WHERE token = $2 AND active = true
                "#,
            )
            .bind(&expires_at)
            .bind(token)
            .execute(&self.pool)
            .await?;

            Ok(())
        }

        async fn delete_session(&self, token: &str) -> AuthResult<()> {
            sqlx::query("DELETE FROM sessions WHERE token = $1")
                .bind(token)
                .execute(&self.pool)
                .await?;

            Ok(())
        }

        async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
            sqlx::query("DELETE FROM sessions WHERE user_id = $1")
                .bind(user_id)
                .execute(&self.pool)
                .await?;

            Ok(())
        }

        async fn delete_expired_sessions(&self) -> AuthResult<usize> {
            let result =
                sqlx::query("DELETE FROM sessions WHERE expires_at < NOW() OR active = false")
                    .execute(&self.pool)
                    .await?;

            Ok(result.rows_affected() as usize)
        }

        async fn create_account(&self, create_account: CreateAccount) -> AuthResult<Account> {
            let id = Uuid::new_v4().to_string();
            let now = Utc::now();

            let account = sqlx::query_as::<_, Account>(
                r#"
                INSERT INTO accounts (id, account_id, provider_id, user_id, access_token, refresh_token, id_token, access_token_expires_at, refresh_token_expires_at, scope, password, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                RETURNING *
                "#
            )
            .bind(&id)
            .bind(&create_account.account_id)
            .bind(&create_account.provider_id)
            .bind(&create_account.user_id)
            .bind(&create_account.access_token)
            .bind(&create_account.refresh_token)
            .bind(&create_account.id_token)
            .bind(&create_account.access_token_expires_at)
            .bind(&create_account.refresh_token_expires_at)
            .bind(&create_account.scope)
            .bind(&create_account.password)
            .bind(&now)
            .bind(&now)
            .fetch_one(&self.pool)
            .await?;

            Ok(account)
        }

        async fn get_account(
            &self,
            provider: &str,
            provider_account_id: &str,
        ) -> AuthResult<Option<Account>> {
            let account = sqlx::query_as::<_, Account>(
                r#"
                SELECT *
                FROM accounts 
                WHERE provider_id = $1 AND account_id = $2
                "#,
            )
            .bind(provider)
            .bind(provider_account_id)
            .fetch_optional(&self.pool)
            .await?;

            Ok(account)
        }

        async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<Account>> {
            let accounts = sqlx::query_as::<_, Account>(
                r#"
                SELECT id, user_id, provider, provider_account_id, access_token, refresh_token, expires_at, token_type, scope, created_at
                FROM accounts 
                WHERE user_id = $1
                ORDER BY created_at DESC
                "#
            )
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;

            Ok(accounts)
        }

        async fn delete_account(&self, id: &str) -> AuthResult<()> {
            sqlx::query("DELETE FROM accounts WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await?;

            Ok(())
        }

        async fn create_verification(
            &self,
            create_verification: CreateVerification,
        ) -> AuthResult<Verification> {
            let id = Uuid::new_v4().to_string();
            let now = Utc::now();

            let verification = sqlx::query_as::<_, Verification>(
                r#"
                INSERT INTO verifications (id, identifier, value, expires_at, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING *
                "#
            )
            .bind(&id)
            .bind(&create_verification.identifier)
            .bind(&create_verification.value)
            .bind(&create_verification.expires_at)
            .bind(&now)
            .bind(&now)
            .fetch_one(&self.pool)
            .await?;

            Ok(verification)
        }

        async fn get_verification(
            &self,
            identifier: &str,
            value: &str,
        ) -> AuthResult<Option<Verification>> {
            let verification = sqlx::query_as::<_, Verification>(
                r#"
                SELECT *
                FROM verifications 
                WHERE identifier = $1 AND value = $2 AND expires_at > NOW()
                "#,
            )
            .bind(identifier)
            .bind(value)
            .fetch_optional(&self.pool)
            .await?;

            Ok(verification)
        }

        async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<Verification>> {
            let verification = sqlx::query_as::<_, Verification>(
                r#"
                SELECT *
                FROM verifications 
                WHERE value = $1 AND expires_at > NOW()
                "#,
            )
            .bind(value)
            .fetch_optional(&self.pool)
            .await?;

            Ok(verification)
        }

        async fn delete_verification(&self, id: &str) -> AuthResult<()> {
            sqlx::query("DELETE FROM verifications WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await?;

            Ok(())
        }

        async fn delete_expired_verifications(&self) -> AuthResult<usize> {
            let result = sqlx::query("DELETE FROM verifications WHERE expires_at < NOW()")
                .execute(&self.pool)
                .await?;

            Ok(result.rows_affected() as usize)
        }

        // Organization operations
        async fn create_organization(
            &self,
            create_org: CreateOrganization,
        ) -> AuthResult<Organization> {
            let id = create_org.id.unwrap_or_else(|| Uuid::new_v4().to_string());
            let now = Utc::now();

            let organization = sqlx::query_as::<_, Organization>(
                r#"
                INSERT INTO organization (id, name, slug, logo, metadata, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                RETURNING id, name, slug, logo, metadata, created_at, updated_at
                "#,
            )
            .bind(&id)
            .bind(&create_org.name)
            .bind(&create_org.slug)
            .bind(&create_org.logo)
            .bind(sqlx::types::Json(
                create_org.metadata.unwrap_or(serde_json::json!({})),
            ))
            .bind(&now)
            .bind(&now)
            .fetch_one(&self.pool)
            .await?;

            Ok(organization)
        }

        async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<Organization>> {
            let organization = sqlx::query_as::<_, Organization>(
                r#"
                SELECT id, name, slug, logo, metadata, created_at, updated_at
                FROM organization WHERE id = $1
                "#,
            )
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

            Ok(organization)
        }

        async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Organization>> {
            let organization = sqlx::query_as::<_, Organization>(
                r#"
                SELECT id, name, slug, logo, metadata, created_at, updated_at
                FROM organization WHERE slug = $1
                "#,
            )
            .bind(slug)
            .fetch_optional(&self.pool)
            .await?;

            Ok(organization)
        }

        async fn update_organization(
            &self,
            id: &str,
            update: UpdateOrganization,
        ) -> AuthResult<Organization> {
            let mut query = sqlx::QueryBuilder::new("UPDATE organization SET updated_at = NOW()");

            if let Some(name) = &update.name {
                query.push(", name = ");
                query.push_bind(name);
            }
            if let Some(slug) = &update.slug {
                query.push(", slug = ");
                query.push_bind(slug);
            }
            if let Some(logo) = &update.logo {
                query.push(", logo = ");
                query.push_bind(logo);
            }
            if let Some(metadata) = &update.metadata {
                query.push(", metadata = ");
                query.push_bind(sqlx::types::Json(metadata.clone()));
            }

            query.push(" WHERE id = ");
            query.push_bind(id);
            query.push(" RETURNING id, name, slug, logo, metadata, created_at, updated_at");

            let organization = query
                .build_query_as::<Organization>()
                .fetch_one(&self.pool)
                .await?;

            Ok(organization)
        }

        async fn delete_organization(&self, id: &str) -> AuthResult<()> {
            sqlx::query("DELETE FROM organization WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await?;

            Ok(())
        }

        async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<Organization>> {
            let organizations = sqlx::query_as::<_, Organization>(
                r#"
                SELECT o.id, o.name, o.slug, o.logo, o.metadata, o.created_at, o.updated_at
                FROM organization o
                INNER JOIN member m ON o.id = m.organization_id
                WHERE m.user_id = $1
                ORDER BY o.created_at DESC
                "#,
            )
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;

            Ok(organizations)
        }

        // Member operations
        async fn create_member(&self, create_member: CreateMember) -> AuthResult<Member> {
            let id = Uuid::new_v4().to_string();
            let now = Utc::now();

            let member = sqlx::query_as::<_, Member>(
                r#"
                INSERT INTO member (id, organization_id, user_id, role, created_at)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING id, organization_id, user_id, role, created_at
                "#,
            )
            .bind(&id)
            .bind(&create_member.organization_id)
            .bind(&create_member.user_id)
            .bind(&create_member.role)
            .bind(&now)
            .fetch_one(&self.pool)
            .await?;

            Ok(member)
        }

        async fn get_member(
            &self,
            organization_id: &str,
            user_id: &str,
        ) -> AuthResult<Option<Member>> {
            let member = sqlx::query_as::<_, Member>(
                r#"
                SELECT id, organization_id, user_id, role, created_at
                FROM member
                WHERE organization_id = $1 AND user_id = $2
                "#,
            )
            .bind(organization_id)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;

            Ok(member)
        }

        async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<MemberWithUser>> {
            let row = sqlx::query(
                r#"
                SELECT m.id, m.organization_id, m.user_id, m.role, m.created_at,
                       u.id as uid, u.email, u.name, u.image
                FROM member m
                INNER JOIN users u ON m.user_id = u.id
                WHERE m.id = $1
                "#,
            )
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

            if let Some(row) = row {
                use sqlx::Row;
                Ok(Some(MemberWithUser {
                    id: row.try_get("id")?,
                    organization_id: row.try_get("organization_id")?,
                    user_id: row.try_get("user_id")?,
                    role: row.try_get("role")?,
                    created_at: row.try_get("created_at")?,
                    user: MemberUser {
                        id: row.try_get("uid")?,
                        email: row.try_get("email")?,
                        name: row.try_get("name")?,
                        image: row.try_get("image")?,
                    },
                }))
            } else {
                Ok(None)
            }
        }

        async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<Member> {
            let member = sqlx::query_as::<_, Member>(
                r#"
                UPDATE member SET role = $1
                WHERE id = $2
                RETURNING id, organization_id, user_id, role, created_at
                "#,
            )
            .bind(role)
            .bind(member_id)
            .fetch_one(&self.pool)
            .await?;

            Ok(member)
        }

        async fn delete_member(&self, member_id: &str) -> AuthResult<()> {
            sqlx::query("DELETE FROM member WHERE id = $1")
                .bind(member_id)
                .execute(&self.pool)
                .await?;

            Ok(())
        }

        async fn list_organization_members(
            &self,
            organization_id: &str,
        ) -> AuthResult<Vec<MemberWithUser>> {
            let rows = sqlx::query(
                r#"
                SELECT m.id, m.organization_id, m.user_id, m.role, m.created_at,
                       u.id as uid, u.email, u.name, u.image
                FROM member m
                INNER JOIN users u ON m.user_id = u.id
                WHERE m.organization_id = $1
                ORDER BY m.created_at ASC
                "#,
            )
            .bind(organization_id)
            .fetch_all(&self.pool)
            .await?;

            use sqlx::Row;
            let members = rows
                .iter()
                .map(|row| {
                    Ok(MemberWithUser {
                        id: row.try_get("id")?,
                        organization_id: row.try_get("organization_id")?,
                        user_id: row.try_get("user_id")?,
                        role: row.try_get("role")?,
                        created_at: row.try_get("created_at")?,
                        user: MemberUser {
                            id: row.try_get("uid")?,
                            email: row.try_get("email")?,
                            name: row.try_get("name")?,
                            image: row.try_get("image")?,
                        },
                    })
                })
                .collect::<Result<Vec<_>, sqlx::Error>>()?;

            Ok(members)
        }

        async fn count_organization_members(&self, organization_id: &str) -> AuthResult<usize> {
            let count: (i64,) =
                sqlx::query_as("SELECT COUNT(*) FROM member WHERE organization_id = $1")
                    .bind(organization_id)
                    .fetch_one(&self.pool)
                    .await?;

            Ok(count.0 as usize)
        }

        async fn count_organization_owners(&self, organization_id: &str) -> AuthResult<usize> {
            let count: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM member WHERE organization_id = $1 AND role = 'owner'",
            )
            .bind(organization_id)
            .fetch_one(&self.pool)
            .await?;

            Ok(count.0 as usize)
        }

        // Invitation operations
        async fn create_invitation(&self, create_inv: CreateInvitation) -> AuthResult<Invitation> {
            let id = Uuid::new_v4().to_string();
            let now = Utc::now();

            let invitation = sqlx::query_as::<_, Invitation>(
                r#"
                INSERT INTO invitation (id, organization_id, email, role, status, inviter_id, expires_at, created_at)
                VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7)
                RETURNING id, organization_id, email, role, status, inviter_id, expires_at, created_at
                "#,
            )
            .bind(&id)
            .bind(&create_inv.organization_id)
            .bind(&create_inv.email)
            .bind(&create_inv.role)
            .bind(&create_inv.inviter_id)
            .bind(&create_inv.expires_at)
            .bind(&now)
            .fetch_one(&self.pool)
            .await?;

            Ok(invitation)
        }

        async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<Invitation>> {
            let invitation = sqlx::query_as::<_, Invitation>(
                r#"
                SELECT id, organization_id, email, role, status, inviter_id, expires_at, created_at
                FROM invitation
                WHERE id = $1
                "#,
            )
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

            Ok(invitation)
        }

        async fn get_pending_invitation(
            &self,
            organization_id: &str,
            email: &str,
        ) -> AuthResult<Option<Invitation>> {
            let invitation = sqlx::query_as::<_, Invitation>(
                r#"
                SELECT id, organization_id, email, role, status, inviter_id, expires_at, created_at
                FROM invitation
                WHERE organization_id = $1 AND LOWER(email) = LOWER($2) AND status = 'pending'
                "#,
            )
            .bind(organization_id)
            .bind(email)
            .fetch_optional(&self.pool)
            .await?;

            Ok(invitation)
        }

        async fn update_invitation_status(
            &self,
            id: &str,
            status: InvitationStatus,
        ) -> AuthResult<Invitation> {
            let invitation = sqlx::query_as::<_, Invitation>(
                r#"
                UPDATE invitation SET status = $1
                WHERE id = $2
                RETURNING id, organization_id, email, role, status, inviter_id, expires_at, created_at
                "#,
            )
            .bind(status.to_string())
            .bind(id)
            .fetch_one(&self.pool)
            .await?;

            Ok(invitation)
        }

        async fn list_organization_invitations(
            &self,
            organization_id: &str,
        ) -> AuthResult<Vec<Invitation>> {
            let invitations = sqlx::query_as::<_, Invitation>(
                r#"
                SELECT id, organization_id, email, role, status, inviter_id, expires_at, created_at
                FROM invitation
                WHERE organization_id = $1
                ORDER BY created_at DESC
                "#,
            )
            .bind(organization_id)
            .fetch_all(&self.pool)
            .await?;

            Ok(invitations)
        }

        async fn list_user_invitations(&self, email: &str) -> AuthResult<Vec<Invitation>> {
            let invitations = sqlx::query_as::<_, Invitation>(
                r#"
                SELECT id, organization_id, email, role, status, inviter_id, expires_at, created_at
                FROM invitation
                WHERE LOWER(email) = LOWER($1) AND status = 'pending' AND expires_at > NOW()
                ORDER BY created_at DESC
                "#,
            )
            .bind(email)
            .fetch_all(&self.pool)
            .await?;

            Ok(invitations)
        }

        // Session organization support
        async fn update_session_active_organization(
            &self,
            token: &str,
            organization_id: Option<&str>,
        ) -> AuthResult<Session> {
            let session = sqlx::query_as::<_, Session>(
                r#"
                UPDATE sessions SET active_organization_id = $1, updated_at = NOW()
                WHERE token = $2 AND active = true
                RETURNING id, user_id, token, expires_at, created_at, updated_at, ip_address, user_agent, active, impersonated_by, active_organization_id
                "#,
            )
            .bind(organization_id)
            .bind(token)
            .fetch_one(&self.pool)
            .await?;

            Ok(session)
        }
    }
}

#[cfg(feature = "sqlx-postgres")]
pub use sqlx_adapter::SqlxAdapter;
