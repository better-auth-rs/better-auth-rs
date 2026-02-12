use chrono::{DateTime, Utc};

use crate::entity::{
    AuthAccount, AuthInvitation, AuthMember, AuthOrganization, AuthSession, AuthTwoFactor,
    AuthUser, AuthVerification,
};
use crate::types::{
    Account, CreateAccount, CreateInvitation, CreateMember, CreateOrganization, CreateSession,
    CreateTwoFactor, CreateUser, CreateVerification, Invitation, InvitationStatus, Member,
    Organization, Session, TwoFactor, UpdateAccount, UpdateOrganization, UpdateUser, User,
    Verification,
};

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

/// Construction and mutation for account entities stored in memory.
pub trait MemoryAccount: AuthAccount {
    fn from_create(id: String, create: &CreateAccount, now: DateTime<Utc>) -> Self;
    fn apply_update(&mut self, update: &UpdateAccount);
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

/// Construction and mutation for two-factor entities stored in memory.
pub trait MemoryTwoFactor: AuthTwoFactor {
    fn from_create(id: String, create: &CreateTwoFactor, now: DateTime<Utc>) -> Self;
    fn set_backup_codes(&mut self, codes: String);
}

// -- Default implementations for built-in types --

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

    fn apply_update(&mut self, update: &UpdateAccount) {
        if let Some(access_token) = &update.access_token {
            self.access_token = Some(access_token.clone());
        }
        if let Some(refresh_token) = &update.refresh_token {
            self.refresh_token = Some(refresh_token.clone());
        }
        if let Some(id_token) = &update.id_token {
            self.id_token = Some(id_token.clone());
        }
        if let Some(at) = update.access_token_expires_at {
            self.access_token_expires_at = Some(at);
        }
        if let Some(at) = update.refresh_token_expires_at {
            self.refresh_token_expires_at = Some(at);
        }
        if let Some(scope) = &update.scope {
            self.scope = Some(scope.clone());
        }
        self.updated_at = Utc::now();
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

impl MemoryTwoFactor for TwoFactor {
    fn from_create(id: String, create: &CreateTwoFactor, _now: DateTime<Utc>) -> Self {
        TwoFactor {
            id,
            secret: create.secret.clone(),
            backup_codes: create.backup_codes.clone(),
            user_id: create.user_id.clone(),
        }
    }

    fn set_backup_codes(&mut self, codes: String) {
        self.backup_codes = Some(codes);
    }
}
