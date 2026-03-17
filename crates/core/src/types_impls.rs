use chrono::{DateTime, Utc};

use crate::entity::{
    AuthAccount, AuthApiKey, AuthInvitation, AuthMember, AuthOrganization, AuthPasskey,
    AuthSession, AuthTwoFactor, AuthUser, AuthVerification,
};

use super::types::{Account, ApiKey, Passkey, Session, TwoFactor, User, Verification};
use super::types_org::{Invitation, InvitationStatus, Member, Organization};

/// Blanket conversion from any [`AuthUser`] implementor to the concrete [`User`] type.
///
/// This avoids hand-written `to_user()` helpers scattered across plugins.
impl<T: AuthUser> From<&T> for User {
    fn from(u: &T) -> Self {
        Self {
            id: u.id().to_owned(),
            name: u.name().map(str::to_owned),
            email: u.email().map(str::to_owned),
            email_verified: u.email_verified(),
            image: u.image().map(str::to_owned),
            created_at: u.created_at(),
            updated_at: u.updated_at(),
            username: u.username().map(str::to_owned),
            display_username: u.display_username().map(str::to_owned),
            two_factor_enabled: u.two_factor_enabled(),
            role: u.role().map(str::to_owned),
            banned: u.banned(),
            ban_reason: u.ban_reason().map(str::to_owned),
            ban_expires: u.ban_expires(),
            metadata: u.metadata().clone(),
        }
    }
}

impl AuthUser for User {
    fn id(&self) -> &str {
        &self.id
    }
    fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    fn email_verified(&self) -> bool {
        self.email_verified
    }
    fn image(&self) -> Option<&str> {
        self.image.as_deref()
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
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
    fn ban_expires(&self) -> Option<DateTime<Utc>> {
        self.ban_expires
    }
    fn metadata(&self) -> &serde_json::Value {
        &self.metadata
    }
}

impl AuthSession for Session {
    fn id(&self) -> &str {
        &self.id
    }
    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
    fn token(&self) -> &str {
        &self.token
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
    fn ip_address(&self) -> Option<&str> {
        self.ip_address.as_deref()
    }
    fn user_agent(&self) -> Option<&str> {
        self.user_agent.as_deref()
    }
    fn user_id(&self) -> &str {
        &self.user_id
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

impl AuthAccount for Account {
    fn id(&self) -> &str {
        &self.id
    }
    fn account_id(&self) -> &str {
        &self.account_id
    }
    fn provider_id(&self) -> &str {
        &self.provider_id
    }
    fn user_id(&self) -> &str {
        &self.user_id
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
    fn access_token_expires_at(&self) -> Option<DateTime<Utc>> {
        self.access_token_expires_at
    }
    fn refresh_token_expires_at(&self) -> Option<DateTime<Utc>> {
        self.refresh_token_expires_at
    }
    fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }
    fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

impl AuthOrganization for Organization {
    fn id(&self) -> &str {
        &self.id
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn slug(&self) -> &str {
        &self.slug
    }
    fn logo(&self) -> Option<&str> {
        self.logo.as_deref()
    }
    fn metadata(&self) -> Option<&serde_json::Value> {
        self.metadata.as_ref()
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

impl AuthMember for Member {
    fn id(&self) -> &str {
        &self.id
    }
    fn organization_id(&self) -> &str {
        &self.organization_id
    }
    fn user_id(&self) -> &str {
        &self.user_id
    }
    fn role(&self) -> &str {
        &self.role
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl AuthInvitation for Invitation {
    fn id(&self) -> &str {
        &self.id
    }
    fn organization_id(&self) -> &str {
        &self.organization_id
    }
    fn email(&self) -> &str {
        &self.email
    }
    fn role(&self) -> &str {
        &self.role
    }
    fn status(&self) -> &InvitationStatus {
        &self.status
    }
    fn inviter_id(&self) -> &str {
        &self.inviter_id
    }
    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl AuthVerification for Verification {
    fn id(&self) -> &str {
        &self.id
    }
    fn identifier(&self) -> &str {
        &self.identifier
    }
    fn value(&self) -> &str {
        &self.value
    }
    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

impl AuthTwoFactor for TwoFactor {
    fn id(&self) -> &str {
        &self.id
    }
    fn secret(&self) -> &str {
        &self.secret
    }
    fn backup_codes(&self) -> Option<&str> {
        self.backup_codes.as_deref()
    }
    fn user_id(&self) -> &str {
        &self.user_id
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

impl AuthApiKey for ApiKey {
    fn id(&self) -> &str {
        &self.id
    }
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    fn start(&self) -> Option<&str> {
        self.start.as_deref()
    }
    fn prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }
    fn key_hash(&self) -> &str {
        &self.key_hash
    }
    fn user_id(&self) -> &str {
        &self.user_id
    }
    fn refill_interval(&self) -> Option<i64> {
        self.refill_interval
    }
    fn refill_amount(&self) -> Option<i64> {
        self.refill_amount
    }
    fn last_refill_at(&self) -> Option<&str> {
        self.last_refill_at.as_deref()
    }
    fn enabled(&self) -> bool {
        self.enabled
    }
    fn rate_limit_enabled(&self) -> bool {
        self.rate_limit_enabled
    }
    fn rate_limit_time_window(&self) -> Option<i64> {
        self.rate_limit_time_window
    }
    fn rate_limit_max(&self) -> Option<i64> {
        self.rate_limit_max
    }
    fn request_count(&self) -> Option<i64> {
        self.request_count
    }
    fn remaining(&self) -> Option<i64> {
        self.remaining
    }
    fn last_request(&self) -> Option<&str> {
        self.last_request.as_deref()
    }
    fn expires_at(&self) -> Option<&str> {
        self.expires_at.as_deref()
    }
    fn created_at(&self) -> &str {
        &self.created_at
    }
    fn updated_at(&self) -> &str {
        &self.updated_at
    }
    fn permissions(&self) -> Option<&str> {
        self.permissions.as_deref()
    }
    fn metadata(&self) -> Option<&str> {
        self.metadata.as_deref()
    }
}

impl AuthPasskey for Passkey {
    fn id(&self) -> &str {
        &self.id
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn public_key(&self) -> &str {
        &self.public_key
    }
    fn user_id(&self) -> &str {
        &self.user_id
    }
    fn credential_id(&self) -> &str {
        &self.credential_id
    }
    fn counter(&self) -> u64 {
        self.counter
    }
    fn device_type(&self) -> &str {
        &self.device_type
    }
    fn backed_up(&self) -> bool {
        self.backed_up
    }
    fn transports(&self) -> Option<&str> {
        self.transports.as_deref()
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}
