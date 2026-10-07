use super::rows::Rows;
use super::*;

#[derive(Clone, Default)]
pub(super) struct State {
    pub(super) organizations: Rows<Organization>,
    pub(super) members: Rows<Member>,
    pub(super) invitations: Rows<Invitation>,
    pub(super) teams: Rows<crate::Team>,
    pub(super) team_members: Rows<crate::TeamMember>,
    pub(super) organization_roles: Rows<crate::OrganizationRole>,
    pub(super) jwks: Rows<crate::Jwk>,
    pub(super) users: Rows<UserView>,
    pub(super) wallets: Rows<crate::types::WalletAddress>,
    pub(super) sessions: Rows<SessionView>,
    pub(super) accounts: Rows<crate::FieldMap>,
    pub(super) verifications: Rows<crate::FieldMap>,
    pub(super) two_factors: Rows<TwoFactor>,
    pub(super) device_codes: Rows<DeviceCode>,
    pub(super) api_keys: Rows<ApiKey>,
    pub(super) passkeys: Rows<Passkey>,
    pub(super) rate_limits: IndexMap<String, crate::store::RateLimitRecord>,
}

impl State {
    pub(super) fn deep_clone(&self) -> AuthResult<Self> {
        let mut cloned = self.clone();
        let mut context = crate::StructuredCloneContext::new();
        cloned.organizations = self.organizations.deep_clone(&mut context)?;
        cloned.members = self.members.deep_clone(&mut context)?;
        cloned.invitations = self.invitations.deep_clone(&mut context)?;
        cloned.teams = self.teams.deep_clone(&mut context)?;
        cloned.organization_roles = self.organization_roles.deep_clone(&mut context)?;
        cloned.users = self.users.deep_clone(&mut context)?;
        cloned.two_factors = self.two_factors.deep_clone(&mut context)?;
        cloned.device_codes = self.device_codes.deep_clone(&mut context)?;
        cloned.api_keys = self.api_keys.deep_clone(&mut context)?;
        cloned.passkeys = self.passkeys.deep_clone(&mut context)?;
        cloned.team_members = self.team_members.deep_clone(&mut context)?;
        cloned.jwks = self.jwks.deep_clone(&mut context)?;
        cloned.wallets = self.wallets.deep_clone(&mut context)?;
        cloned.sessions = self.sessions.deep_clone(&mut context)?;
        cloned.accounts = self.accounts.deep_clone(&mut context)?;
        cloned.verifications = self.verifications.deep_clone(&mut context)?;
        cloned.rate_limits = self
            .rate_limits
            .iter()
            .map(|(key, row)| {
                row.structured_clone(&mut context)
                    .map(|row| (key.clone(), row))
            })
            .collect::<AuthResult<_>>()?;
        Ok(cloned)
    }
}
