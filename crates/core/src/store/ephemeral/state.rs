use super::rows::Rows;
use super::*;

#[derive(Clone, Default)]
pub(super) struct State {
    pub(super) organizations: Rows<FieldMap>,
    pub(super) members: Rows<FieldMap>,
    pub(super) invitations: Rows<FieldMap>,
    pub(super) teams: Rows<FieldMap>,
    pub(super) team_members: Rows<FieldMap>,
    pub(super) organization_roles: Rows<FieldMap>,
    pub(super) jwks: Rows<FieldMap>,
    pub(super) users: Rows<UserView>,
    pub(super) wallets: Rows<FieldMap>,
    pub(super) sessions: Rows<FieldMap>,
    pub(super) accounts: Rows<crate::FieldMap>,
    pub(super) verifications: Rows<crate::FieldMap>,
    pub(super) two_factors: Rows<FieldMap>,
    pub(super) device_codes: Rows<FieldMap>,
    pub(super) api_keys: Rows<FieldMap>,
    pub(super) passkeys: Rows<FieldMap>,
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
