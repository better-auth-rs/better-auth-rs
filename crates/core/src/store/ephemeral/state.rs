use super::*;

#[derive(Clone, Default)]
pub(super) struct State {
    pub(super) organizations: IndexMap<String, Organization>,
    pub(super) members: IndexMap<String, Member>,
    pub(super) invitations: IndexMap<String, Invitation>,
    pub(super) teams: IndexMap<String, crate::Team>,
    pub(super) team_members: Vec<crate::TeamMember>,
    pub(super) organization_roles: IndexMap<String, crate::OrganizationRole>,
    pub(super) jwks: Vec<crate::Jwk>,
    pub(super) users: IndexMap<String, UserView>,
    pub(super) wallets: Vec<crate::types::WalletAddress>,
    pub(super) sessions: IndexMap<String, SessionView>,
    pub(super) accounts: IndexMap<String, AccountView>,
    pub(super) verifications: IndexMap<String, VerificationView>,
    pub(super) two_factors: IndexMap<String, TwoFactor>,
    pub(super) device_codes: IndexMap<String, DeviceCode>,
    pub(super) api_keys: IndexMap<String, ApiKey>,
    pub(super) passkeys: IndexMap<String, Passkey>,
    pub(super) rate_limits: IndexMap<String, crate::store::RateLimitRecord>,
}
