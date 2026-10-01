use super::rows::Rows;
use super::*;

#[derive(Clone, Default)]
pub(super) struct State {
    pub(super) organizations: Rows<Organization>,
    pub(super) members: Rows<Member>,
    pub(super) invitations: Rows<Invitation>,
    pub(super) teams: Rows<crate::Team>,
    pub(super) team_members: Vec<crate::TeamMember>,
    pub(super) organization_roles: Rows<crate::OrganizationRole>,
    pub(super) jwks: Vec<crate::Jwk>,
    pub(super) users: Rows<UserView>,
    pub(super) wallets: Vec<crate::types::WalletAddress>,
    pub(super) sessions: IndexMap<String, SessionView>,
    pub(super) accounts: Vec<Map<String, Value>>,
    pub(super) verifications: Vec<Map<String, Value>>,
    pub(super) two_factors: Rows<TwoFactor>,
    pub(super) device_codes: Rows<DeviceCode>,
    pub(super) api_keys: Rows<ApiKey>,
    pub(super) passkeys: Rows<Passkey>,
    pub(super) rate_limits: IndexMap<String, crate::store::RateLimitRecord>,
}
