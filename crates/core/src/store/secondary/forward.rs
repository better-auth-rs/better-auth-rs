use super::SecondaryStore;
use crate::store::*;
use crate::types::*;
use crate::{AuthResult, AuthSchema};
use async_trait::async_trait;

#[async_trait]
impl<S: AuthSchema> RateLimitStore for SecondaryStore<S> {
    async fn consume_rate_limit(
        &self,
        key: &str,
        rule: crate::middleware::EndpointRateLimit,
        cleanup_window: f64,
    ) -> AuthResult<crate::middleware::RateLimitDecision> {
        self.inner
            .consume_rate_limit(key, rule, cleanup_window)
            .await
    }
}

#[async_trait]
impl<S: AuthSchema> AccountStore<S> for SecondaryStore<S> {
    async fn create_account(
        &self,
        create_account: CreateAccount,
    ) -> AuthResult<crate::wire::AccountView> {
        self.inner.create_account(create_account).await
    }
    async fn create_account_optional(
        &self,
        create_account: CreateAccount,
    ) -> AuthResult<Option<crate::wire::AccountView>> {
        self.inner.create_account_optional(create_account).await
    }
    async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<crate::wire::AccountView>> {
        self.inner.get_account(provider, provider_account_id).await
    }
    async fn get_account_owner(
        &self,
        provider: &str,
        account_id: &str,
    ) -> AuthResult<Option<AccountOwner>> {
        self.inner.get_account_owner(provider, account_id).await
    }
    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<crate::wire::AccountView>> {
        self.inner.get_user_accounts(user_id).await
    }
    async fn get_credential_account(
        &self,
        user_id: &str,
    ) -> AuthResult<Option<crate::wire::AccountView>> {
        self.inner.get_credential_account(user_id).await
    }
    async fn update_account(
        &self,
        id: &str,
        update: UpdateAccount,
    ) -> AuthResult<crate::wire::AccountView> {
        self.inner.update_account(id, update).await
    }
    async fn update_account_optional(
        &self,
        id: &str,
        update: UpdateAccount,
    ) -> AuthResult<Option<crate::wire::AccountView>> {
        self.inner.update_account_optional(id, update).await
    }
    async fn delete_account(&self, id: &str) -> AuthResult<()> {
        self.inner.delete_account(id).await
    }
}

#[async_trait]
impl<S: AuthSchema> OrganizationStore for SecondaryStore<S> {
    async fn get_organization_details(
        &self,
        query: OrganizationDetailsQuery<'_>,
    ) -> AuthResult<Option<OrganizationDetails>> {
        self.inner.get_organization_details(query).await
    }
    async fn insert_organization(&self, record: Organization) -> AuthResult<Organization> {
        self.inner.insert_organization(record).await
    }
    async fn delete_organization_records(&self, id: &str) -> AuthResult<()> {
        self.inner.delete_organization_records(id).await
    }

    async fn get_organization_by_id_value(
        &self,
        id: &serde_json::Value,
    ) -> AuthResult<Option<Organization>> {
        self.inner.get_organization_by_id_value(id).await
    }

    fn configure_organization_fields(
        &self,
        fields: crate::organization_fields::OrganizationFields,
    ) -> AuthResult<()> {
        self.inner.configure_organization_fields(fields)
    }
    async fn create_organization(&self, org: CreateOrganization) -> AuthResult<Organization> {
        self.inner.create_organization(org).await
    }
    async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<Organization>> {
        self.inner.get_organization_by_id(id).await
    }
    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Organization>> {
        self.inner.get_organization_by_slug(slug).await
    }
    async fn get_organization_by_slug_value(
        &self,
        slug: &serde_json::Value,
    ) -> AuthResult<Option<Organization>> {
        self.inner.get_organization_by_slug_value(slug).await
    }
    async fn list_organizations_by_ids(&self, ids: &[String]) -> AuthResult<Vec<Organization>> {
        self.inner.list_organizations_by_ids(ids).await
    }
    async fn update_organization(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Organization> {
        self.inner.update_organization(id, update).await
    }
    async fn delete_organization(&self, id: &str) -> AuthResult<()> {
        self.inner.delete_organization(id).await
    }
    async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<Organization>> {
        self.inner.list_user_organizations(user_id).await
    }
}

#[async_trait]
impl<S: AuthSchema> MemberStore for SecondaryStore<S> {
    async fn insert_member(&self, record: Member) -> AuthResult<Member> {
        self.inner.insert_member(record).await
    }

    async fn get_member_value(
        &self,
        organization_id: &serde_json::Value,
        user_id: &serde_json::Value,
    ) -> AuthResult<Option<Member>> {
        self.inner.get_member_value(organization_id, user_id).await
    }

    async fn create_member(&self, member: CreateMember) -> AuthResult<Member> {
        self.inner.create_member(member).await
    }
    async fn get_member(&self, organization_id: &str, user_id: &str) -> AuthResult<Option<Member>> {
        self.inner.get_member(organization_id, user_id).await
    }
    async fn get_member_with_user(
        &self,
        organization_id: &str,
        user_id: &str,
    ) -> AuthResult<Option<MemberUser>> {
        self.inner
            .get_member_with_user(organization_id, user_id)
            .await
    }
    async fn get_member_with_user_value(
        &self,
        organization_id: &serde_json::Value,
        user_id: &serde_json::Value,
    ) -> AuthResult<Option<MemberUser>> {
        self.inner
            .get_member_with_user_value(organization_id, user_id)
            .await
    }
    async fn get_member_by_id_with_user(&self, id: &str) -> AuthResult<Option<MemberUser>> {
        self.inner.get_member_by_id_with_user(id).await
    }
    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<Member>> {
        self.inner.get_member_by_id(id).await
    }
    async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<Member> {
        self.inner.update_member_role(member_id, role).await
    }
    async fn delete_member(&self, member_id: &str) -> AuthResult<()> {
        self.inner.delete_member(member_id).await
    }
    async fn delete_member_for_user(
        &self,
        member_id: &str,
        organization_id: &str,
        user_id: &str,
    ) -> AuthResult<()> {
        self.inner
            .delete_member_for_user(member_id, organization_id, user_id)
            .await
    }
    async fn list_organization_members(&self, org_id: &str) -> AuthResult<Vec<Member>> {
        self.inner.list_organization_members(org_id).await
    }
    async fn query_organization_members(
        &self,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<(Vec<Member>, usize)> {
        self.inner.query_organization_members(params).await
    }
    async fn count_organization_members(&self, org_id: &str) -> AuthResult<i64> {
        self.inner.count_organization_members(org_id).await
    }
    async fn count_organization_members_value(
        &self,
        org_id: &serde_json::Value,
    ) -> AuthResult<i64> {
        self.inner.count_organization_members_value(org_id).await
    }
    async fn count_organization_owners(&self, org_id: &str) -> AuthResult<i64> {
        self.inner.count_organization_owners(org_id).await
    }
}

#[async_trait]
impl<S: AuthSchema> InvitationStore for SecondaryStore<S> {
    async fn create_invitation(&self, invitation: CreateInvitation) -> AuthResult<Invitation> {
        self.inner.create_invitation(invitation).await
    }
    async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<Invitation>> {
        self.inner.get_invitation_by_id(id).await
    }
    async fn get_pending_invitation(
        &self,
        org_id: &str,
        email: &str,
    ) -> AuthResult<Option<Invitation>> {
        self.inner.get_pending_invitation(org_id, email).await
    }
    async fn update_invitation_status(
        &self,
        id: &str,
        status: InvitationStatus,
    ) -> AuthResult<Invitation> {
        self.inner.update_invitation_status(id, status).await
    }
    async fn update_invitation_expiry(
        &self,
        id: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Invitation> {
        self.inner.update_invitation_expiry(id, expires_at).await
    }
    async fn list_organization_invitations(&self, org_id: &str) -> AuthResult<Vec<Invitation>> {
        self.inner.list_organization_invitations(org_id).await
    }
    async fn count_pending_organization_invitations(&self, org_id: &str) -> AuthResult<i64> {
        self.inner
            .count_pending_organization_invitations(org_id)
            .await
    }
    async fn list_user_invitations(
        &self,
        email: &str,
    ) -> AuthResult<Vec<super::super::InvitationOrganization>> {
        self.inner.list_user_invitations(email).await
    }
}

#[async_trait]
impl<S: AuthSchema> TwoFactorStore for SecondaryStore<S> {
    async fn create_two_factor(&self, two_factor: CreateTwoFactor) -> AuthResult<TwoFactor> {
        self.inner.create_two_factor(two_factor).await
    }
    async fn get_two_factor_by_user_id(&self, user_id: &str) -> AuthResult<Option<TwoFactor>> {
        self.inner.get_two_factor_by_user_id(user_id).await
    }
    async fn update_two_factor_backup_codes(
        &self,
        user_id: &str,
        backup_codes: &str,
    ) -> AuthResult<TwoFactor> {
        self.inner
            .update_two_factor_backup_codes(user_id, backup_codes)
            .await
    }
    async fn update_two_factor(
        &self,
        id: &crate::SchemaValue<String>,
        update: crate::types::UpdateTwoFactor,
    ) -> AuthResult<TwoFactor> {
        self.inner.update_two_factor(id, update).await
    }
    async fn compare_exchange_two_factor_backup_codes(
        &self,
        id: &crate::SchemaValue<String>,
        previous: &str,
        replacement: &str,
    ) -> AuthResult<bool> {
        self.inner
            .compare_exchange_two_factor_backup_codes(id, previous, replacement)
            .await
    }
    async fn record_two_factor_failure(
        &self,
        id: &crate::SchemaValue<String>,
        max_attempts: i64,
        locked_until: &(dyn Fn() -> AuthResult<chrono::DateTime<chrono::Utc>> + Send + Sync),
    ) -> AuthResult<()> {
        self.inner
            .record_two_factor_failure(id, max_attempts, locked_until)
            .await
    }
    async fn reset_two_factor_failures(
        &self,
        id: &crate::SchemaValue<String>,
        locked_before: Option<chrono::DateTime<chrono::Utc>>,
    ) -> AuthResult<()> {
        self.inner
            .reset_two_factor_failures(id, locked_before)
            .await
    }
    async fn delete_two_factor(&self, user_id: &str) -> AuthResult<()> {
        self.inner.delete_two_factor(user_id).await
    }
}

#[async_trait]
impl<S: AuthSchema> ApiKeyStore for SecondaryStore<S> {
    async fn create_api_key(&self, input: CreateApiKey) -> AuthResult<ApiKey> {
        self.inner.create_api_key(input).await
    }
    async fn get_api_key_by_id(&self, id: &str) -> AuthResult<Option<ApiKey>> {
        self.inner.get_api_key_by_id(id).await
    }
    async fn get_api_key_by_id_value(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<ApiKey>> {
        self.inner.get_api_key_by_id_value(id).await
    }
    async fn get_api_key_by_hash(&self, hash: &str) -> AuthResult<Option<ApiKey>> {
        self.inner.get_api_key_by_hash(hash).await
    }
    async fn find_api_keys_by_reference(
        &self,
        reference_id: &str,
        sort: Option<(&str, &str)>,
    ) -> AuthResult<Vec<ApiKey>> {
        self.inner
            .find_api_keys_by_reference(reference_id, sort)
            .await
    }
    async fn count_api_keys_by_reference(&self, reference_id: &str) -> AuthResult<u64> {
        self.inner.count_api_keys_by_reference(reference_id).await
    }
    async fn update_api_key(
        &self,
        id: &crate::SchemaValue<String>,
        update: UpdateApiKey,
    ) -> AuthResult<ApiKey> {
        self.inner.update_api_key(id, update).await
    }
    async fn update_api_key_optional(
        &self,
        id: &crate::SchemaValue<String>,
        update: UpdateApiKey,
    ) -> AuthResult<Option<ApiKey>> {
        self.inner.update_api_key_optional(id, update).await
    }
    async fn delete_api_key(&self, id: &crate::SchemaValue<String>) -> AuthResult<()> {
        self.inner.delete_api_key(id).await
    }
    async fn delete_expired_api_keys(&self) -> AuthResult<usize> {
        self.inner.delete_expired_api_keys().await
    }
    async fn write_api_key_usage(
        &self,
        id: &crate::SchemaValue<String>,
        write: crate::store::ApiKeyUsageWrite,
    ) -> AuthResult<Option<ApiKey>> {
        self.inner.write_api_key_usage(id, write).await
    }
}

#[async_trait]
impl<S: AuthSchema> PasskeyStore for SecondaryStore<S> {
    async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<Passkey> {
        self.inner.create_passkey(input).await
    }
    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<Passkey>> {
        self.inner.get_passkey_by_id(id).await
    }
    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AuthResult<Option<Passkey>> {
        self.inner.get_passkey_by_credential_id(credential_id).await
    }
    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<Passkey>> {
        self.inner.list_passkeys_by_user(user_id).await
    }
    async fn update_passkey_authentication(
        &self,
        id: &crate::SchemaValue<String>,
        update: UpdatePasskeyAuthentication,
    ) -> AuthResult<Passkey> {
        self.inner.update_passkey_authentication(id, update).await
    }
    async fn update_passkey_name(&self, id: &str, name: &str) -> AuthResult<Passkey> {
        self.inner.update_passkey_name(id, name).await
    }
    async fn delete_passkey(&self, id: &str) -> AuthResult<()> {
        self.inner.delete_passkey(id).await
    }
}

#[async_trait]
impl<S: AuthSchema> DeviceCodeStore for SecondaryStore<S> {
    async fn create_device_code(&self, input: CreateDeviceCode) -> AuthResult<DeviceCode> {
        self.inner.create_device_code(input).await
    }
    async fn get_device_code_by_device_code(
        &self,
        device_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        self.inner.get_device_code_by_device_code(device_code).await
    }
    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        self.inner.get_device_code_by_user_code(user_code).await
    }
    async fn update_device_code(
        &self,
        id: &crate::SchemaValue<String>,
        update: UpdateDeviceCode,
    ) -> AuthResult<DeviceCode> {
        self.inner.update_device_code(id, update).await
    }
    async fn update_device_code_if_status(
        &self,
        id: &crate::SchemaValue<String>,
        current_status: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<bool> {
        self.inner
            .update_device_code_if_status(id, current_status, update)
            .await
    }
    async fn claim_device_code(
        &self,
        id: &crate::SchemaValue<String>,
        user_id: &str,
    ) -> AuthResult<bool> {
        self.inner.claim_device_code(id, user_id).await
    }
    async fn consume_device_code(
        &self,
        expected: &DeviceCode,
        ownership: &crate::DeviceCodeOwnership,
    ) -> AuthResult<Option<DeviceCode>> {
        self.inner.consume_device_code(expected, ownership).await
    }
    async fn delete_device_code(&self, id: &crate::SchemaValue<String>) -> AuthResult<()> {
        self.inner.delete_device_code(id).await
    }
    async fn delete_device_code_if_status(
        &self,
        id: &crate::SchemaValue<String>,
        status: &str,
    ) -> AuthResult<bool> {
        self.inner.delete_device_code_if_status(id, status).await
    }
}

#[async_trait]
impl<S: AuthSchema> WalletStore for SecondaryStore<S> {
    async fn get_wallet_address(
        &self,
        address: &str,
        chain_id: Option<i64>,
    ) -> AuthResult<Option<crate::types::WalletAddress>> {
        self.inner.get_wallet_address(address, chain_id).await
    }
    async fn create_wallet_address(
        &self,
        wallet: crate::types::CreateWalletAddress,
    ) -> AuthResult<crate::types::WalletAddress> {
        self.inner.create_wallet_address(wallet).await
    }
}

#[async_trait]
impl<S: AuthSchema> TeamStore for SecondaryStore<S> {
    async fn get_team_value(&self, id: &serde_json::Value) -> AuthResult<Option<Team>> {
        self.inner.get_team_value(id).await
    }
    async fn create_team(&self, input: crate::CreateTeam) -> AuthResult<crate::Team> {
        self.inner.create_team(input).await
    }
    async fn get_team(&self, id: &str) -> AuthResult<Option<crate::Team>> {
        self.inner.get_team(id).await
    }
    async fn update_team(&self, id: &str, update: crate::UpdateTeam) -> AuthResult<crate::Team> {
        self.inner.update_team(id, update).await
    }
    async fn delete_team(&self, id: &str) -> AuthResult<()> {
        self.inner.delete_team(id).await
    }
    async fn count_organization_teams(&self, organization_id: &str) -> AuthResult<u64> {
        self.inner.count_organization_teams(organization_id).await
    }
    async fn list_organization_teams(&self, organization_id: &str) -> AuthResult<Vec<crate::Team>> {
        self.inner.list_organization_teams(organization_id).await
    }
    async fn list_user_teams(&self, user_id: &str) -> AuthResult<Vec<crate::Team>> {
        self.inner.list_user_teams(user_id).await
    }
    async fn get_team_member(
        &self,
        team_id: &str,
        user_id: &str,
    ) -> AuthResult<Option<crate::TeamMember>> {
        self.inner.get_team_member(team_id, user_id).await
    }
    async fn count_team_members(&self, team_id: &str) -> AuthResult<u64> {
        self.inner.count_team_members(team_id).await
    }
    async fn list_team_members(&self, team_id: &str) -> AuthResult<Vec<crate::TeamMember>> {
        self.inner.list_team_members(team_id).await
    }
    async fn add_team_member(
        &self,
        team_id: &crate::SchemaValue<String>,
        user_id: &str,
        maximum: Option<usize>,
    ) -> AuthResult<Option<crate::TeamMember>> {
        self.inner.add_team_member(team_id, user_id, maximum).await
    }
    async fn remove_team_member(&self, team_id: &str, user_id: &str) -> AuthResult<()> {
        self.inner.remove_team_member(team_id, user_id).await
    }
}

#[async_trait]
impl<S: AuthSchema> OrganizationRoleStore for SecondaryStore<S> {
    async fn create_organization_role(
        &self,
        input: crate::CreateOrganizationRole,
    ) -> AuthResult<crate::OrganizationRole> {
        self.inner.create_organization_role(input).await
    }
    async fn get_organization_role(&self, id: &str) -> AuthResult<Option<crate::OrganizationRole>> {
        self.inner.get_organization_role(id).await
    }
    async fn find_organization_role(
        &self,
        organization_id: &str,
        key: super::super::OrganizationRoleKey<'_>,
    ) -> AuthResult<Option<crate::OrganizationRole>> {
        self.inner
            .find_organization_role(organization_id, key)
            .await
    }
    async fn query_organization_roles(
        &self,
        organization_id: &str,
        names: &[String],
    ) -> AuthResult<Vec<crate::OrganizationRole>> {
        self.inner
            .query_organization_roles(organization_id, names)
            .await
    }
    async fn count_organization_roles(&self, organization_id: &str) -> AuthResult<u64> {
        self.inner.count_organization_roles(organization_id).await
    }
    async fn list_organization_roles(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<crate::OrganizationRole>> {
        self.inner.list_organization_roles(organization_id).await
    }
    async fn update_organization_role(
        &self,
        id: &str,
        update: crate::UpdateOrganizationRole,
    ) -> AuthResult<crate::OrganizationRole> {
        self.inner.update_organization_role(id, update).await
    }
    async fn delete_organization_role(&self, id: &str) -> AuthResult<()> {
        self.inner.delete_organization_role(id).await
    }
}

#[async_trait]
impl<S: AuthSchema> JwksStore for SecondaryStore<S> {
    async fn get_jwk(&self, id: &str) -> AuthResult<Option<crate::Jwk>> {
        self.inner.get_jwk(id).await
    }
    async fn list_jwks(&self) -> AuthResult<Vec<crate::Jwk>> {
        self.inner.list_jwks().await
    }
    async fn create_jwk(&self, input: crate::CreateJwk) -> AuthResult<crate::Jwk> {
        self.inner.create_jwk(input).await
    }
}
