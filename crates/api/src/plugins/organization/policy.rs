use super::{OrganizationConfig, hooks::*};
use better_auth_core::{AuthResult, Team, wire::UserView};

impl OrganizationConfig {
    pub(crate) async fn may_create(&self, user: &UserView) -> AuthResult<bool> {
        if let Some(policy) = &self.policy
            && let Some(value) = policy.allow_user_to_create_organization(user).await?
        {
            return Ok(value);
        }
        Ok(self.allow_user_to_create_organization)
    }
    pub(crate) async fn organization_limit_reached(
        &self,
        user: &UserView,
        count: usize,
    ) -> AuthResult<bool> {
        if let Some(policy) = &self.policy
            && let Some(value) = policy.organization_limit_reached(user).await?
        {
            return Ok(value);
        }
        Ok(self.organization_limit.is_some_and(|limit| count >= limit))
    }
    pub(crate) async fn member_limit(&self, event: OrganizationUser<'_>) -> AuthResult<usize> {
        if let Some(policy) = &self.membership_limit_callback {
            return policy.membership_limit(event).await;
        }
        Ok(self
            .membership_limit
            .filter(|limit| *limit > 0)
            .unwrap_or(100))
    }
    pub(crate) async fn pending_invitation_limit(
        &self,
        event: OrganizationMemberEvent<'_>,
        ctx: OrganizationEndpoint<'_>,
    ) -> AuthResult<usize> {
        if let Some(policy) = &self.policy
            && let Some(value) = policy.invitation_limit(event, ctx).await?
        {
            return Ok(value);
        }
        Ok(self.invitation_limit.unwrap_or(100))
    }
    pub(crate) async fn team_limit(
        &self,
        data: OrganizationTeamLimit<'_>,
        ctx: OrganizationEndpoint<'_>,
    ) -> AuthResult<Option<usize>> {
        if let Some(policy) = &self.policy
            && let Some(value) = policy.maximum_teams(data, ctx).await?
        {
            return Ok(Some(value));
        }
        Ok(self.teams.maximum_teams)
    }
    pub(crate) async fn team_member_limit(
        &self,
        data: OrganizationTeamMemberLimit<'_>,
    ) -> AuthResult<Option<usize>> {
        if let Some(policy) = &self.teams.maximum_members_per_team_callback {
            return policy.maximum_members_per_team(data).await.map(Some);
        }
        Ok(self.teams.maximum_members_per_team)
    }
    pub(crate) async fn role_limit(&self, organization_id: &str) -> AuthResult<Option<usize>> {
        if let Some(policy) = &self.policy
            && let Some(value) = policy
                .maximum_roles_per_organization(organization_id)
                .await?
        {
            return Ok(Some(value));
        }
        Ok(self.maximum_roles_per_organization)
    }
    pub(crate) async fn custom_default_team(
        &self,
        organization: &super::types::OrganizationResponse,
        ctx: OrganizationEndpoint<'_>,
    ) -> AuthResult<Option<Team>> {
        match &self.policy {
            Some(policy) => policy.create_default_team(organization, ctx).await,
            None => Ok(None),
        }
    }
    pub(crate) fn member_list_limit(&self) -> usize {
        if self.membership_limit_callback.is_some() {
            100
        } else {
            self.membership_limit
                .filter(|limit| *limit > 0)
                .unwrap_or(100)
        }
    }
    pub(crate) fn invitation_expires_at(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<chrono::DateTime<chrono::Utc>> {
        let seconds = if self.invitation_expires_in == 0.0 || self.invitation_expires_in.is_nan() {
            172800.0
        } else {
            self.invitation_expires_in
        };
        better_auth_core::utils::date::from_milliseconds(
            now.timestamp_millis() as f64 + seconds * 1000.0,
        )
        .ok_or_else(|| better_auth_core::AuthError::config("Invitation expiry is out of range"))
    }
}
