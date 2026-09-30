//! Typed application hooks. Mutable inputs represent upstream `data` overrides.

use super::types::OrganizationResponse;

use async_trait::async_trait;
use better_auth_core::{
    AuthConfig, AuthContext, AuthRequest, AuthResult, AuthSchema, CreateInvitation, CreateMember,
    CreateOrganization, CreateTeam, Invitation, Member, Team, TeamMember, UpdateOrganization,
    UpdateTeam,
    store::{InvitationStore, MemberStore, OrganizationStore, TeamStore},
    wire::{SessionView, UserView},
};

/// Request and persistence capabilities supplied to endpoint-aware callbacks.
pub struct OrganizationEndpoint<'a> {
    /// HTTP request, absent for a trusted server call without a request.
    pub request: Option<&'a AuthRequest>,
    /// Global authentication configuration.
    pub auth_config: &'a AuthConfig,
    /// Organization persistence used by the running auth instance.
    pub organizations: &'a dyn OrganizationStore,
    /// Team persistence, including atomic member capacity checks.
    pub teams: &'a dyn TeamStore,
    /// Organization membership persistence.
    pub members: &'a dyn MemberStore,
    /// Invitation persistence.
    pub invitations: &'a dyn InvitationStore,
}

impl<'a> OrganizationEndpoint<'a> {
    pub(crate) fn new<S: AuthSchema>(
        ctx: &'a AuthContext<S>,
        request: Option<&'a AuthRequest>,
    ) -> Self {
        Self {
            request,
            auth_config: &ctx.config,
            organizations: ctx.database.as_ref(),
            teams: ctx.database.as_ref(),
            members: ctx.database.as_ref(),
            invitations: ctx.database.as_ref(),
        }
    }
}

/// An organization and the user acting on it.
#[derive(Clone, Copy)]
pub struct OrganizationUser<'a> {
    /// Persisted organization associated with the operation.
    pub organization: &'a OrganizationResponse,
    /// Acting user, or the invited/added user where upstream supplies that user.
    pub user: &'a UserView,
}

/// Member and user supplied to organization update hooks.
#[derive(Clone, Copy)]
pub struct OrganizationActor<'a> {
    /// Acting user's organization membership.
    pub member: &'a Member,
    /// Acting user.
    pub user: &'a UserView,
}

/// A membership operation and its upstream user subject.
#[derive(Clone, Copy)]
pub struct OrganizationMemberEvent<'a> {
    /// Membership being added, removed, or changed.
    pub member: &'a Member,
    /// User supplied by the upstream hook at this call site.
    pub user: &'a UserView,
    /// Organization containing the membership.
    pub organization: &'a OrganizationResponse,
}

/// Invitation state and the user acting on it.
#[derive(Clone, Copy)]
pub struct OrganizationInvitationEvent<'a> {
    /// Invitation snapshot at this hook's position in the operation.
    pub invitation: &'a Invitation,
    /// Inviter, recipient, or cancelling user, according to the hook.
    pub user: &'a UserView,
    /// Organization receiving the invited user.
    pub organization: &'a OrganizationResponse,
}

/// Team state and its optional authenticated actor.
#[derive(Clone, Copy)]
pub struct OrganizationTeamEvent<'a> {
    /// Persisted team snapshot.
    pub team: &'a Team,
    /// Acting user; absent for trusted team creation/deletion without a session.
    pub user: Option<&'a UserView>,
    /// Organization containing the team.
    pub organization: &'a OrganizationResponse,
}

/// The target of a team membership change.
#[derive(Clone, Copy)]
pub struct OrganizationTeamMemberTarget<'a> {
    /// Team receiving or losing the member.
    pub team: &'a Team,
    /// User being added or removed, rather than the administrator.
    pub user: &'a UserView,
    /// Organization containing the team.
    pub organization: &'a OrganizationResponse,
}

/// Membership input before the adapter generates its creation timestamp.
#[derive(Debug, Clone)]
pub struct OrganizationMemberDraft {
    pub additional_fields: serde_json::Map<String, serde_json::Value>,

    pub organization_id: String,
    pub user_id: String,
    pub role: String,
    /// Server-side addMember input; team assignment is handled separately from this record.
    pub team_id: Option<String>,
    /// The hook starts without a timestamp; the adapter always generates the stored value.
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}
impl OrganizationMemberDraft {
    pub(crate) fn into_create(self) -> CreateMember {
        CreateMember {
            organization_id: self.organization_id,
            user_id: self.user_id,
            role: self.role,
            additional_fields: self.additional_fields,
        }
    }
}

/// Team fields visible before adapter defaults are applied.
#[derive(Debug, Clone)]
pub struct OrganizationTeamDraft {
    pub additional_fields: serde_json::Map<String, serde_json::Value>,

    pub id: Option<String>,
    pub name: String,
    pub organization_id: String,
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
    /// None leaves the route default; Some(None) explicitly clears the timestamp.
    pub updated_at: Option<Option<chrono::DateTime<chrono::Utc>>>,
}
impl OrganizationTeamDraft {
    pub(crate) fn into_create(
        self,
        created_at: chrono::DateTime<chrono::Utc>,
        updated_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> CreateTeam {
        CreateTeam {
            additional_fields: self.additional_fields,
            id: self.id,
            name: self.name,
            organization_id: self.organization_id,
            created_at: Some(self.created_at.unwrap_or(created_at)),
            updated_at: self.updated_at.unwrap_or(updated_at),
        }
    }
}

/// Invitation fields visible before adapter defaults are applied.
#[derive(Debug, Clone)]
pub struct OrganizationInvitationDraft {
    pub additional_fields: serde_json::Map<String, serde_json::Value>,

    pub id: Option<String>,
    pub organization_id: String,
    pub email: String,
    pub role: String,
    pub inviter_id: String,
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
    pub status: Option<better_auth_core::InvitationStatus>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Informational first-team alias. Upstream ignores returned changes to this field.
    pub team_id: Option<String>,
    /// Destination teams used by the adapter after the hook.
    pub team_ids: Vec<String>,
}
impl OrganizationInvitationDraft {
    pub(crate) fn into_create(self, expires_at: chrono::DateTime<chrono::Utc>) -> CreateInvitation {
        CreateInvitation {
            additional_fields: self.additional_fields,
            id: self.id,
            created_at: self.created_at,
            status: self.status,
            organization_id: self.organization_id,
            email: self.email,
            role: self.role,
            inviter_id: self.inviter_id,
            expires_at: self.expires_at.unwrap_or(expires_at),
            team_id: (!self.team_ids.is_empty()).then(|| self.team_ids.join(",")),
        }
    }
}

/// Hooks run in upstream order. Returning an error stops the current operation.
///
/// Before hooks modify typed inputs in place. After-hook failures do not undo
/// persistence that upstream has already committed.
#[async_trait]
pub trait OrganizationHooks: Send + Sync {
    /// Override organization creation fields after the initial slug check.
    async fn before_create_organization(
        &self,
        _data: &mut CreateOrganization,
        _user: &UserView,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Run after owner/default-team creation and before selecting the active organization.
    async fn after_create_organization(
        &self,
        _event: OrganizationMemberEvent<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Override the update after permission and initial slug checks.
    async fn before_update_organization(
        &self,
        _data: &mut UpdateOrganization,
        _actor: OrganizationActor<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Observe the persisted organization update.
    async fn after_update_organization(
        &self,
        _organization: &OrganizationResponse,
        _actor: OrganizationActor<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Run before deleting organization data.
    async fn before_delete_organization(
        &self,
        _event: OrganizationUser<'_>,
        _ctx: OrganizationEndpoint<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Run after deleting organization data.
    async fn after_delete_organization(
        &self,
        _event: OrganizationUser<'_>,
        _ctx: OrganizationEndpoint<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Override membership creation fields for an owner or server-side member addition.
    async fn before_add_member(
        &self,
        _data: &mut OrganizationMemberDraft,
        _event: OrganizationUser<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Observe membership creation after any requested team membership succeeds.
    async fn after_add_member(&self, _event: OrganizationMemberEvent<'_>) -> AuthResult<()> {
        Ok(())
    }
    /// Run before removing a member. Leaving an organization does not invoke this hook.
    async fn before_remove_member(&self, _event: OrganizationMemberEvent<'_>) -> AuthResult<()> {
        Ok(())
    }
    /// Run after removing the member and clearing the applicable active organization.
    async fn after_remove_member(&self, _event: OrganizationMemberEvent<'_>) -> AuthResult<()> {
        Ok(())
    }
    /// Override the new role after validating the requested role and owner constraints.
    async fn before_update_member_role(
        &self,
        _role: &mut String,
        _event: OrganizationMemberEvent<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Observe the updated membership and the role it replaced.
    async fn after_update_member_role(
        &self,
        _previous_role: &str,
        _event: OrganizationMemberEvent<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Override invitation creation fields after permission and capacity checks.
    async fn before_create_invitation(
        &self,
        _data: &mut OrganizationInvitationDraft,
        _event: OrganizationUser<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Run after persisting a new invitation and delivering its email. Resends skip this hook.
    async fn after_create_invitation(
        &self,
        _event: OrganizationInvitationEvent<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Run after checking recipient membership capacity and before accepting the invitation.
    async fn before_accept_invitation(
        &self,
        _event: OrganizationInvitationEvent<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Observe the accepted invitation and its new organization membership.
    async fn after_accept_invitation(
        &self,
        _member: &Member,
        _event: OrganizationInvitationEvent<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Run before changing a recipient's invitation to rejected.
    async fn before_reject_invitation(
        &self,
        _event: OrganizationInvitationEvent<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Observe the rejected invitation.
    async fn after_reject_invitation(
        &self,
        _event: OrganizationInvitationEvent<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Run before cancellation; the event user is the cancelling user.
    async fn before_cancel_invitation(
        &self,
        _event: OrganizationInvitationEvent<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Observe the cancelled invitation.
    async fn after_cancel_invitation(
        &self,
        _event: OrganizationInvitationEvent<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Override new team fields, including the default team during organization creation.
    async fn before_create_team(
        &self,
        _data: &mut OrganizationTeamDraft,
        _organization: &OrganizationResponse,
        _user: Option<&UserView>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Observe a persisted team after default-team membership, when applicable.
    async fn after_create_team(&self, _event: OrganizationTeamEvent<'_>) -> AuthResult<()> {
        Ok(())
    }
    /// Modify or replace the update after permission checks. Team IDs remain immutable.
    async fn before_update_team(
        &self,
        _updates: &mut UpdateTeam,
        _event: OrganizationTeamEvent<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Observe the persisted team update.
    async fn after_update_team(&self, _event: OrganizationTeamEvent<'_>) -> AuthResult<()> {
        Ok(())
    }
    /// Run before deleting team membership and invitation references.
    async fn before_delete_team(&self, _event: OrganizationTeamEvent<'_>) -> AuthResult<()> {
        Ok(())
    }
    /// Run after team deletion commits.
    async fn after_delete_team(&self, _event: OrganizationTeamEvent<'_>) -> AuthResult<()> {
        Ok(())
    }
    /// Run before adding a team member. Upstream ignores this hook's data overrides.
    async fn before_add_team_member(
        &self,
        _target: OrganizationTeamMemberTarget<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Observe the existing or newly created team membership.
    async fn after_add_team_member(
        &self,
        _member: &TeamMember,
        _target: OrganizationTeamMemberTarget<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Run before removing the target team membership.
    async fn before_remove_team_member(
        &self,
        _member: &TeamMember,
        _target: OrganizationTeamMemberTarget<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Run after removing the target team membership.
    async fn after_remove_team_member(
        &self,
        _member: &TeamMember,
        _target: OrganizationTeamMemberTarget<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }
}

/// Authenticated session supplied to dynamic team limits.
#[derive(Clone, Copy)]
pub struct OrganizationSession<'a> {
    /// Authenticated user, which may differ from the member being added.
    pub user: &'a UserView,
    /// Current authenticated session.
    pub session: &'a SessionView,
}

/// Context for the maximum-team callback.
#[derive(Clone, Copy)]
pub struct OrganizationTeamLimit<'a> {
    /// Organization whose teams will be counted.
    pub organization_id: &'a str,
    /// Current session, absent for trusted server-side team creation.
    pub session: Option<OrganizationSession<'a>>,
}

/// Context for atomic team membership capacity checks.
#[derive(Clone, Copy)]
pub struct OrganizationTeamMemberLimit<'a> {
    /// Organization containing the destination team.
    pub organization_id: &'a str,
    /// Destination team identifier.
    pub team_id: &'a str,
    /// Authenticated actor's session.
    pub session: OrganizationSession<'a>,
}

/// Asynchronous configuration callbacks. `None` keeps the configured static value.
#[async_trait]
pub trait OrganizationPolicy: Send + Sync {
    /// Decide whether this user may create an organization.
    async fn allow_user_to_create_organization(
        &self,
        _user: &UserView,
    ) -> AuthResult<Option<bool>> {
        Ok(None)
    }
    /// Return true when the user's organization limit has been reached.
    async fn organization_limit_reached(&self, _user: &UserView) -> AuthResult<Option<bool>> {
        Ok(None)
    }
    /// Resolve pending invitation capacity for the authenticated inviter.
    async fn invitation_limit(
        &self,
        _event: OrganizationMemberEvent<'_>,
        _ctx: OrganizationEndpoint<'_>,
    ) -> AuthResult<Option<usize>> {
        Ok(None)
    }
    /// Resolve the maximum number of teams before team creation.
    async fn maximum_teams(
        &self,
        _data: OrganizationTeamLimit<'_>,
        _ctx: OrganizationEndpoint<'_>,
    ) -> AuthResult<Option<usize>> {
        Ok(None)
    }
    /// Resolve the maximum number of stored dynamic roles.
    async fn maximum_roles_per_organization(
        &self,
        _organization_id: &str,
    ) -> AuthResult<Option<usize>> {
        Ok(None)
    }
    /// Create and persist a default team, or return `None` for normal creation.
    async fn create_default_team(
        &self,
        _organization: &OrganizationResponse,
        _ctx: OrganizationEndpoint<'_>,
    ) -> AuthResult<Option<Team>> {
        Ok(None)
    }
}

/// Dynamic team capacity requires an authenticated actor session.
#[async_trait]
pub trait TeamMemberLimitPolicy: Send + Sync {
    async fn maximum_members_per_team(
        &self,
        data: OrganizationTeamMemberLimit<'_>,
    ) -> AuthResult<usize>;
}

/// Dynamic organization capacity. Listing endpoints still use the upstream default page size.
#[async_trait]
pub trait MembershipLimitPolicy: Send + Sync {
    async fn membership_limit(&self, data: OrganizationUser<'_>) -> AuthResult<usize>;
}
