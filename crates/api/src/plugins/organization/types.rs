use better_auth_core::entity::MemberUserView;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct CreateOrganizationRequest {
    #[validate(length(min = 1, message = "Name is required"))]
    pub name: String,
    #[validate(length(min = 1, max = 100, message = "Slug must be 1-100 characters"))]
    pub slug: String,
    pub logo: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateOrganizationRequest {
    pub name: Option<String>,
    pub slug: Option<String>,
    pub logo: Option<String>,
    pub metadata: Option<serde_json::Value>,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteOrganizationRequest {
    #[serde(rename = "organizationId")]
    pub organization_id: String,
}

#[derive(Debug, Deserialize)]
pub struct CheckSlugRequest {
    pub slug: String,
}

#[derive(Debug, Deserialize)]
pub struct SetActiveOrganizationRequest {
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    #[serde(rename = "organizationSlug")]
    pub organization_slug: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LeaveOrganizationRequest {
    #[serde(rename = "organizationId")]
    pub organization_id: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct GetFullOrganizationQuery {
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    #[serde(rename = "organizationSlug")]
    pub organization_slug: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct InviteMemberRequest {
    #[validate(email(message = "Invalid email address"))]
    pub email: String,
    #[validate(length(min = 1, message = "Role is required"))]
    pub role: String,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RemoveMemberRequest {
    #[serde(rename = "memberId")]
    pub member_id: Option<String>,
    pub email: Option<String>,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateMemberRoleRequest {
    #[serde(rename = "memberId")]
    pub member_id: String,
    pub role: String,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ListMembersQuery {
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    #[serde(rename = "organizationSlug")]
    pub organization_slug: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct AcceptInvitationRequest {
    #[serde(rename = "invitationId")]
    pub invitation_id: String,
}

#[derive(Debug, Deserialize)]
pub struct RejectInvitationRequest {
    #[serde(rename = "invitationId")]
    pub invitation_id: String,
}

#[derive(Debug, Deserialize)]
pub struct CancelInvitationRequest {
    #[serde(rename = "invitationId")]
    pub invitation_id: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct GetInvitationQuery {
    pub id: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct ListInvitationsQuery {
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct HasPermissionRequest {
    pub permissions: HashMap<String, Vec<String>>,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CheckSlugResponse {
    pub status: bool,
}

#[derive(Debug, Serialize)]
pub struct SuccessResponse {
    pub success: bool,
}

#[derive(Debug, Serialize)]
pub struct HasPermissionResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateOrganizationResponse<O: Serialize, M: Serialize> {
    #[serde(flatten)]
    pub organization: O,
    pub members: Vec<M>,
}

#[derive(Debug, Serialize)]
pub struct FullOrganizationResponse<O: Serialize, I: Serialize> {
    #[serde(flatten)]
    pub organization: O,
    pub members: Vec<MemberResponse>,
    pub invitations: Vec<I>,
}

#[derive(Debug, Serialize)]
pub struct InvitationResponse<I: Serialize> {
    pub invitation: I,
}

#[derive(Debug, Serialize)]
pub struct AcceptInvitationResponse<I: Serialize> {
    pub invitation: I,
    pub member: MemberResponse,
}

#[derive(Debug, Serialize)]
pub struct ListMembersResponse {
    pub members: Vec<MemberResponse>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct GetInvitationResponse<I: Serialize> {
    #[serde(flatten)]
    pub invitation: I,
    #[serde(rename = "organizationName")]
    pub organization_name: String,
    #[serde(rename = "organizationSlug")]
    pub organization_slug: String,
    #[serde(rename = "inviterEmail")]
    pub inviter_email: Option<String>,
}

/// Member with user details (for API responses).
///
/// Uses [`MemberUserView`] from `better_auth_core::entity` for user info,
/// making it work with any `DatabaseAdapter` implementation.
#[derive(Debug, Clone, Serialize)]
pub struct MemberResponse {
    pub id: String,
    #[serde(rename = "organizationId")]
    pub organization_id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    pub role: String,
    #[serde(rename = "createdAt")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub user: MemberUserView,
}

impl MemberResponse {
    /// Construct from any type implementing [`AuthMember`] and [`AuthUser`].
    pub fn from_member_and_user(
        member: &impl better_auth_core::entity::AuthMember,
        user: &impl better_auth_core::entity::AuthUser,
    ) -> Self {
        Self {
            id: member.id().to_string(),
            organization_id: member.organization_id().to_string(),
            user_id: member.user_id().to_string(),
            role: member.role().to_string(),
            created_at: member.created_at(),
            user: MemberUserView::from_user(user),
        }
    }
}
