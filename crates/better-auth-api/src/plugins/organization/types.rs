use better_auth_core::types::{Invitation, MemberWithUser, Organization};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use validator::Validate;

// ============================================================================
// Organization Requests
// ============================================================================

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

// ============================================================================
// Member Requests
// ============================================================================

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

// ============================================================================
// Invitation Requests
// ============================================================================

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

// ============================================================================
// Permission Requests
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct HasPermissionRequest {
    pub permissions: HashMap<String, Vec<String>>,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
}

// ============================================================================
// Responses
// ============================================================================

#[derive(Debug, Serialize)]
pub struct CreateOrganizationResponse {
    #[serde(flatten)]
    pub organization: Organization,
    pub members: Vec<MemberWithUser>,
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
pub struct InvitationResponse {
    pub invitation: Invitation,
}

#[derive(Debug, Serialize)]
pub struct AcceptInvitationResponse {
    pub invitation: Invitation,
    pub member: MemberWithUser,
}

#[derive(Debug, Serialize)]
pub struct HasPermissionResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListMembersResponse {
    pub members: Vec<MemberWithUser>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct GetInvitationResponse {
    #[serde(flatten)]
    pub invitation: Invitation,
    #[serde(rename = "organizationName")]
    pub organization_name: String,
    #[serde(rename = "organizationSlug")]
    pub organization_slug: String,
    #[serde(rename = "inviterEmail")]
    pub inviter_email: Option<String>,
}
