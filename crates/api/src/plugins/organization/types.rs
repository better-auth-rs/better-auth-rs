use better_auth_core::entity::MemberUserView;
use better_auth_core::entity::{AuthMember, AuthOrganization};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use validator::Validate;

fn deserialize_optional_usize_from_string<'de, D>(
    deserializer: D,
) -> Result<Option<usize>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Value {
        Number(usize),
        String(String),
    }

    let value = Option::<Value>::deserialize(deserializer)?;
    match value {
        None => Ok(None),
        Some(Value::Number(number)) => Ok(Some(number)),
        Some(Value::String(string)) => string
            .parse::<usize>()
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum NullableStringField {
    #[default]
    Missing,
    Null,
    Value(String),
}

pub(crate) fn deserialize_nullable_string_field<'de, D>(
    deserializer: D,
) -> Result<NullableStringField, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    Ok(match value {
        Some(value) => NullableStringField::Value(value),
        None => NullableStringField::Null,
    })
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum RoleInput {
    One(String),
    Many(Vec<String>),
}

impl RoleInput {
    pub fn joined(&self) -> String {
        match self {
            Self::One(role) => role.clone(),
            Self::Many(roles) => roles.join(","),
        }
    }

    pub fn roles(&self) -> Vec<&str> {
        match self {
            Self::One(role) => role
                .split(',')
                .map(str::trim)
                .filter(|role| !role.is_empty())
                .collect(),
            Self::Many(roles) => roles
                .iter()
                .flat_map(|role| role.split(','))
                .map(str::trim)
                .filter(|role| !role.is_empty())
                .collect(),
        }
    }
}

fn deserialize_present_metadata<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<serde_json::Value>, D::Error> {
    serde_json::Value::deserialize(deserializer).map(Some)
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateOrganizationRequest {
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,

    #[validate(length(min = 1, message = "Name is required"))]
    pub name: String,
    #[validate(length(min = 1, max = 100, message = "Slug must be 1-100 characters"))]
    pub slug: String,
    pub logo: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_metadata")]
    pub metadata: Option<serde_json::Value>,
    #[serde(rename = "keepCurrentActiveOrganization")]
    pub keep_current_active_organization: Option<bool>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateOrganizationData {
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,

    pub name: Option<String>,
    pub slug: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nullable_string_field")]
    pub logo: NullableStringField,
    #[serde(default, deserialize_with = "deserialize_present_metadata")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateOrganizationRequest {
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    pub data: UpdateOrganizationData,
}

#[derive(Debug, Deserialize, Validate)]
pub struct DeleteOrganizationRequest {
    #[serde(rename = "organizationId")]
    pub organization_id: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CheckSlugRequest {
    pub slug: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct SetActiveOrganizationRequest {
    #[serde(
        default,
        rename = "organizationId",
        deserialize_with = "deserialize_nullable_string_field"
    )]
    pub organization_id: NullableStringField,
    #[serde(rename = "organizationSlug")]
    pub organization_slug: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
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
    #[serde(
        default,
        rename = "membersLimit",
        deserialize_with = "deserialize_optional_usize_from_string"
    )]
    pub members_limit: Option<usize>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct InviteMemberRequest {
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,

    #[validate(email(message = "Invalid email address"))]
    pub email: String,
    pub role: RoleInput,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    #[serde(rename = "teamId")]
    pub team_id: Option<RoleInput>,
    /// Renew and send an existing pending invitation.
    #[serde(default)]
    pub resend: bool,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RemoveMemberRequest {
    #[serde(rename = "memberIdOrEmail")]
    pub member_id_or_email: String,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateMemberRoleRequest {
    #[serde(rename = "memberId")]
    pub member_id: String,
    pub role: RoleInput,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ListMembersQuery {
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    #[serde(rename = "organizationSlug")]
    pub organization_slug: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_usize_from_string")]
    pub limit: Option<usize>,
    #[serde(default, deserialize_with = "deserialize_optional_usize_from_string")]
    pub offset: Option<usize>,
    #[serde(rename = "sortBy")]
    pub sort_by: Option<String>,
    #[serde(rename = "sortDirection")]
    pub sort_direction: Option<String>,
    #[serde(rename = "filterField")]
    pub filter_field: Option<String>,
    #[serde(rename = "filterValue")]
    pub filter_value: Option<String>,
    #[serde(rename = "filterOperator")]
    pub filter_operator: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct AcceptInvitationRequest {
    #[serde(rename = "invitationId")]
    pub invitation_id: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RejectInvitationRequest {
    #[serde(rename = "invitationId")]
    pub invitation_id: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CancelInvitationRequest {
    #[serde(rename = "invitationId")]
    pub invitation_id: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct GetInvitationQuery {
    pub id: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct GetActiveMemberRoleQuery {
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    #[serde(rename = "organizationSlug")]
    pub organization_slug: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ListInvitationsQuery {
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub teams: Option<Vec<FullOrganizationTeam>>,
}

#[derive(Debug, Serialize)]
pub struct InvitationResponse<I: Serialize> {
    pub invitation: I,
}

#[derive(Debug, Serialize)]
pub struct RemovedMemberResponse {
    pub member: RemovedMember,
}

/// A removed membership; email lookup also includes the public user summary.
#[derive(Debug, Serialize)]
pub struct RemovedMember {
    #[serde(flatten)]
    pub member: BasicMemberResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<MemberUserView>,
}

#[derive(Debug, Serialize)]
pub struct BasicMemberResponse {
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,

    pub id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "organizationId")]
    pub organization_id: String,
    pub role: String,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "better_auth_core::utils::date::serialize")]
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct AcceptInvitationResponse<I: Serialize, M: Serialize> {
    pub invitation: I,
    pub member: M,
}

#[derive(Debug, Serialize)]
pub struct ListMembersResponse {
    pub members: Vec<MemberResponse>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct GetActiveMemberRoleResponse {
    pub role: String,
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

#[derive(Debug, Serialize)]
pub struct UserInvitationResponse<I: Serialize> {
    #[serde(flatten)]
    pub invitation: I,
    #[serde(rename = "organizationName")]
    pub organization_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreatedOrganizationResponse {
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,

    pub id: String,
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "better_auth_core::utils::date::serialize")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OrganizationResponse {
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,

    pub id: String,
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "better_auth_core::utils::date::serialize")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl CreatedOrganizationResponse {
    pub fn from_organization(organization: &impl AuthOrganization) -> Self {
        Self {
            additional_fields: organization.projected_fields().cloned().unwrap_or_default(),
            id: organization.id().to_string(),
            name: organization.name().to_string(),
            slug: organization.slug().to_string(),
            logo: organization.logo().map(str::to_owned),
            created_at: organization.created_at(),
            metadata: organization.metadata().cloned(),
        }
    }
}

impl OrganizationResponse {
    /// Creation and update adapter outputs decode the stored JSON text.
    pub fn from_created_organization(organization: &impl AuthOrganization) -> Self {
        let mut output = Self::from_organization(organization);
        output.metadata = organization.metadata().cloned();
        output
    }
    pub fn from_organization(organization: &impl AuthOrganization) -> Self {
        Self {
            additional_fields: organization.projected_fields().cloned().unwrap_or_default(),
            id: organization.id().to_string(),
            name: organization.name().to_string(),
            slug: organization.slug().to_string(),
            logo: organization.logo().map(str::to_owned),
            created_at: organization.created_at(),
            metadata: Some(
                organization
                    .metadata()
                    .map(|value| serde_json::Value::String(value.to_string()))
                    .unwrap_or(serde_json::Value::Null),
            ),
        }
    }
}

/// Member with user details (for API responses).
///
/// Uses [`MemberUserView`] from `better_auth_core::entity` for user info,
/// keeping it compatible with the built-in auth store.
#[derive(Debug, Clone, Serialize)]
pub struct MemberResponse {
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,

    pub id: String,
    #[serde(rename = "organizationId")]
    pub organization_id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    pub role: String,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "better_auth_core::utils::date::serialize")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub user: MemberUserView,
}

impl MemberResponse {
    /// Construct from any type implementing [`AuthMember`] and [`AuthUser`](better_auth_core::entity::AuthUser).
    pub fn from_member_and_user(
        member: &impl better_auth_core::entity::AuthMember,
        user: &impl better_auth_core::entity::AuthUser,
    ) -> Self {
        Self {
            additional_fields: member.projected_fields().cloned().unwrap_or_default(),
            id: member.id().to_string(),
            organization_id: member.organization_id().to_string(),
            user_id: member.user_id().to_string(),
            role: member.role().to_string(),
            created_at: member.created_at(),
            user: MemberUserView::from_user(user),
        }
    }
}

impl BasicMemberResponse {
    pub fn from_member(member: &impl AuthMember) -> Self {
        Self {
            additional_fields: member.projected_fields().cloned().unwrap_or_default(),
            id: member.id().to_string(),
            organization_id: member.organization_id().to_string(),
            user_id: member.user_id().to_string(),
            role: member.role().to_string(),
            created_at: member.created_at(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CreateOrganizationRequest, GetFullOrganizationQuery, NullableStringField,
        SetActiveOrganizationRequest,
    };

    #[test]
    fn set_active_request_distinguishes_missing_from_null() {
        let missing: SetActiveOrganizationRequest = serde_json::from_value(serde_json::json!({}))
            .expect("missing field should deserialize");
        let null: SetActiveOrganizationRequest = serde_json::from_value(serde_json::json!({
            "organizationId": null
        }))
        .expect("null field should deserialize");
        let value: SetActiveOrganizationRequest = serde_json::from_value(serde_json::json!({
            "organizationId": "org-123"
        }))
        .expect("string field should deserialize");

        assert!(matches!(
            missing.organization_id,
            NullableStringField::Missing
        ));
        assert!(matches!(null.organization_id, NullableStringField::Null));
        assert!(matches!(
            value.organization_id,
            NullableStringField::Value(ref organization_id) if organization_id == "org-123"
        ));
    }

    #[test]
    fn create_organization_request_deserializes_keep_current_active_organization() {
        let request: CreateOrganizationRequest = serde_json::from_value(serde_json::json!({
            "name": "Acme",
            "slug": "acme",
            "keepCurrentActiveOrganization": true
        }))
        .expect("request should deserialize");

        assert_eq!(request.keep_current_active_organization, Some(true));
    }

    #[test]
    fn get_full_organization_query_deserializes_members_limit_from_string_or_number() {
        let string_limit: GetFullOrganizationQuery = serde_json::from_value(serde_json::json!({
            "membersLimit": "1"
        }))
        .expect("string limit should deserialize");
        let number_limit: GetFullOrganizationQuery = serde_json::from_value(serde_json::json!({
            "membersLimit": 2
        }))
        .expect("number limit should deserialize");

        assert_eq!(string_limit.members_limit, Some(1));
        assert_eq!(number_limit.members_limit, Some(2));
    }
}

/// Team fields returned by the full organization join.
#[derive(Debug, Serialize)]
pub struct FullOrganizationTeam {
    #[serde(flatten)]
    pub team: better_auth_core::types::Team,
    #[serde(rename = "memberCount")]
    pub member_count: usize,
}
