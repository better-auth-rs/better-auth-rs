use better_auth_core::entity::MemberUserView;
use better_auth_core::entity::{AuthMember, AuthOrganization};
use better_auth_core::{SchemaField, SchemaValue};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use validator::Validate;

mod input_fields;
mod native_fields;

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(untagged)]
pub enum NullableStringField {
    #[default]
    Missing,
    Null,
    Value(String),
}

impl NullableStringField {
    pub(crate) fn is_missing(&self) -> bool {
        matches!(self, Self::Missing)
    }
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum RoleInput {
    One(String),
    Many(Vec<String>),
}

impl better_auth_core::SchemaField for RoleInput {
    fn from_field(
        value: better_auth_core::FieldValue,
    ) -> Result<Self, better_auth_core::FieldValue> {
        match String::from_field(value) {
            Ok(value) => Ok(Self::One(value)),
            Err(value) => Vec::<String>::from_field(value).map(Self::Many),
        }
    }

    fn into_field(self) -> better_auth_core::FieldValue {
        match self {
            Self::One(value) => value.into_field(),
            Self::Many(value) => value.into_field(),
        }
    }
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
) -> Result<Option<better_auth_core::FieldValue>, D::Error> {
    better_auth_core::field_value::serde::value::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct CreateOrganizationRequest {
    #[serde(flatten)]
    #[serde(with = "better_auth_core::field_value::serde::map")]
    pub additional_fields: better_auth_core::FieldMap,

    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub name: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub slug: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub logo: SchemaValue<Option<String>>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub metadata: SchemaValue<Option<better_auth_core::FieldValue>>,
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
    #[serde(rename = "keepCurrentActiveOrganization")]
    pub keep_current_active_organization: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateOrganizationData {
    #[serde(flatten)]
    #[serde(with = "better_auth_core::field_value::serde::map")]
    pub additional_fields: better_auth_core::FieldMap,

    #[serde(default, deserialize_with = "deserialize_nullable_string_field")]
    pub name: NullableStringField,
    #[serde(default, deserialize_with = "deserialize_nullable_string_field")]
    pub slug: NullableStringField,
    #[serde(default, deserialize_with = "deserialize_nullable_string_field")]
    pub logo: NullableStringField,
    #[serde(default, deserialize_with = "deserialize_present_metadata")]
    pub metadata: Option<better_auth_core::FieldValue>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateOrganizationRequest {
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    pub data: UpdateOrganizationData,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct DeleteOrganizationRequest {
    #[serde(rename = "organizationId")]
    pub organization_id: String,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CheckSlugRequest {
    pub slug: String,
}

#[derive(Debug, Clone, Deserialize, Validate)]
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

#[derive(Debug, Clone, Deserialize, Validate)]
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
        deserialize_with = "better_auth_core::query::optional_nonzero_number"
    )]
    pub members_limit: Option<f64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct InviteMemberRequest {
    #[serde(flatten)]
    #[serde(with = "better_auth_core::field_value::serde::map")]
    pub additional_fields: better_auth_core::FieldMap,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub email: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub role: SchemaValue<RoleInput>,
    #[serde(
        default,
        rename = "organizationId",
        skip_serializing_if = "SchemaValue::is_json_omitted"
    )]
    pub organization_id: SchemaValue<String>,
    #[serde(
        default,
        rename = "teamId",
        skip_serializing_if = "SchemaValue::is_json_omitted"
    )]
    pub team_id: SchemaValue<RoleInput>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub resend: SchemaValue<bool>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct RemoveMemberRequest {
    #[serde(rename = "memberIdOrEmail")]
    pub member_id_or_email: String,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
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
    #[serde(
        default,
        deserialize_with = "better_auth_core::query::optional_nonzero_number"
    )]
    pub limit: Option<f64>,
    #[serde(
        default,
        deserialize_with = "better_auth_core::query::optional_nonzero_number"
    )]
    pub offset: Option<f64>,
    #[serde(rename = "sortBy")]
    pub sort_by: Option<String>,
    #[serde(rename = "sortDirection")]
    pub sort_direction: Option<String>,
    #[serde(rename = "filterField")]
    pub filter_field: Option<String>,
    #[serde(rename = "filterValue")]
    pub filter_value: Option<serde_json::Value>,
    #[serde(rename = "filterOperator")]
    pub filter_operator: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct AcceptInvitationRequest {
    #[serde(rename = "invitationId")]
    pub invitation_id: String,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct RejectInvitationRequest {
    #[serde(rename = "invitationId")]
    pub invitation_id: String,
}

#[derive(Debug, Clone, Deserialize, Validate)]
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

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct HasPermissionRequest {
    pub permissions: Option<HashMap<String, Vec<String>>>,
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
    /// Source property order, independent of the current typed values.
    #[serde(skip)]
    pub field_order: Vec<String>,
    #[serde(flatten)]
    #[serde(with = "better_auth_core::field_value::serde::map")]
    pub additional_fields: better_auth_core::FieldMap,

    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub id: SchemaValue<String>,
    #[serde(rename = "userId")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub user_id: SchemaValue<String>,
    #[serde(rename = "organizationId")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub organization_id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub role: SchemaValue<String>,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "better_auth_core::schema_value::serialize_date")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub created_at: SchemaValue<better_auth_core::FieldDate>,
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
    #[serde(skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub role: SchemaValue<String>,
}

#[derive(Debug, Serialize)]
pub struct GetInvitationResponse<I: Serialize> {
    #[serde(flatten)]
    pub invitation: I,
    #[serde(rename = "organizationName")]
    pub organization_name: SchemaValue<String>,
    #[serde(rename = "organizationSlug")]
    pub organization_slug: SchemaValue<String>,
    #[serde(
        rename = "inviterEmail",
        skip_serializing_if = "SchemaValue::is_json_omitted"
    )]
    pub inviter_email: SchemaValue<Option<String>>,
}

#[derive(Debug, Serialize)]
pub struct UserInvitationResponse<I: Serialize> {
    #[serde(flatten)]
    pub invitation: I,
    #[serde(
        rename = "organizationName",
        skip_serializing_if = "SchemaValue::is_json_omitted"
    )]
    pub organization_name: SchemaValue<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreatedOrganizationResponse {
    #[serde(flatten)]
    #[serde(with = "better_auth_core::field_value::serde::map")]
    pub additional_fields: better_auth_core::FieldMap,

    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub name: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub slug: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub logo: SchemaValue<Option<String>>,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "better_auth_core::schema_value::serialize_date")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub created_at: SchemaValue<better_auth_core::FieldDate>,

    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub metadata: SchemaValue<Option<better_auth_core::FieldValue>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OrganizationResponse {
    #[serde(flatten)]
    #[serde(with = "better_auth_core::field_value::serde::map")]
    pub additional_fields: better_auth_core::FieldMap,

    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub name: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub slug: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub logo: SchemaValue<Option<String>>,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "better_auth_core::schema_value::serialize_date")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub created_at: SchemaValue<better_auth_core::FieldDate>,

    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub metadata: SchemaValue<Option<better_auth_core::FieldValue>>,
}

impl CreatedOrganizationResponse {
    pub fn from_organization(organization: &impl AuthOrganization) -> Self {
        Self {
            additional_fields: organization.projected_fields().cloned().unwrap_or_default(),
            id: organization.id().into_owned(),
            name: organization.name().clone(),
            slug: organization.slug().clone(),
            logo: organization.logo().clone(),
            created_at: organization.created_at().clone(),
            metadata: organization.metadata().clone(),
        }
    }
}

impl OrganizationResponse {
    /// Creation and update adapter outputs decode the stored JSON text.
    pub fn from_created_organization(organization: &impl AuthOrganization) -> Self {
        let mut output = Self::from_organization(organization);
        output.metadata = organization.metadata().clone();
        output
    }
    pub fn from_organization(organization: &impl AuthOrganization) -> Self {
        Self {
            additional_fields: organization.projected_fields().cloned().unwrap_or_default(),
            id: organization.id().into_owned(),
            name: organization.name().clone(),
            slug: organization.slug().clone(),
            logo: organization.logo().clone(),
            created_at: organization.created_at().clone(),
            metadata: organization.metadata().clone(),
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
    #[serde(with = "better_auth_core::field_value::serde::map")]
    pub additional_fields: better_auth_core::FieldMap,

    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub id: SchemaValue<String>,
    #[serde(rename = "organizationId")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub organization_id: SchemaValue<String>,
    #[serde(rename = "userId")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub user_id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub role: SchemaValue<String>,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "better_auth_core::schema_value::serialize_date")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub created_at: SchemaValue<better_auth_core::FieldDate>,
    pub user: MemberUserView,
}

impl MemberResponse {
    /// Construct from projected member fields and the Organization adapter's user summary.
    pub fn from_member_and_user(
        member: &impl better_auth_core::entity::AuthMember,
        user: &MemberUserView,
    ) -> Self {
        Self {
            additional_fields: member.projected_fields().cloned().unwrap_or_default(),
            id: member.id().into_owned(),
            organization_id: member.organization_id().clone(),
            user_id: member.user_id().clone(),
            role: member.role().clone(),
            created_at: member.created_at().clone(),
            user: user.clone(),
        }
    }
}

impl BasicMemberResponse {
    pub fn try_from_member(member: &impl AuthMember) -> better_auth_core::AuthResult<Self> {
        let member = better_auth_core::Member::try_from_member(member)?;
        Ok(Self {
            field_order: member.field_order,
            additional_fields: member.additional_fields,
            id: member.id,
            organization_id: member.organization_id,
            user_id: member.user_id,
            role: member.role,
            created_at: member.created_at,
        })
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

        assert_eq!(string_limit.members_limit, Some(1.0));
        assert_eq!(number_limit.members_limit, Some(2.0));
    }
}

/// Team fields returned by the full organization join.
#[derive(Debug, Serialize)]
pub struct FullOrganizationTeam {
    #[serde(flatten)]
    pub team: better_auth_core::types::Team,
}
