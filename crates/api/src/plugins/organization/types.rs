use better_auth_core::entity::AuthMember;
use better_auth_core::entity::MemberUserView;
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
    pub error: Option<String>,
    pub success: bool,
}

#[derive(Debug, Serialize)]
pub struct CreateOrganizationResponse<O: Serialize, M: Serialize> {
    #[serde(flatten)]
    pub organization: O,
    pub members: Vec<M>,
}

#[derive(Debug, Serialize)]
pub struct InvitationResponse<I: Serialize> {
    pub invitation: I,
}

#[derive(Debug, Serialize)]
pub struct RemovedMemberResponse {
    pub member: RemovedMember,
}

/// Complete removed membership; email lookup retains its native `user` summary.
pub type RemovedMember = better_auth_core::Member;

/// Complete projected membership with native field values and source property order.
pub type BasicMemberResponse = better_auth_core::Member;

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

/// Complete Organization output with native fields and source property order.
pub type CreatedOrganizationResponse = better_auth_core::Organization;
pub type OrganizationResponse = better_auth_core::Organization;

/// Complete projected membership and the Organization adapter's user summary.
#[derive(Debug, Clone)]
pub struct MemberResponse {
    pub member: BasicMemberResponse,
    pub user: MemberUserView,
}

impl From<better_auth_core::store::MemberUser> for MemberResponse {
    fn from(joined: better_auth_core::store::MemberUser) -> Self {
        Self {
            member: joined.member,
            user: joined.user,
        }
    }
}

impl MemberResponse {
    /// Preserve the projected membership's property order and native values.
    pub fn try_from_member_and_user(
        member: &impl AuthMember,
        user: &MemberUserView,
    ) -> better_auth_core::AuthResult<Self> {
        Ok(Self {
            member: BasicMemberResponse::try_from_member(member)?,
            user: user.clone(),
        })
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "Required fixture operations must succeed before comparing the contract."
)]
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
