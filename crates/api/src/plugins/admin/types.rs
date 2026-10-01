use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Role input accepted by TypeScript admin routes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RoleInput {
    One(String),
    Many(Vec<String>),
}

impl RoleInput {
    pub(crate) fn joined(&self) -> String {
        match self {
            Self::One(role) => role.clone(),
            Self::Many(roles) => roles.join(","),
        }
    }

    pub(crate) fn roles(&self) -> &[String] {
        match self {
            Self::One(role) => std::slice::from_ref(role),
            Self::Many(roles) => roles,
        }
    }
}

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SetRoleRequest {
    #[serde(rename = "userId")]
    pub user_id: String,
    pub role: RoleInput,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct GetUserQuery {
    pub id: String,
}

/// User provisioned by an administrator or trusted requestless server code.
#[derive(Debug, Clone, Serialize, Deserialize, validator::Validate)]
pub struct CreateUserRequest {
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<RoleInput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct AdminUpdateUserRequest {
    #[serde(rename = "userId")]
    pub user_id: String,
    pub data: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct UserIdRequest {
    #[serde(rename = "userId")]
    pub user_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct BanUserRequest {
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "banReason")]
    pub ban_reason: Option<String>,
    #[serde(rename = "banExpiresIn")]
    pub ban_expires_in: Option<f64>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RevokeSessionRequest {
    #[serde(rename = "sessionToken")]
    pub session_token: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SetUserPasswordRequest {
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "newPassword")]
    pub new_password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct HasPermissionRequest {
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
    pub role: Option<String>,
    pub permissions: Option<HashMap<String, Vec<String>>>,
}

impl HasPermissionRequest {
    pub(crate) fn requested_permissions(&self) -> Option<&HashMap<String, Vec<String>>> {
        self.permissions.as_ref()
    }
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

pub(crate) type AdminUserView = better_auth_core::wire::UserView;

#[derive(Debug, Serialize)]
pub struct UserResponse<U: Serialize> {
    pub user: U,
}

#[derive(Debug, Serialize)]
pub(crate) struct SessionUserResponse<S: Serialize, U: Serialize> {
    pub session: S,
    pub user: U,
}

#[derive(Debug, Serialize)]
pub(crate) struct ListUsersResponse<U: Serialize> {
    pub users: Vec<U>,
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<f64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ListSessionsResponse<S: Serialize> {
    pub sessions: Vec<S>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SuccessResponse {
    pub success: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct PermissionResponse {
    pub error: Option<String>,
    pub success: bool,
}

/// Query parameters for `list_users`.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct ListUsersQueryParams {
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
    #[serde(rename = "searchField")]
    pub search_field: Option<String>,
    #[serde(rename = "searchValue")]
    pub search_value: Option<String>,
    #[serde(rename = "searchOperator")]
    pub search_operator: Option<String>,
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
