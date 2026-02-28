use serde::{Deserialize, Serialize};
use validator::Validate;

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct SetRoleRequest {
    #[serde(rename = "userId")]
    #[validate(length(min = 1, message = "userId is required"))]
    pub user_id: String,
    #[validate(length(min = 1, message = "role is required"))]
    pub role: String,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct CreateUserRequest {
    #[validate(email(message = "Invalid email address"))]
    pub email: String,
    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
    #[validate(length(min = 1, message = "Name is required"))]
    pub name: String,
    pub role: Option<String>,
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct UserIdRequest {
    #[serde(rename = "userId")]
    #[validate(length(min = 1, message = "userId is required"))]
    pub user_id: String,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct BanUserRequest {
    #[serde(rename = "userId")]
    #[validate(length(min = 1, message = "userId is required"))]
    pub user_id: String,
    #[serde(rename = "banReason")]
    pub ban_reason: Option<String>,
    /// Number of seconds until the ban expires.
    #[serde(rename = "banExpiresIn")]
    pub ban_expires_in: Option<i64>,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct RevokeSessionRequest {
    #[serde(rename = "sessionToken")]
    #[validate(length(min = 1, message = "sessionToken is required"))]
    pub session_token: String,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct SetUserPasswordRequest {
    #[serde(rename = "userId")]
    #[validate(length(min = 1, message = "userId is required"))]
    pub user_id: String,
    #[serde(rename = "newPassword")]
    #[validate(length(min = 1, message = "newPassword is required"))]
    pub new_password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct HasPermissionRequest {
    pub permission: Option<serde_json::Value>,
    pub permissions: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub(crate) struct UserResponse<U: Serialize> {
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
    pub limit: usize,
    pub offset: usize,
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
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Query parameters for `list_users`.
#[derive(Debug, Deserialize)]
pub(crate) struct ListUsersQueryParams {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
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
    pub filter_value: Option<String>,
    #[serde(rename = "filterOperator")]
    pub filter_operator: Option<String>,
}
