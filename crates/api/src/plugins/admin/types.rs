use std::collections::HashMap;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;

/// Role input accepted by TypeScript admin routes.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum RoleInput {
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

    pub(crate) fn roles(&self) -> Vec<&str> {
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

    pub(crate) fn is_empty(&self) -> bool {
        self.roles().is_empty()
    }
}

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct SetRoleRequest {
    #[serde(rename = "userId")]
    #[validate(length(min = 1, message = "userId is required"))]
    pub user_id: String,
    pub role: RoleInput,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct GetUserQuery {
    #[validate(length(min = 1, message = "id is required"))]
    pub id: String,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct CreateUserRequest {
    #[validate(email(message = "Invalid email address"))]
    pub email: String,
    pub password: Option<String>,
    #[validate(length(min = 1, message = "Name is required"))]
    pub name: String,
    pub role: Option<RoleInput>,
    pub data: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct AdminUpdateUserRequest {
    #[serde(rename = "userId")]
    #[validate(length(min = 1, message = "userId is required"))]
    pub user_id: String,
    pub data: serde_json::Map<String, serde_json::Value>,
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
#[expect(
    dead_code,
    reason = "server-side HTTP route currently checks session user only"
)]
pub(crate) struct HasPermissionRequest {
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
    pub role: Option<String>,
    pub permission: Option<HashMap<String, Vec<String>>>,
    pub permissions: Option<HashMap<String, Vec<String>>>,
}

impl HasPermissionRequest {
    pub(crate) fn requested_permissions(&self) -> Option<&HashMap<String, Vec<String>>> {
        self.permissions.as_ref().or(self.permission.as_ref())
    }
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub(crate) struct AdminUserView {
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    #[serde(rename = "emailVerified")]
    pub email_verified: bool,
    pub image: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
    pub username: Option<String>,
    #[serde(rename = "displayUsername")]
    pub display_username: Option<String>,
    #[serde(rename = "twoFactorEnabled")]
    pub two_factor_enabled: bool,
    pub role: Option<String>,
    pub banned: bool,
    #[serde(rename = "banReason")]
    pub ban_reason: Option<String>,
    #[serde(rename = "banExpires")]
    pub ban_expires: Option<String>,
}

impl<T: better_auth_core::entity::AuthUser> From<&T> for AdminUserView {
    fn from(user: &T) -> Self {
        Self {
            id: user.id().into_owned(),
            name: user.name().map(str::to_owned),
            email: user.email().map(str::to_owned),
            email_verified: user.email_verified(),
            image: user.image().map(str::to_owned),
            created_at: user.created_at(),
            updated_at: user.updated_at(),
            username: user.username().map(str::to_owned),
            display_username: user.display_username().map(str::to_owned),
            two_factor_enabled: user.two_factor_enabled(),
            role: user.role().map(str::to_owned),
            banned: user.banned(),
            ban_reason: user.ban_reason().map(str::to_owned),
            ban_expires: user
                .ban_expires()
                .map(|value| value.to_rfc3339_opts(SecondsFormat::Millis, true)),
        }
    }
}

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
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
