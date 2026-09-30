//! Organization teams and dynamic access-control records.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A team belonging to one organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Team {
    pub id: String,
    pub name: String,
    pub organization_id: String,
    #[serde(serialize_with = "crate::utils::date::serialize")]
    pub created_at: DateTime<Utc>,
    #[serde(serialize_with = "crate::utils::date::serialize_option")]
    pub updated_at: Option<DateTime<Utc>>,
}

/// Data required to create a team.
#[derive(Debug, Clone)]
pub struct CreateTeam {
    pub updated_at: Option<DateTime<Utc>>,
    pub name: String,
    pub organization_id: String,
}

/// A user's membership in a team.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamMember {
    pub id: String,
    pub team_id: String,
    pub user_id: String,
    #[serde(serialize_with = "crate::utils::date::serialize")]
    pub created_at: DateTime<Utc>,
}

/// A dynamic role scoped to one organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationRole {
    pub id: String,
    pub organization_id: String,
    pub role: String,
    pub permission: serde_json::Value,
    #[serde(serialize_with = "crate::utils::date::serialize")]
    pub created_at: DateTime<Utc>,
    #[serde(serialize_with = "crate::utils::date::serialize_option")]
    pub updated_at: Option<DateTime<Utc>>,
}

/// Data required to create a dynamic role.
#[derive(Debug, Clone)]
pub struct CreateOrganizationRole {
    pub organization_id: String,
    pub role: String,
    pub permission: serde_json::Value,
}

/// Mutable dynamic-role fields.
#[derive(Debug, Clone, Default)]
pub struct UpdateOrganizationRole {
    pub role: Option<String>,
    pub permission: Option<serde_json::Value>,
}
