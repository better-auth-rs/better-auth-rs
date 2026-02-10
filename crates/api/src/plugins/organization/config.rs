use std::collections::HashMap;

/// Configuration for the Organization plugin
#[derive(Debug, Clone)]
pub struct OrganizationConfig {
    /// Allow users to create organizations (default: true)
    pub allow_user_to_create_organization: bool,
    /// Maximum organizations per user (None = unlimited)
    pub organization_limit: Option<usize>,
    /// Maximum members per organization (None = unlimited)
    pub membership_limit: Option<usize>,
    /// Role assigned to organization creator (default: "owner")
    pub creator_role: String,
    /// Invitation expiration in seconds (default: 48 hours)
    pub invitation_expires_in: u64,
    /// Maximum pending invitations per organization (None = unlimited)
    pub invitation_limit: Option<usize>,
    /// Disable organization deletion (default: false)
    pub disable_organization_deletion: bool,
    /// Custom role definitions (extending default roles)
    pub roles: HashMap<String, RolePermissions>,
}

/// Permission definitions for a role
#[derive(Debug, Clone, Default)]
pub struct RolePermissions {
    pub organization: Vec<String>,
    pub member: Vec<String>,
    pub invitation: Vec<String>,
}

impl Default for OrganizationConfig {
    fn default() -> Self {
        Self {
            allow_user_to_create_organization: true,
            organization_limit: None,
            membership_limit: Some(100),
            creator_role: "owner".to_string(),
            invitation_expires_in: 60 * 60 * 48, // 48 hours
            invitation_limit: Some(100),
            disable_organization_deletion: false,
            roles: HashMap::new(),
        }
    }
}

impl OrganizationConfig {
    pub fn new() -> Self {
        Self::default()
    }
}
