use std::collections::HashMap;

/// Resource types for permission checks
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Resource {
    Organization,
    Member,
    Invitation,
}

impl Resource {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "organization" => Some(Self::Organization),
            "member" => Some(Self::Member),
            "invitation" => Some(Self::Invitation),
            _ => None,
        }
    }
}

/// Actions that can be performed on resources
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Action {
    Create,
    Read,
    Update,
    Delete,
    Cancel,
}

impl Action {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "create" => Some(Self::Create),
            "read" => Some(Self::Read),
            "update" => Some(Self::Update),
            "delete" => Some(Self::Delete),
            "cancel" => Some(Self::Cancel),
            _ => None,
        }
    }
}

/// Permission definition
pub type Permissions = HashMap<Resource, Vec<Action>>;

/// Role with associated permissions
#[derive(Debug, Clone)]
pub struct Role {
    pub name: String,
    pub permissions: Permissions,
}

/// Get default role definitions matching TypeScript implementation
pub fn default_roles() -> HashMap<String, Role> {
    let mut roles = HashMap::new();

    // Owner - full permissions
    roles.insert(
        "owner".to_string(),
        Role {
            name: "owner".to_string(),
            permissions: {
                let mut p = HashMap::new();
                p.insert(Resource::Organization, vec![Action::Update, Action::Delete]);
                p.insert(
                    Resource::Member,
                    vec![Action::Create, Action::Update, Action::Delete],
                );
                p.insert(Resource::Invitation, vec![Action::Create, Action::Cancel]);
                p
            },
        },
    );

    // Admin - most permissions except org deletion
    roles.insert(
        "admin".to_string(),
        Role {
            name: "admin".to_string(),
            permissions: {
                let mut p = HashMap::new();
                p.insert(Resource::Organization, vec![Action::Update]);
                p.insert(
                    Resource::Member,
                    vec![Action::Create, Action::Update, Action::Delete],
                );
                p.insert(Resource::Invitation, vec![Action::Create, Action::Cancel]);
                p
            },
        },
    );

    // Member - read-only
    roles.insert(
        "member".to_string(),
        Role {
            name: "member".to_string(),
            permissions: HashMap::new(),
        },
    );

    roles
}

/// Check if a role has permission for an action on a resource
pub fn has_permission(
    role: &str,
    resource: &Resource,
    action: &Action,
    custom_roles: &HashMap<String, crate::plugins::organization::config::RolePermissions>,
) -> bool {
    let default = default_roles();

    // Check custom roles first
    if let Some(custom_role) = custom_roles.get(role) {
        let actions = match resource {
            Resource::Organization => &custom_role.organization,
            Resource::Member => &custom_role.member,
            Resource::Invitation => &custom_role.invitation,
        };
        let action_str = match action {
            Action::Create => "create",
            Action::Read => "read",
            Action::Update => "update",
            Action::Delete => "delete",
            Action::Cancel => "cancel",
        };
        if actions.iter().any(|a| a == action_str) {
            return true;
        }
    }

    // Fall back to default roles
    if let Some(role_def) = default.get(role)
        && let Some(actions) = role_def.permissions.get(resource)
    {
        return actions.contains(action);
    }

    false
}

/// Handle composite roles (comma-separated)
pub fn has_permission_any(
    roles_str: &str,
    resource: &Resource,
    action: &Action,
    custom_roles: &HashMap<String, crate::plugins::organization::config::RolePermissions>,
) -> bool {
    for role in roles_str.split(',').map(|s| s.trim()) {
        if has_permission(role, resource, action, custom_roles) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_owner_has_full_permissions() {
        let custom = HashMap::new();

        assert!(has_permission(
            "owner",
            &Resource::Organization,
            &Action::Update,
            &custom
        ));
        assert!(has_permission(
            "owner",
            &Resource::Organization,
            &Action::Delete,
            &custom
        ));
        assert!(has_permission(
            "owner",
            &Resource::Member,
            &Action::Create,
            &custom
        ));
        assert!(has_permission(
            "owner",
            &Resource::Invitation,
            &Action::Cancel,
            &custom
        ));
    }

    #[test]
    fn test_admin_cannot_delete_organization() {
        let custom = HashMap::new();

        assert!(has_permission(
            "admin",
            &Resource::Organization,
            &Action::Update,
            &custom
        ));
        assert!(!has_permission(
            "admin",
            &Resource::Organization,
            &Action::Delete,
            &custom
        ));
    }

    #[test]
    fn test_member_has_no_permissions() {
        let custom = HashMap::new();

        assert!(!has_permission(
            "member",
            &Resource::Organization,
            &Action::Update,
            &custom
        ));
        assert!(!has_permission(
            "member",
            &Resource::Member,
            &Action::Create,
            &custom
        ));
    }

    #[test]
    fn test_composite_roles() {
        let custom = HashMap::new();

        // member,admin should have admin permissions
        assert!(has_permission_any(
            "member,admin",
            &Resource::Organization,
            &Action::Update,
            &custom
        ));

        // member alone should not
        assert!(!has_permission_any(
            "member",
            &Resource::Organization,
            &Action::Update,
            &custom
        ));
    }
}
