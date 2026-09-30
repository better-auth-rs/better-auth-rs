use std::collections::HashMap;

/// Resource types for permission checks
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Resource {
    Organization,
    Member,
    Invitation,
    /// Organization-owned API keys. Upstream's default statements grant no
    /// role any action here; only the creator role is implicitly allowed.
    ApiKey,
    Team,
    AccessControl,
}

impl Resource {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "organization" => Some(Self::Organization),
            "member" => Some(Self::Member),
            "invitation" => Some(Self::Invitation),
            "apikey" => Some(Self::ApiKey),
            "team" => Some(Self::Team),
            "ac" => Some(Self::AccessControl),
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
    let _ = roles.insert(
        "owner".to_string(),
        Role {
            name: "owner".to_string(),
            permissions: {
                let mut p = HashMap::new();
                let _ = p.insert(Resource::Organization, vec![Action::Update, Action::Delete]);
                let _ = p.insert(
                    Resource::Member,
                    vec![Action::Create, Action::Update, Action::Delete],
                );
                let _ = p.insert(Resource::Invitation, vec![Action::Create, Action::Cancel]);
                let _ = p.insert(
                    Resource::Team,
                    vec![Action::Create, Action::Update, Action::Delete],
                );
                let _ = p.insert(
                    Resource::AccessControl,
                    vec![Action::Create, Action::Read, Action::Update, Action::Delete],
                );
                p
            },
        },
    );

    // Admin - most permissions except org deletion
    let _ = roles.insert(
        "admin".to_string(),
        Role {
            name: "admin".to_string(),
            permissions: {
                let mut p = HashMap::new();
                let _ = p.insert(Resource::Organization, vec![Action::Update]);
                let _ = p.insert(
                    Resource::Member,
                    vec![Action::Create, Action::Update, Action::Delete],
                );
                let _ = p.insert(Resource::Invitation, vec![Action::Create, Action::Cancel]);
                let _ = p.insert(
                    Resource::Team,
                    vec![Action::Create, Action::Update, Action::Delete],
                );
                let _ = p.insert(
                    Resource::AccessControl,
                    vec![Action::Create, Action::Read, Action::Update, Action::Delete],
                );
                p
            },
        },
    );

    // Member - read-only
    let _ = roles.insert(
        "member".to_string(),
        Role {
            name: "member".to_string(),
            permissions: HashMap::from([(Resource::AccessControl, vec![Action::Read])]),
        },
    );

    roles
}

/// Check if a role has permission for an action on a resource
pub fn has_permission(
    role: &str,
    resource: &Resource,
    action: &Action,
    custom_roles: &HashMap<String, crate::plugins::organization::RolePermissions>,
) -> bool {
    let default = default_roles();

    // Check custom roles first
    if let Some(custom_role) = custom_roles.get(role) {
        let actions = match resource {
            Resource::Organization => &custom_role.organization,
            Resource::Member => &custom_role.member,
            Resource::Invitation => &custom_role.invitation,
            Resource::ApiKey => &custom_role.api_key,
            Resource::Team => &custom_role.team,
            Resource::AccessControl => &custom_role.ac,
        };
        let action_str = match action {
            Action::Create => "create",
            Action::Read => "read",
            Action::Update => "update",
            Action::Delete => "delete",
            Action::Cancel => "cancel",
        };
        return actions.iter().any(|a| a == action_str);
    }

    if !custom_roles.is_empty() {
        return false;
    }

    // Fall back to default roles
    if let Some(role_def) = default.get(role)
        && let Some(actions) = role_def.permissions.get(resource)
    {
        return actions.contains(action);
    }

    false
}

type Statements = HashMap<String, Vec<String>>;

fn role_statements(roles: &HashMap<String, super::RolePermissions>) -> HashMap<String, Statements> {
    if roles.is_empty() {
        return default_roles()
            .into_iter()
            .map(|(name, role)| {
                let statements = role
                    .permissions
                    .into_iter()
                    .map(|(resource, actions)| {
                        (
                            resource.as_str().to_owned(),
                            actions
                                .into_iter()
                                .map(|action| action.as_str().to_owned())
                                .collect(),
                        )
                    })
                    .collect();
                (name, statements)
            })
            .collect();
    }
    roles
        .iter()
        .map(|(name, role)| {
            let mut statements = role.additional.clone();
            for (resource, actions) in [
                ("organization", &role.organization),
                ("member", &role.member),
                ("invitation", &role.invitation),
                ("apikey", &role.api_key),
                ("team", &role.team),
                ("ac", &role.ac),
            ] {
                let _ = statements.insert(resource.to_owned(), actions.clone());
            }
            (name.clone(), statements)
        })
        .collect()
}

impl Resource {
    /// Return the upstream resource name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Organization => "organization",
            Self::Member => "member",
            Self::Invitation => "invitation",
            Self::ApiKey => "apikey",
            Self::Team => "team",
            Self::AccessControl => "ac",
        }
    }
}

impl Action {
    /// Return the upstream action name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Read => "read",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Cancel => "cancel",
        }
    }
}

fn authorize(role: &str, permissions: &Statements, roles: &HashMap<String, Statements>) -> bool {
    !permissions.is_empty()
        && role.split(',').any(|name| {
            roles.get(name).is_some_and(|statements| {
                permissions.iter().all(|(resource, requested)| {
                    !requested.is_empty()
                        && statements.get(resource).is_some_and(|allowed| {
                            requested.iter().all(|action| allowed.contains(action))
                        })
                })
            })
        })
}

/// Check the complete permission request against each assigned role independently.
pub(crate) async fn check_permissions(
    role: &str,
    organization_id: &str,
    permissions: &Statements,
    config: &super::OrganizationConfig,
    ctx: &better_auth_core::AuthContext<impl better_auth_core::AuthSchema>,
) -> better_auth_core::AuthResult<bool> {
    let mut roles = role_statements(&config.roles);
    if config.dynamic_access_control && config.ac.is_some() {
        for row in ctx
            .database
            .list_organization_roles(organization_id)
            .await?
        {
            let stored: Statements = serde_json::from_value(row.permission)?;
            let statements = roles.entry(row.role).or_default();
            for (resource, actions) in stored {
                let allowed = statements.entry(resource).or_default();
                for action in actions {
                    if !allowed.contains(&action) {
                        allowed.push(action);
                    }
                }
            }
        }
    }
    Ok(authorize(role, permissions, &roles))
}

/// Authorize one resource through the organization's configured and persisted roles.
pub(crate) async fn check_permission(
    role: &str,
    organization_id: &str,
    resource: &str,
    actions: &[&str],
    config: &super::OrganizationConfig,
    ctx: &better_auth_core::AuthContext<impl better_auth_core::AuthSchema>,
) -> better_auth_core::AuthResult<bool> {
    check_permissions(
        role,
        organization_id,
        &HashMap::from([(
            resource.to_owned(),
            actions.iter().map(|action| (*action).to_owned()).collect(),
        )]),
        config,
        ctx,
    )
    .await
}

/// Handle composite roles (comma-separated)
pub fn has_permission_any(
    roles_str: &str,
    resource: &Resource,
    action: &Action,
    custom_roles: &HashMap<String, crate::plugins::organization::RolePermissions>,
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
    fn composite_roles_must_each_authorize_the_complete_request() {
        let roles = HashMap::from([
            (
                "reader".into(),
                HashMap::from([("team".into(), vec!["read".into()])]),
            ),
            (
                "writer".into(),
                HashMap::from([("team".into(), vec!["update".into()])]),
            ),
        ]);
        assert!(!authorize(
            "reader,writer",
            &HashMap::from([("team".into(), vec!["read".into(), "update".into()])]),
            &roles
        ));
        assert!(authorize(
            "reader,writer",
            &HashMap::from([("team".into(), vec!["update".into()])]),
            &roles
        ));
        assert!(!authorize(
            "reader",
            &HashMap::from([("team".into(), vec![])]),
            &roles
        ));
        assert!(!authorize("reader", &HashMap::new(), &roles));
    }

    #[test]
    fn configured_roles_replace_default_permissions() {
        let custom =
            HashMap::from([("owner".to_owned(), super::super::RolePermissions::default())]);
        assert!(!has_permission(
            "owner",
            &Resource::Organization,
            &Action::Delete,
            &custom
        ));
        assert!(!has_permission(
            "admin",
            &Resource::Organization,
            &Action::Update,
            &custom
        ));
    }

    // Upstream reference: packages/better-auth/src/plugins/access/access.test.ts and packages/better-auth/src/plugins/organization/access/statement.ts; adapted to the Rust organization RBAC helpers.
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

    // Upstream reference: packages/better-auth/src/plugins/access/access.test.ts and packages/better-auth/src/plugins/organization/access/statement.ts; adapted to the Rust organization RBAC helpers.
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

    // Upstream reference: packages/better-auth/src/plugins/access/access.test.ts and packages/better-auth/src/plugins/organization/access/statement.ts; adapted to the Rust organization RBAC helpers.
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

    // Upstream reference: packages/better-auth/src/plugins/access/access.test.ts and packages/better-auth/src/plugins/organization/access/statement.ts; adapted to the Rust organization RBAC helpers.
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
