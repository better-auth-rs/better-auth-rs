//! Permission helpers for the admin plugin.

use std::collections::HashMap;

use super::AdminConfig;

/// Role-based permission grants for the admin plugin.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RolePermissions {
    /// Resource name -> allowed actions.
    pub permissions: HashMap<String, Vec<String>>,
}

impl RolePermissions {
    /// Create an empty role definition.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow a set of actions for one resource.
    pub fn allow<I, S>(mut self, resource: impl Into<String>, actions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let _ = self.permissions.insert(
            resource.into(),
            actions.into_iter().map(Into::into).collect(),
        );
        self
    }

    fn allows(&self, requested: &HashMap<String, Vec<String>>) -> bool {
        if requested.is_empty() {
            return false;
        }

        requested.iter().all(|(resource, actions)| {
            self.permissions.get(resource).is_some_and(|allowed| {
                actions
                    .iter()
                    .all(|action| allowed.iter().any(|item| item == action))
            })
        })
    }
}

pub(super) fn default_roles() -> HashMap<String, RolePermissions> {
    HashMap::from([
        (
            "admin".to_string(),
            RolePermissions::new()
                .allow(
                    "user",
                    [
                        "create",
                        "list",
                        "set-role",
                        "ban",
                        "impersonate",
                        "delete",
                        "set-password",
                        "get",
                        "update",
                    ],
                )
                .allow("session", ["list", "revoke", "delete"]),
        ),
        ("user".to_string(), RolePermissions::new()),
    ])
}

fn configured_roles(config: &AdminConfig) -> HashMap<String, RolePermissions> {
    if config.roles.is_empty() {
        default_roles()
    } else {
        config.roles.clone()
    }
}

fn role_names<'a>(role: Option<&'a str>, default_role: &'a str) -> Vec<&'a str> {
    role.unwrap_or(default_role)
        .split(',')
        .map(str::trim)
        .filter(|role| !role.is_empty())
        .collect()
}

pub(super) fn is_admin_user_id(user_id: Option<&str>, config: &AdminConfig) -> bool {
    user_id.is_some_and(|user_id| {
        config
            .admin_user_ids
            .as_ref()
            .is_some_and(|ids| ids.iter().any(|id| id == user_id))
    })
}

pub(super) fn has_permission(
    user_id: Option<&str>,
    role: Option<&str>,
    config: &AdminConfig,
    requested: &HashMap<String, Vec<String>>,
) -> bool {
    if is_admin_user_id(user_id, config) {
        return true;
    }

    let roles = configured_roles(config);
    role_names(role, &config.default_role)
        .into_iter()
        .filter_map(|role| roles.get(role))
        .any(|role| role.allows(requested))
}

pub(super) fn is_admin_role(role: Option<&str>, config: &AdminConfig) -> bool {
    role_names(role, &config.default_role)
        .into_iter()
        .any(|role| config.admin_roles.iter().any(|admin| admin == role))
}
