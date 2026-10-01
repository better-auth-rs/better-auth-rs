//! Persisted organization access-control roles.

use std::collections::HashMap;

use better_auth_core::types::{
    CreateOrganizationRole, HttpMethod, OrganizationRole, UpdateOrganizationRole,
};
use better_auth_core::{AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema};
use serde::Deserialize;
use serde_json::json;
use validator::Validate;

use super::require_session;
use crate::plugins::organization::{OrganizationConfig, rbac::check_permission};

type Permissions = HashMap<String, Vec<String>>;

// Preserve request order because upstream returns missingPermissions in that order.
#[derive(Clone)]
struct RequestedPermissions(Vec<(String, serde_json::Value)>);

impl RequestedPermissions {
    fn dynamic(value: &serde_json::Value) -> Self {
        use serde_json::Value;
        Self(match value {
            Value::Object(fields) => fields
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
            Value::Array(values) => values
                .iter()
                .enumerate()
                .map(|(index, value)| (index.to_string(), value.clone()))
                .collect(),
            Value::String(value) => value
                .chars()
                .enumerate()
                .map(|(index, value)| (index.to_string(), json!(value.to_string())))
                .collect(),
            _ => Vec::new(),
        })
    }
}

impl<'de> Deserialize<'de> for RequestedPermissions {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = RequestedPermissions;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an object mapping resources to action arrays")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Self::Value, M::Error> {
                let mut permissions = Vec::new();
                while let Some((key, actions)) = map.next_entry::<String, Vec<String>>()? {
                    permissions.push((key, json!(actions)));
                }
                Ok(RequestedPermissions(permissions))
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}

impl serde::Serialize for RequestedPermissions {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(self.0.iter().map(|(resource, actions)| (resource, actions)))
    }
}

#[derive(Clone, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub(in crate::plugins::organization) struct CreateRole {
    #[serde(default)]
    additional_fields: OptionalField<serde_json::Map<String, serde_json::Value>>,
    organization_id: Option<String>,
    role: String,
    permission: RequestedPermissions,
}

#[derive(Clone, Default, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub(in crate::plugins::organization) struct RoleSelector {
    organization_id: Option<String>,
    role_name: Option<String>,
    role_id: Option<String>,
}

#[derive(Clone, Deserialize, Validate)]
pub(in crate::plugins::organization) struct UpdateRole {
    #[serde(flatten)]
    selector: RoleSelector,
    data: RoleUpdate,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::plugins::organization) struct RoleUpdate {
    #[serde(default)]
    role_name: OptionalField<String>,
    #[serde(default)]
    permission: OptionalField<RequestedPermissions>,
}

#[derive(Clone, Default)]
enum OptionalField<T> {
    #[default]
    Missing,
    Null,
    Value(T),
}
impl<'de, T: Deserialize<'de>> Deserialize<'de> for OptionalField<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match Option::<T>::deserialize(deserializer)? {
            Some(value) => Self::Value(value),
            None => Self::Null,
        })
    }
}
impl<T> OptionalField<T> {
    fn into_option(self) -> Option<T> {
        match self {
            Self::Value(value) => Some(value),
            _ => None,
        }
    }
}

fn role_error(action: &str) -> AuthError {
    let (code, message) = match action {
        "create" => (
            "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE",
            "You are not allowed to create a role",
        ),
        "update" => (
            "YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE",
            "You are not allowed to update a role",
        ),
        "delete" => (
            "YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE",
            "You are not allowed to delete a role",
        ),
        "list" => (
            "YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE",
            "You are not allowed to list a role",
        ),
        _ => (
            "YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE",
            "You are not allowed to read a role",
        ),
    };
    AuthError::Upstream {
        status: 403,
        code,
        message,
    }
}

fn require_ac(config: &OrganizationConfig) -> AuthResult<&Permissions> {
    config.ac.as_ref().ok_or(AuthError::Upstream {
        status: 501, code: "MISSING_AC_INSTANCE",
        message: "Dynamic Access Control requires a pre-defined ac instance on the server auth plugin. Read server logs for more information",
    })
}

fn predefined(name: &str, config: &OrganizationConfig) -> bool {
    config.roles.as_ref().map_or_else(
        || ["owner", "admin", "member"].contains(&name),
        |roles| roles.contains_key(name),
    )
}

async fn unused_name(
    name: &str,
    organization_id: &str,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl AuthSchema>,
) -> AuthResult<()> {
    if predefined(name, config)
        || ctx
            .database
            .list_organization_roles(organization_id)
            .await?
            .iter()
            .any(|role| role.role == name)
    {
        return Err(AuthError::Upstream {
            status: 400,
            code: "ROLE_NAME_IS_ALREADY_TAKEN",
            message: "That role name is already taken",
        });
    }
    Ok(())
}

async fn authorize_member(
    req: &AuthRequest,
    organization_id: Option<&str>,
    action: &str,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl AuthSchema>,
) -> AuthResult<(String, String)> {
    let (user, session) = require_session(req, ctx).await?;
    let organization_id = organization_id
        .or(session.active_organization_id.as_deref())
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            if action == "create" {
                AuthError::Upstream {
                    status: 400,
                    code: "YOU_MUST_BE_IN_AN_ORGANIZATION_TO_CREATE_A_ROLE",
                    message: "You must be in an organization to create a role",
                }
            } else {
                AuthError::bad_request("No active organization")
            }
        })?;
    let member = ctx
        .database
        .get_member(organization_id, user.id.typed()?)
        .await?
        .ok_or_else(|| AuthError::forbidden("You are not a member of this organization"))?;
    let permission = if action == "list" { "read" } else { action };
    if !check_permission(
        member.role.typed()?,
        organization_id,
        "ac",
        &[permission],
        config,
        ctx,
    )
    .await?
    {
        return Err(role_error(action));
    }
    Ok((organization_id.to_owned(), member.role.typed()?.clone()))
}

async fn select_role(
    selector: &RoleSelector,
    organization_id: &str,
    ctx: &AuthContext<impl AuthSchema>,
) -> AuthResult<OrganizationRole> {
    let role = ctx
        .database
        .list_organization_roles(organization_id)
        .await?
        .into_iter()
        .find(|role| {
            if let Some(name) = selector
                .role_name
                .as_deref()
                .filter(|name| !name.is_empty())
            {
                role.role == name
            } else {
                selector.role_id.as_ref().is_some_and(|id| role.id == *id)
            }
        });
    role.ok_or(AuthError::Upstream {
        status: 400,
        code: "ROLE_NOT_FOUND",
        message: "Role not found",
    })
}

async fn validate_permissions(
    permission: &RequestedPermissions,
    member_role: &str,
    organization_id: &str,
    action: &str,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl AuthSchema>,
) -> AuthResult<Option<AuthResponse>> {
    let ac = require_ac(config)?;
    if permission
        .0
        .iter()
        .any(|(resource, _)| !ac.contains_key(resource))
    {
        return Err(AuthError::Upstream {
            status: 400,
            code: "INVALID_RESOURCE",
            message: "The provided permission includes an invalid resource",
        });
    }
    let mut missing = Vec::new();
    for (resource, actions) in &permission.0 {
        let actions = match actions {
            serde_json::Value::Array(actions) => actions.clone(),
            serde_json::Value::String(actions) => actions
                .chars()
                .map(|value| json!(value.to_string()))
                .collect(),
            _ => {
                return Err(AuthError::internal(
                    "Role permission actions are not iterable",
                ));
            }
        };
        for requested in actions {
            let allowed = if let Some(requested) = requested.as_str() {
                check_permission(
                    member_role,
                    organization_id,
                    resource,
                    &[requested],
                    config,
                    ctx,
                )
                .await?
            } else {
                false
            };
            if !allowed {
                let requested =
                    better_auth_core::SchemaValue::<serde_json::Value>::Dynamic(requested)
                        .display_string()?;
                missing.push(format!("{resource}:{requested}"));
            }
        }
    }
    if missing.is_empty() {
        return Ok(None);
    }
    let (status, code, message) = role_error(action).error_payload();
    Ok(Some(AuthResponse::json(
        status,
        &json!({"code":code,"message":message,"missingPermissions":missing}),
    )?))
}

/// Dispatch the enabled dynamic-role endpoints.
pub async fn handle_role_request(
    req: &AuthRequest,
    ctx: &AuthContext<impl AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<Option<AuthResponse>> {
    let (_, session) = require_session(req, ctx).await?;
    let response = match (req.method(), req.path()) {
        (HttpMethod::Post, "/organization/create-role") => {
            let body: CreateRole = super::super::request::read(req, &config.schema)?;
            let additional_fields = body.additional_fields.into_option().unwrap_or_default();
            let _ = require_ac(config)?;
            if body
                .organization_id
                .as_deref()
                .or(session.active_organization_id.as_deref())
                .is_none_or(str::is_empty)
            {
                return Err(AuthError::Upstream {
                    status: 400,
                    code: "YOU_MUST_BE_IN_AN_ORGANIZATION_TO_CREATE_A_ROLE",
                    message: "You must be in an organization to create a role",
                });
            }
            let name = body.role.to_lowercase();
            // Predefined names are rejected before membership and permission checks.
            if predefined(&name, config) {
                return Err(AuthError::Upstream {
                    status: 400,
                    code: "ROLE_NAME_IS_ALREADY_TAKEN",
                    message: "That role name is already taken",
                });
            }
            let (organization_id, member_role) =
                authorize_member(req, body.organization_id.as_deref(), "create", config, ctx)
                    .await?;
            let maximum = config.role_limit(&organization_id).await?;
            let count = ctx
                .database
                .list_organization_roles(&organization_id)
                .await?
                .len();
            if maximum.is_some_and(|limit| count >= limit) {
                return Err(AuthError::Upstream {
                    status: 400,
                    code: "TOO_MANY_ROLES",
                    message: "This organization has too many roles",
                });
            }
            if let Some(response) = validate_permissions(
                &body.permission,
                &member_role,
                &organization_id,
                "create",
                config,
                ctx,
            )
            .await?
            {
                return Ok(Some(response));
            }
            unused_name(&name, &organization_id, config, ctx).await?;
            let permission = serde_json::to_value(body.permission)?;
            let mut role = ctx
                .database
                .create_organization_role(CreateOrganizationRole {
                    additional_fields,
                    organization_id,
                    role: name,
                    permission: permission.clone(),
                })
                .await?;
            role.permission = permission.clone().into();
            AuthResponse::json(
                200,
                &json!({"success":true,"roleData":role,"statements":permission}),
            )?
        }
        (HttpMethod::Get, "/organization/list-roles" | "/organization/get-role") => {
            let selector: RoleSelector =
                serde_json::from_value(req.query.clone().unwrap_or_else(|| serde_json::json!({})))?;
            let action = if req.path().ends_with("list-roles") {
                "list"
            } else {
                "read"
            };
            let (organization_id, _) = authorize_member(
                req,
                selector.organization_id.as_deref(),
                action,
                config,
                ctx,
            )
            .await?;
            if action == "list" {
                let roles = ctx
                    .database
                    .list_organization_roles(&organization_id)
                    .await?
                    .into_iter()
                    .map(|mut role| {
                        role.permission =
                            super::super::native_json::permission(&role.permission)?.into();
                        Ok(role)
                    })
                    .collect::<AuthResult<Vec<_>>>()?;
                AuthResponse::json(200, &roles)?
            } else {
                if req.query.is_none() {
                    return Err(AuthError::internal("Role lookup requires a query object"));
                }
                let mut role = select_role(&selector, &organization_id, ctx).await?;
                role.permission = super::super::native_json::permission(&role.permission)?.into();
                AuthResponse::json(200, &role)?
            }
        }
        (HttpMethod::Post, "/organization/delete-role") => {
            let selector: RoleSelector = super::super::request::read(req, &config.schema)?;
            let (organization_id, _) = authorize_member(
                req,
                selector.organization_id.as_deref(),
                "delete",
                config,
                ctx,
            )
            .await?;
            if selector
                .role_name
                .as_deref()
                .is_some_and(|name| predefined(name, config))
            {
                return Err(AuthError::Upstream {
                    status: 400,
                    code: "CANNOT_DELETE_A_PRE_DEFINED_ROLE",
                    message: "Cannot delete a pre-defined role",
                });
            }
            let role = select_role(&selector, &organization_id, ctx).await?;
            let _ = super::super::native_json::permission(&role.permission)?;
            if ctx
                .database
                .list_organization_members(&organization_id)
                .await?
                .iter()
                .map(|member| member.role.typed())
                .collect::<AuthResult<Vec<_>>>()?
                .iter()
                .any(|member_role| member_role.split(',').any(|name| role.role == name.trim()))
            {
                return Err(AuthError::Upstream {
                    status: 400,
                    code: "ROLE_IS_ASSIGNED_TO_MEMBERS",
                    message: "Cannot delete a role that is assigned to members. Please reassign the members to a different role first",
                });
            }
            ctx.database
                .delete_organization_role(role.id.typed()?)
                .await?;
            AuthResponse::json(200, &json!({"success":true}))?
        }
        (HttpMethod::Post, "/organization/update-role") => {
            let body: UpdateRole = super::super::request::read(req, &config.schema)?;
            let raw = req.input_body()?;
            let raw_data = raw
                .as_ref()
                .and_then(|value| value.get("data"))
                .and_then(serde_json::Value::as_object)
                .ok_or_else(|| AuthError::internal("Validated role data is missing"))?;
            let schema = &config.schema.organization_role;
            let overrides_permission = schema
                .additional_fields
                .get("permission")
                .is_some_and(|field| field.input);
            let mut fields: serde_json::Map<String, serde_json::Value> = raw_data
                .iter()
                .filter(|(name, _)| {
                    schema
                        .additional_fields
                        .get(*name)
                        .is_some_and(|field| field.input)
                })
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect();
            let requested = body.data.permission.into_option();
            let permission = if overrides_permission {
                fields.remove("permission")
            } else {
                requested.as_ref().map(serde_json::to_value).transpose()?
            }
            .filter(better_auth_core::user_fields::is_truthy);
            let requested = requested.unwrap_or_else(|| {
                RequestedPermissions::dynamic(
                    permission.as_ref().unwrap_or(&serde_json::Value::Null),
                )
            });
            let _ = require_ac(config)?;
            let (organization_id, member_role) = authorize_member(
                req,
                body.selector.organization_id.as_deref(),
                "update",
                config,
                ctx,
            )
            .await?;
            let mut role = select_role(&body.selector, &organization_id, ctx).await?;
            role.permission = if role
                .permission
                .json()?
                .as_ref()
                .is_some_and(better_auth_core::user_fields::is_truthy)
            {
                super::super::native_json::permission(&role.permission)?.into()
            } else {
                better_auth_core::SchemaValue::Undefined
            };
            if permission.is_some()
                && let Some(response) = validate_permissions(
                    &requested,
                    &member_role,
                    &organization_id,
                    "update",
                    config,
                    ctx,
                )
                .await?
            {
                return Ok(Some(response));
            }
            let name = body
                .data
                .role_name
                .into_option()
                .filter(|name| !name.is_empty())
                .map(|name| name.to_lowercase());
            if let Some(name) = &name {
                unused_name(name, &organization_id, config, ctx).await?;
            }
            let _ = ctx
                .database
                .update_organization_role(
                    role.id.typed()?,
                    UpdateOrganizationRole {
                        additional_fields: fields.clone(),
                        role: name.clone(),
                        permission: permission.clone(),
                    },
                )
                .await?;
            // The endpoint merges raw input into the old snapshot; adapter transforms remain in storage.
            let mut updated = role;
            if let Some(value) = fields
                .remove("id")
                .and_then(|value| value.as_str().map(str::to_owned))
            {
                updated.id = value.into();
            }
            if let Some(value) = fields.remove("organizationId") {
                updated.organization_id = better_auth_core::SchemaValue::Dynamic(value);
            }
            if let Some(value) = fields.remove("role") {
                updated.role = better_auth_core::SchemaValue::Dynamic(value);
            }
            if let Some(value) = fields.remove("createdAt") {
                updated.created_at = better_auth_core::SchemaValue::Dynamic(value);
            }
            if let Some(value) = fields.remove("updatedAt") {
                updated.updated_at = better_auth_core::SchemaValue::Dynamic(value);
            }
            updated.additional_fields.extend(fields);
            if let Some(name) = name {
                updated.role = name.into();
            }
            if let Some(permission) = permission {
                updated.permission = permission.into();
            } else if !updated
                .permission
                .json()?
                .as_ref()
                .is_some_and(better_auth_core::user_fields::is_truthy)
            {
                updated.permission = serde_json::Value::Null.into();
            }
            AuthResponse::json(200, &json!({"success":true,"roleData":updated}))?
        }
        _ => return Ok(None),
    };
    Ok(Some(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::test_helpers::{
        create_auth_json_request_no_query, create_test_context, create_user_and_session,
    };
    use better_auth_core::{CreateMember, CreateOrganization, CreateUser};
    use chrono::Duration;

    #[tokio::test]
    async fn persisted_roles_authorize_only_their_tenant_and_cannot_escalate() {
        let ctx = create_test_context().await;
        let (user, session) = create_user_and_session(
            &ctx,
            CreateUser {
                email: Some("role-admin@example.com".into()),
                ..Default::default()
            },
            Duration::hours(1),
        )
        .await;
        let org = ctx
            .database
            .create_organization(CreateOrganization {
                additional_fields: Default::default(),
                id: None,
                name: "Roles".into(),
                slug: "roles".into(),
                logo: None.into(),
                metadata: None.into(),
            })
            .await
            .unwrap();
        ctx.database
            .create_member(CreateMember {
                additional_fields: Default::default(),
                organization_id: org.id.clone(),
                user_id: user.id.clone(),
                role: "admin".into(),
            })
            .await
            .unwrap();
        let config = OrganizationConfig {
            dynamic_access_control: true,
            ac: Some(HashMap::from([(
                "organization".into(),
                vec!["update".into(), "delete".into()],
            )])),
            ..Default::default()
        };
        let request = |permission| {
            create_auth_json_request_no_query(
                HttpMethod::Post,
                "/organization/create-role",
                Some(&session.token),
                Some(json!({"organizationId":org.id,"role":"Editor","permission":permission})),
            )
        };
        let denied =
            handle_role_request(&request(json!({"organization":["delete"]})), &ctx, &config)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(denied.status, 403);
        let denied: serde_json::Value = serde_json::from_slice(&denied.body).unwrap();
        assert_eq!(denied["missingPermissions"], json!(["organization:delete"]));
        assert!(
            ctx.database
                .list_organization_roles(org.id.typed().unwrap())
                .await
                .unwrap()
                .is_empty()
        );
        let created =
            handle_role_request(&request(json!({"organization":["update"]})), &ctx, &config)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(created.status, 200);
        let rows = ctx
            .database
            .list_organization_roles(org.id.typed().unwrap())
            .await
            .unwrap();
        assert_eq!(rows[0].role, "editor");
        assert!(
            check_permission(
                "editor",
                org.id.typed().unwrap(),
                "organization",
                &["update"],
                &config,
                &ctx
            )
            .await
            .unwrap()
        );
        assert!(
            !check_permission(
                "editor",
                "other-tenant",
                "organization",
                &["update"],
                &config,
                &ctx
            )
            .await
            .unwrap()
        );
        let duplicate =
            handle_role_request(&request(json!({"organization":["update"]})), &ctx, &config)
                .await
                .unwrap_err();
        assert_eq!(
            duplicate.error_payload().1.as_deref(),
            Some("ROLE_NAME_IS_ALREADY_TAKEN")
        );
    }
}
