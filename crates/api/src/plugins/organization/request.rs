use super::{
    OrganizationFields,
    handlers::{roles, team},
    input::{self, BaseField},
    types::*,
};
use better_auth_core::{
    AuthError, AuthRequest, AuthResult, endpoint_input::ValidatedBody, user_fields::UserConfig,
};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

fn typed<T: DeserializeOwned + Send + Sync + 'static>(value: Value) -> AuthResult<ValidatedBody> {
    Ok(ValidatedBody::new(
        Some(value.clone()),
        serde_json::from_value::<T>(value)?,
    ))
}

pub(super) fn read<T: Clone + Send + Sync + 'static>(
    req: &AuthRequest,
    schema: &OrganizationFields,
) -> AuthResult<T> {
    if let Some(value) = req.validated_body::<T>() {
        return Ok(value.clone());
    }
    validate(req, &prepared_schema(req.path(), schema))?
        .get::<T>()
        .cloned()
        .ok_or_else(|| {
            AuthError::internal("Organization body validator returned a different input type")
        })
}

pub(super) fn prepared_schema(path: &str, schema: &OrganizationFields) -> OrganizationFields {
    let mut schema = schema.clone();
    if path == "/organization/update-role" {
        for field in schema.organization_role.fields_mut().values_mut() {
            field.required = Some(false);
        }
    }
    schema
}

fn schema_fields(
    schema: &UserConfig,
    body: &Map<String, Value>,
    base: &[(&str, BaseField, bool)],
    prefix: &str,
    partial: bool,
    errors: &mut Vec<String>,
) -> AuthResult<Map<String, Value>> {
    input::fields(schema, body, base, prefix, partial, false, errors)
}

fn static_fields(
    body: &Map<String, Value>,
    base: &[(&str, BaseField, bool)],
    errors: &mut Vec<String>,
) -> AuthResult<Map<String, Value>> {
    schema_fields(&UserConfig::default(), body, base, "body", false, errors)
}

fn selector(body: &Map<String, Value>, output: &mut Map<String, Value>, errors: &mut Vec<String>) {
    if let Some((name, value)) = ["roleName", "roleId"].into_iter().find_map(|name| {
        body.get(name)
            .filter(|value| value.as_str().is_some_and(|value| !value.is_empty()))
            .map(|value| (name, value))
    }) {
        let _ = output.insert(name.into(), value.clone());
    } else {
        let name = match (
            body.get("roleName").and_then(Value::as_str),
            body.get("roleId").and_then(Value::as_str),
        ) {
            (Some(""), None) => Some("roleName"),
            (None, Some("")) => Some("roleId"),
            _ => None,
        };
        errors.push(name.map_or_else(
            || "[body] Invalid input".into(),
            |name| format!("[body.{name}] Too small: expected string to have >=1 characters"),
        ));
    }
}

pub(super) fn validate(
    req: &AuthRequest,
    schema: &OrganizationFields,
) -> AuthResult<ValidatedBody> {
    use BaseField::*;
    let raw = req.input_body()?;
    let mut errors = Vec::new();
    let Some(body) = input::object(raw.as_ref(), "body", &mut errors) else {
        if matches!(
            req.path(),
            "/organization/delete-role"
                | "/organization/update-role"
                | "/organization/has-permission"
        ) {
            errors.push("[body] Invalid input".into());
        }
        input::finish(errors)?;
        return Err(AuthError::internal("Invalid Organization body"));
    };
    let mut output = match req.path() {
        "/organization/create" => schema_fields(
            &schema.organization,
            body,
            &[
                ("name", NonemptyString, true),
                ("slug", NonemptyString, true),
                ("userId", CoercedString, false),
                ("logo", NullableString, false),
                ("metadata", Record, false),
                ("keepCurrentActiveOrganization", Boolean, false),
            ],
            "body",
            false,
            &mut errors,
        )?,
        "/organization/update" => {
            let mut output = Map::new();
            if let Some(data) = input::object(body.get("data"), "body.data", &mut errors) {
                let data = input::fields(
                    &schema.organization,
                    data,
                    &[
                        ("name", NonemptyString, false),
                        ("slug", NonemptyString, false),
                        ("logo", NullableString, false),
                        ("metadata", Record, false),
                    ],
                    "body.data",
                    true,
                    true,
                    &mut errors,
                )?;
                let _ = output.insert("data".into(), Value::Object(data));
            }
            output.extend(static_fields(
                body,
                &[("organizationId", String, false)],
                &mut errors,
            )?);
            output
        }
        "/organization/delete" | "/organization/leave" => {
            static_fields(body, &[("organizationId", String, true)], &mut errors)?
        }
        "/organization/check-slug" => static_fields(body, &[("slug", String, true)], &mut errors)?,
        "/organization/set-active" => static_fields(
            body,
            &[
                ("organizationId", NullableString, false),
                ("organizationSlug", String, false),
            ],
            &mut errors,
        )?,
        "/organization/remove-member" => static_fields(
            body,
            &[
                ("memberIdOrEmail", String, true),
                ("organizationId", String, false),
            ],
            &mut errors,
        )?,
        "/organization/update-member-role" => static_fields(
            body,
            &[
                ("role", Roles, true),
                ("memberId", String, true),
                ("organizationId", String, false),
            ],
            &mut errors,
        )?,
        "/organization/invite-member" => schema_fields(
            &schema.invitation,
            body,
            &[
                ("email", String, true),
                ("role", Roles, true),
                ("organizationId", String, false),
                ("resend", Boolean, false),
                ("teamId", Roles, false),
            ],
            "body",
            false,
            &mut errors,
        )?,
        "/organization/accept-invitation"
        | "/organization/reject-invitation"
        | "/organization/cancel-invitation" => {
            static_fields(body, &[("invitationId", String, true)], &mut errors)?
        }
        "/organization/create-team" => schema_fields(
            &schema.team,
            body,
            &[("name", String, true), ("organizationId", String, false)],
            "body",
            false,
            &mut errors,
        )?,
        "/organization/update-team" => {
            let mut output = static_fields(body, &[("teamId", String, true)], &mut errors)?;
            if let Some(data) = input::object(body.get("data"), "body.data", &mut errors) {
                let data = schema_fields(
                    &schema.team,
                    data,
                    &[("name", String, true), ("organizationId", String, true)],
                    "body.data",
                    true,
                    &mut errors,
                )?;
                let _ = output.insert("data".into(), Value::Object(data));
            }
            output
        }
        "/organization/remove-team" => static_fields(
            body,
            &[("teamId", String, true), ("organizationId", String, false)],
            &mut errors,
        )?,
        "/organization/set-active-team" => {
            static_fields(body, &[("teamId", NullableString, false)], &mut errors)?
        }
        "/organization/add-team-member" | "/organization/remove-team-member" => static_fields(
            body,
            &[
                ("teamId", String, true),
                ("userId", CoercedString, true),
                ("organizationId", String, false),
            ],
            &mut errors,
        )?,
        "/organization/create-role" => {
            let mut output = static_fields(
                body,
                &[
                    ("organizationId", String, false),
                    ("role", String, true),
                    ("permission", Permissions, true),
                ],
                &mut errors,
            )?;
            if let Some(value) = body.get("additionalFields")
                && let Some(data) = input::object(Some(value), "body.additionalFields", &mut errors)
            {
                let data = schema_fields(
                    &schema.organization_role,
                    data,
                    &[],
                    "body.additionalFields",
                    false,
                    &mut errors,
                )?;
                let _ = output.insert("additionalFields".into(), Value::Object(data));
            }
            output
        }
        "/organization/delete-role" => {
            let mut output =
                static_fields(body, &[("organizationId", String, false)], &mut errors)?;
            selector(body, &mut output, &mut errors);
            output
        }
        "/organization/update-role" => {
            let mut output =
                static_fields(body, &[("organizationId", String, false)], &mut errors)?;
            if let Some(data) = input::object(body.get("data"), "body.data", &mut errors) {
                // The upstream role update endpoint makes configured fields nullish at initialization.
                let data = schema_fields(
                    &schema.organization_role,
                    data,
                    &[
                        ("permission", Permissions, false),
                        ("roleName", String, false),
                    ],
                    "body.data",
                    false,
                    &mut errors,
                )?;
                let _ = output.insert("data".into(), Value::Object(data));
            }
            selector(body, &mut output, &mut errors);
            output
        }
        "/organization/has-permission" => {
            let mut output =
                static_fields(body, &[("organizationId", String, false)], &mut errors)?;
            let mut branches = Vec::new();
            for field in ["permission", "permissions"] {
                let mut branch_errors = Vec::new();
                let branch =
                    static_fields(body, &[(field, Permissions, true)], &mut branch_errors)?;
                if branch_errors.is_empty() {
                    branches.push(branch);
                }
            }
            if branches.len() == 1 {
                if let Some(branch) = branches.pop() {
                    output.extend(branch);
                }
            } else {
                errors.push(
                    if branches.is_empty() {
                        "[body] Invalid input"
                    } else {
                        "[body] Invalid input: more than one option matched"
                    }
                    .into(),
                );
            }
            output
        }
        _ => {
            return Err(AuthError::internal(
                "Organization endpoint has no body schema",
            ));
        }
    };
    input::finish(errors)?;
    let value = Value::Object(output.clone());
    match req.path() {
        "/organization/create" => typed::<CreateOrganizationRequest>(value),
        "/organization/update" => typed::<UpdateOrganizationRequest>(value),
        "/organization/delete" => typed::<DeleteOrganizationRequest>(value),
        "/organization/leave" => typed::<LeaveOrganizationRequest>(value),
        "/organization/check-slug" => typed::<CheckSlugRequest>(value),
        "/organization/set-active" => typed::<SetActiveOrganizationRequest>(value),
        "/organization/remove-member" => typed::<RemoveMemberRequest>(value),
        "/organization/update-member-role" => typed::<UpdateMemberRoleRequest>(value),
        "/organization/invite-member" => typed::<InviteMemberRequest>(value),
        "/organization/accept-invitation" => typed::<AcceptInvitationRequest>(value),
        "/organization/reject-invitation" => typed::<RejectInvitationRequest>(value),
        "/organization/cancel-invitation" => typed::<CancelInvitationRequest>(value),
        "/organization/create-team" => typed::<team::CreateBody>(value),
        "/organization/update-team" => typed::<team::UpdateBody>(value),
        "/organization/remove-team" => typed::<team::TeamBody>(value),
        "/organization/set-active-team" => typed::<team::ActiveBody>(value),
        "/organization/add-team-member" | "/organization/remove-team-member" => {
            typed::<team::MemberBody>(value)
        }
        "/organization/create-role" => typed::<roles::CreateRole>(value),
        "/organization/delete-role" => typed::<roles::RoleSelector>(value),
        "/organization/update-role" => {
            if schema
                .organization_role
                .fields()
                .get("permission")
                .is_some_and(|field| field.input())
                && let Some(data) = output.get_mut("data").and_then(Value::as_object_mut)
            {
                let _ = data.remove("permission");
            }
            Ok(ValidatedBody::new(
                Some(value),
                serde_json::from_value::<roles::UpdateRole>(Value::Object(output))?,
            ))
        }
        "/organization/has-permission" => typed::<HasPermissionRequest>(value),
        _ => Err(AuthError::internal(
            "Organization endpoint has no typed body",
        )),
    }
}
