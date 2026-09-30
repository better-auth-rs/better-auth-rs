use super::types::OrganizationResponse;
use better_auth_core::{
    AuthContext, AuthSchema, Team, entity::AuthOrganization,
    organization_fields::OrganizationFields,
};
use serde_json::Value;

pub(super) fn parse_input<T: serde::Serialize>(
    schema: &better_auth_core::user_fields::UserConfig,
    body: &T,
    additional: &serde_json::Map<String, Value>,
    prefix: &str,
    partial: bool,
) -> better_auth_core::AuthResult<serde_json::Map<String, Value>> {
    let input = serde_json::to_value(body)?;
    let input = input.as_object().ok_or_else(|| {
        better_auth_core::AuthError::config("Organization input must serialize as an object")
    })?;
    let mut parsed = schema.parse_organization_input(input, prefix, partial)?;
    // Typed request fields already contain the validated core values.
    parsed.retain(|name, _| additional.contains_key(name));
    Ok(parsed)
}

pub(super) fn organization(
    organization: &impl AuthOrganization,
    ctx: &AuthContext<impl AuthSchema>,
) -> OrganizationResponse {
    let mut response = OrganizationResponse::from_organization(organization);
    if let Some(fields) = ctx.extensions.get::<OrganizationFields>() {
        fields
            .organization
            .filter_returned_fields(&mut response.additional_fields);
    }
    response
}

pub(super) fn created_organization(
    organization: &impl AuthOrganization,
    ctx: &AuthContext<impl AuthSchema>,
) -> OrganizationResponse {
    let mut response = self::organization(organization, ctx);
    response.metadata = organization.metadata().cloned();
    response
}

pub(super) fn team(mut team: Team, ctx: &AuthContext<impl AuthSchema>) -> Team {
    if let Some(fields) = ctx.extensions.get::<OrganizationFields>() {
        fields
            .team
            .filter_returned_fields(&mut team.additional_fields);
    }
    team
}

pub(super) fn filter_response(path: &str, value: &mut Value, fields: &OrganizationFields) {
    fn filter(value: &mut Value, schema: &better_auth_core::user_fields::UserConfig) {
        match value {
            Value::Object(map) => schema.filter_returned_fields(map),
            Value::Array(items) => {
                for item in items {
                    filter(item, schema);
                }
            }
            _ => {}
        }
    }
    match path {
        "/organization/create"
        | "/organization/update"
        | "/organization/delete"
        | "/organization/list"
        | "/organization/get-organization"
        | "/organization/set-active" => filter(value, &fields.organization),
        "/organization/get-full-organization" => {
            filter(value, &fields.organization);
            for (key, schema) in [
                ("members", &fields.member),
                ("invitations", &fields.invitation),
                ("teams", &fields.team),
            ] {
                if let Some(value) = value.get_mut(key) {
                    filter(value, schema);
                }
            }
        }
        "/organization/create-team"
        | "/organization/update-team"
        | "/organization/list-teams"
        | "/organization/list-user-teams"
        | "/organization/set-active-team" => filter(value, &fields.team),
        _ => {}
    }
}
