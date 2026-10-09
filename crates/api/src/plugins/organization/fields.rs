use super::types::OrganizationResponse;
use better_auth_core::{
    AuthContext, AuthSchema, Team, entity::AuthOrganization,
    organization_fields::OrganizationFields,
};
use serde_json::Value;

pub(super) fn shape_native_session_teams(
    value: &mut better_auth_core::FieldValue,
    enabled: bool,
) -> better_auth_core::AuthResult<()> {
    use better_auth_core::FieldValue;
    use std::sync::Arc;
    match value {
        FieldValue::Array(values) => {
            for value in Arc::make_mut(values) {
                shape_native_session_teams(value, enabled)?;
            }
        }
        FieldValue::Object(object) => {
            let mut fields = object.snapshot_fields()?;
            if ["id", "token", "expiresAt", "userId"]
                .iter()
                .all(|key| fields.contains_key(*key))
            {
                if enabled {
                    let _ = fields
                        .entry("activeTeamId".into())
                        .or_insert(FieldValue::Null);
                } else {
                    let _ = fields.remove("activeTeamId");
                }
            } else {
                for key in ["session", "sessions"] {
                    if let Some(session) = fields.get_mut(key) {
                        shape_native_session_teams(session, enabled)?;
                    }
                }
            }
            *object = fields.into();
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn shape_session_teams(
    value: &mut Box<serde_json::value::RawValue>,
    enabled: bool,
) -> better_auth_core::AuthResult<bool> {
    use serde_json::value::{RawValue, to_raw_value};
    use std::collections::{BTreeMap, btree_map::Entry};

    // Other plugins can return JSON strings with unpaired UTF-16 surrogates.
    // Inspect session structure without decoding unrelated string values.
    match value.get().as_bytes().first() {
        Some(b'[') => {
            let mut sessions: Vec<Box<RawValue>> = serde_json::from_str(value.get())?;
            let mut changed = false;
            for session in &mut sessions {
                changed |= shape_session_teams(session, enabled)?;
            }
            if changed {
                *value = to_raw_value(&sessions)?;
            }
            Ok(changed)
        }
        Some(b'{') => {
            let mut fields: BTreeMap<String, Box<RawValue>> = serde_json::from_str(value.get())?;
            let mut changed = false;
            if ["id", "token", "expiresAt", "userId"]
                .iter()
                .all(|key| fields.contains_key(*key))
            {
                if enabled {
                    if let Entry::Vacant(entry) = fields.entry("activeTeamId".into()) {
                        let _ = entry.insert(to_raw_value(&Value::Null)?);
                        changed = true;
                    }
                } else {
                    changed = fields.remove("activeTeamId").is_some();
                }
            } else {
                for key in ["session", "sessions"] {
                    if let Some(session) = fields.get_mut(key) {
                        changed |= shape_session_teams(session, enabled)?;
                    }
                }
            }
            if changed {
                *value = to_raw_value(&fields)?;
            }
            Ok(changed)
        }
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::value::RawValue;
    use std::collections::BTreeMap;

    #[test]
    fn session_shaping_preserves_unpaired_surrogates_in_unrelated_fields() {
        let mut value = RawValue::from_string(
            r#"{"session":{"id":"s","token":"t","expiresAt":"date","userId":"u","label":"\ud83d"},"other":"\udc00"}"#.into(),
        )
        .unwrap();
        assert!(shape_session_teams(&mut value, true).unwrap());
        let fields: BTreeMap<String, Box<RawValue>> = serde_json::from_str(value.get()).unwrap();
        assert_eq!(fields["other"].get(), r#""\udc00""#);
        let session: BTreeMap<String, Box<RawValue>> =
            serde_json::from_str(fields["session"].get()).unwrap();
        assert_eq!(session["label"].get(), r#""\ud83d""#);
        assert_eq!(session["activeTeamId"].get(), "null");

        assert!(shape_session_teams(&mut value, false).unwrap());
        assert!(!value.get().contains("activeTeamId"));
        assert!(!shape_session_teams(&mut value, false).unwrap());

        let raw = r#"{"start":"\ud83d"}"#;
        let mut value = RawValue::from_string(raw.into()).unwrap();
        assert!(!shape_session_teams(&mut value, true).unwrap());
        assert_eq!(value.get(), raw);
    }
}

pub(super) fn invitation_team_id_is_declared(config: &super::OrganizationConfig) -> bool {
    config.teams.enabled || config.schema.invitation.fields().contains_key("teamId")
}

pub(super) fn invitation_snapshot(
    mut invitation: better_auth_core::Invitation,
    config: &super::OrganizationConfig,
) -> better_auth_core::Invitation {
    if !invitation_team_id_is_declared(config) {
        invitation.team_id = better_auth_core::SchemaValue::Undefined;
    }
    invitation
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
    response.metadata = organization.metadata().clone();
    response
}

pub(super) fn team(
    team: Team,
    config: &super::OrganizationConfig,
) -> better_auth_core::AuthResult<Team> {
    team.filter_output_fields(&config.schema.team)
}

enum ResponseFields {
    Organization,
    FullOrganization,
    Team,
    Other,
}

fn response_fields(path: &str) -> ResponseFields {
    match path {
        "/organization/create"
        | "/organization/update"
        | "/organization/delete"
        | "/organization/list"
        | "/organization/get-organization"
        | "/organization/set-active" => ResponseFields::Organization,
        "/organization/get-full-organization" => ResponseFields::FullOrganization,
        "/organization/create-team"
        | "/organization/update-team"
        | "/organization/list-teams"
        | "/organization/list-user-teams"
        | "/organization/set-active-team" => ResponseFields::Team,
        _ => ResponseFields::Other,
    }
}

pub(super) fn filter_native_response(
    path: &str,
    value: &mut better_auth_core::FieldValue,
    fields: &OrganizationFields,
) -> better_auth_core::AuthResult<()> {
    use better_auth_core::FieldValue;
    use std::sync::Arc;
    fn filter(
        value: &mut FieldValue,
        schema: &better_auth_core::user_fields::UserConfig,
        team: bool,
    ) -> better_auth_core::AuthResult<()> {
        match value {
            FieldValue::Object(object) => {
                let mut fields = object.snapshot_fields()?;
                fields.retain(|name, _| {
                    !(team && name == "memberCount")
                        && schema
                            .fields()
                            .get(name)
                            .is_none_or(|field| field.returned())
                });
                *object = fields.into();
            }
            FieldValue::Array(values) => {
                for value in Arc::make_mut(values) {
                    filter(value, schema, team)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    match response_fields(path) {
        ResponseFields::Organization => filter(value, &fields.organization, false)?,
        ResponseFields::FullOrganization => {
            filter(value, &fields.organization, false)?;
            if let FieldValue::Object(record) = value {
                let mut output = record.snapshot_fields()?;
                for (name, schema) in [
                    ("members", &fields.member),
                    ("invitations", &fields.invitation),
                    ("teams", &fields.team),
                ] {
                    if let Some(value) = output.get_mut(name) {
                        filter(value, schema, false)?;
                    }
                }
                *record = output.into();
            }
        }
        ResponseFields::Team => filter(value, &fields.team, true)?,
        ResponseFields::Other => {}
    }
    Ok(())
}

pub(super) fn filter_response(path: &str, value: &mut Value, fields: &OrganizationFields) {
    fn filter(value: &mut Value, schema: &better_auth_core::user_fields::UserConfig) {
        match value {
            Value::Object(map) => map.retain(|name, _| {
                schema
                    .fields()
                    .get(name)
                    .is_none_or(|field| field.returned())
            }),
            Value::Array(items) => {
                for item in items {
                    filter(item, schema);
                }
            }
            _ => {}
        }
    }
    match response_fields(path) {
        ResponseFields::Organization => filter(value, &fields.organization),
        ResponseFields::FullOrganization => {
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
        ResponseFields::Team => {
            match value {
                Value::Object(team) => {
                    let _ = team.remove("memberCount");
                }
                Value::Array(teams) => {
                    for team in teams {
                        if let Some(team) = team.as_object_mut() {
                            let _ = team.remove("memberCount");
                        }
                    }
                }
                _ => {}
            }
            filter(value, &fields.team);
        }
        ResponseFields::Other => {}
    }
}
