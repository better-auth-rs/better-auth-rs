use crate::wire::SessionView;
use serde_json::{Map, Value, json};

impl From<SessionView> for Map<String, Value> {
    fn from(session: SessionView) -> Self {
        let date = |value: chrono::DateTime<chrono::Utc>| {
            json!(value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        };
        let mut fields = Map::from_iter([
            ("id".into(), json!(session.id)),
            ("token".into(), json!(session.token)),
            ("expiresAt".into(), date(session.expires_at)),
            ("createdAt".into(), date(session.created_at)),
            ("updatedAt".into(), date(session.updated_at)),
            ("ipAddress".into(), json!(session.ip_address)),
            ("userAgent".into(), json!(session.user_agent)),
            ("userId".into(), json!(session.user_id)),
        ]);
        for (name, value) in [
            ("impersonatedBy", json!(session.impersonated_by)),
            ("activeTeamId", json!(session.active_team_id)),
            (
                "activeOrganizationId",
                json!(session.active_organization_id),
            ),
        ] {
            if session
                .visible_fields
                .as_ref()
                .is_none_or(|fields| fields.contains(name))
            {
                let _ = fields.insert(name.into(), value);
            }
        }
        fields.extend(session.additional_fields);
        fields
    }
}

impl TryFrom<Map<String, Value>> for SessionView {
    type Error = serde_json::Error;

    fn try_from(mut fields: Map<String, Value>) -> Result<Self, Self::Error> {
        fn take<T: serde::de::DeserializeOwned>(
            fields: &mut Map<String, Value>,
            name: &str,
        ) -> Result<T, serde_json::Error> {
            serde_json::from_value(fields.remove(name).unwrap_or(Value::Null))
        }
        let visible_fields = Some(
            ["impersonatedBy", "activeOrganizationId", "activeTeamId"]
                .into_iter()
                .filter(|name| fields.contains_key(*name))
                .map(str::to_owned)
                .collect(),
        );
        Ok(Self {
            id: take(&mut fields, "id")?,
            token: take(&mut fields, "token")?,
            expires_at: take(&mut fields, "expiresAt")?,
            created_at: take(&mut fields, "createdAt")?,
            updated_at: take(&mut fields, "updatedAt")?,
            ip_address: take(&mut fields, "ipAddress")?,
            user_agent: take(&mut fields, "userAgent")?,
            user_id: take(&mut fields, "userId")?,
            impersonated_by: take(&mut fields, "impersonatedBy")?,
            active_organization_id: take(&mut fields, "activeOrganizationId")?,
            active_team_id: take(&mut fields, "activeTeamId")?,
            active: false,
            visible_fields,
            additional_fields: fields,
        })
    }
}
