use crate::{
    AuthRecordFields, AuthResult, FieldDate, FieldMap, FieldValue, FromFieldMap, SchemaField,
    SchemaValue, wire::SessionView,
};

impl From<SessionView> for FieldMap {
    fn from(session: SessionView) -> Self {
        let mut fields = FieldMap::from_iter([
            ("id".into(), session.id.into_field_value()),
            ("token".into(), session.token.into()),
            ("expiresAt".into(), session.expires_at.into()),
            ("createdAt".into(), session.created_at.into()),
            ("updatedAt".into(), session.updated_at.into()),
            ("ipAddress".into(), session.ip_address.into_field()),
            ("userAgent".into(), session.user_agent.into_field()),
            ("userId".into(), session.user_id.into_field_value()),
        ]);
        for (name, value) in [
            ("impersonatedBy", session.impersonated_by),
            ("activeTeamId", session.active_team_id),
            ("activeOrganizationId", session.active_organization_id),
        ] {
            if session
                .visible_fields
                .as_ref()
                .is_none_or(|fields| fields.contains(name))
            {
                let _ = fields.insert(name.into(), value.into_field());
            }
        }
        fields.extend(session.additional_fields);
        fields
    }
}

impl AuthRecordFields for SessionView {
    fn field_values(&self) -> AuthResult<FieldMap> {
        let mut fields: FieldMap = self.clone().into();
        let _ = fields.insert("active".into(), self.active.into());
        Ok(fields)
    }

    fn structured_clone(&self, context: &mut crate::StructuredCloneContext) -> AuthResult<Self> {
        let mut output = self.clone();
        output.id = context.clone_field(&self.id)?;
        output.user_id = context.clone_field(&self.user_id)?;
        output.expires_at = context.clone_field(&self.expires_at)?;
        output.created_at = context.clone_field(&self.created_at)?;
        output.updated_at = context.clone_field(&self.updated_at)?;
        output.additional_fields = context.clone_map(&self.additional_fields);
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_preserve_private_fields_and_cross_field_date_aliases() -> AuthResult<()> {
        let date = FieldDate::from_milliseconds(1_000.0);
        let mut session = SessionView::from_field_values(FieldMap::from([
            ("id".into(), "session".into()),
            ("userId".into(), "user".into()),
            ("token".into(), "native-token".into()),
            ("expiresAt".into(), date.clone().into()),
            ("createdAt".into(), date.clone().into()),
            ("updatedAt".into(), date.clone().into()),
            ("active".into(), true.into()),
        ]))?;
        let _ = session
            .additional_fields
            .insert("alias".into(), date.clone().into());
        let _ = session.additional_fields.insert("token".into(), 7.into());
        let snapshot = session.structured_clone(&mut crate::StructuredCloneContext::new())?;
        assert!(snapshot.active);
        assert_eq!(snapshot.token, "native-token");
        assert_eq!(snapshot.visible_fields, session.visible_fields);
        assert_eq!(snapshot.additional_fields["token"], FieldValue::Number(7.0));
        assert!(
            snapshot
                .expires_at
                .same_object(snapshot.additional_fields["alias"].as_date().unwrap())
        );
        assert!(snapshot.expires_at.same_object(&snapshot.created_at));
        assert!(!snapshot.expires_at.same_object(&date));
        assert!(serde_json::to_value(&snapshot)?.get("active").is_none());
        Ok(())
    }
}

impl FromFieldMap for SessionView {
    fn from_field_values(mut fields: FieldMap) -> AuthResult<Self> {
        fn take<T: SchemaField>(fields: &mut FieldMap, name: &str) -> AuthResult<T> {
            fields
                .remove(name)
                .unwrap_or(FieldValue::Undefined)
                .decode()
        }
        let visible_fields = Some(
            ["impersonatedBy", "activeOrganizationId", "activeTeamId"]
                .into_iter()
                .filter(|name| fields.contains_key(*name))
                .map(str::to_owned)
                .collect(),
        );
        Ok(Self {
            id: SchemaValue::from_field(fields.remove("id").unwrap_or_default()),
            token: take(&mut fields, "token")?,
            expires_at: take(&mut fields, "expiresAt")?,
            created_at: take(&mut fields, "createdAt")?,
            updated_at: take(&mut fields, "updatedAt")?,
            ip_address: take(&mut fields, "ipAddress")?,
            user_agent: take(&mut fields, "userAgent")?,
            user_id: SchemaValue::from_field(fields.remove("userId").unwrap_or_default()),
            impersonated_by: take(&mut fields, "impersonatedBy")?,
            active_organization_id: take(&mut fields, "activeOrganizationId")?,
            active_team_id: take(&mut fields, "activeTeamId")?,
            active: fields.remove("active").unwrap_or(false.into()).decode()?,
            visible_fields,
            additional_fields: fields,
        })
    }
}

impl serde::Serialize for SessionView {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        crate::field_value::serde::map::serialize(&self.clone().into(), serializer)
    }
}

impl<'de> serde::Deserialize<'de> for SessionView {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut fields = crate::field_value::serde::map::deserialize(deserializer)?;
        for name in ["expiresAt", "createdAt", "updatedAt"] {
            if let Some(FieldValue::String(text)) = fields.get(name) {
                let date =
                    chrono::DateTime::parse_from_rfc3339(text).map_err(serde::de::Error::custom)?;
                let _ = fields.insert(
                    name.into(),
                    FieldDate::from(date.with_timezone(&chrono::Utc)).into(),
                );
            }
        }
        Self::from_field_values(fields).map_err(serde::de::Error::custom)
    }
}
