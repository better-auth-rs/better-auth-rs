use crate::{
    AuthRecordFields, AuthResult, FieldMap, FieldValue, FromFieldMap, SchemaField, SchemaValue,
    wire::SessionView,
};

impl From<SessionView> for FieldMap {
    fn from(session: SessionView) -> Self {
        let mut fields = FieldMap::from_iter([
            ("id".into(), session.id.into_field_value()),
            ("token".into(), session.token.into_field_value()),
            ("expiresAt".into(), session.expires_at.into_field_value()),
            ("createdAt".into(), session.created_at.into_field_value()),
            ("updatedAt".into(), session.updated_at.into_field_value()),
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
        fields.retain(|name, value| !value.is_undefined() || session.field_order.contains(name));
        fields.extend(session.additional_fields);
        fields.in_field_order(&session.field_order)
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
        output.token = context.clone_field(&self.token)?;
        output.ip_address = context.clone_field(&self.ip_address)?;
        output.user_agent = context.clone_field(&self.user_agent)?;
        output.impersonated_by = context.clone_field(&self.impersonated_by)?;
        output.active_organization_id = context.clone_field(&self.active_organization_id)?;
        output.active_team_id = context.clone_field(&self.active_team_id)?;

        output.expires_at = context.clone_field(&self.expires_at)?;
        output.created_at = context.clone_field(&self.created_at)?;
        output.updated_at = context.clone_field(&self.updated_at)?;
        output.additional_fields = context.clone_map(&self.additional_fields)?;
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FieldDate;

    #[test]
    fn public_clone_retains_enumerable_aliases_and_private_active_state() -> AuthResult<()> {
        let date = FieldDate::from_milliseconds(123.0);
        let mut session = SessionView::from_field_values(FieldMap::from([
            ("id".into(), "private-id".into()),
            ("token".into(), "public-token".into()),
            ("createdAt".into(), date.clone().into()),
            ("alias".into(), date.clone().into()),
            ("ownUndefined".into(), FieldValue::Undefined),
        ]))?;
        let factory: crate::user_fields::UserFieldFactory = std::sync::Arc::new(|| {
            Err(crate::AuthError::internal(
                "Public cloning must not invoke functions",
            ))
        });
        session.token =
            SchemaValue::from_field(FieldValue::Function(crate::FieldFunction::from(factory)));
        session.active = true;
        let _ = session
            .additional_fields
            .insert("token".into(), "public-token".into());
        let _ = session
            .additional_fields
            .insert("active".into(), "extension".into());
        let mut config = crate::config::SessionConfig::default();
        let _ = config.fields_mut().insert(
            "id".into(),
            crate::user_fields::UserFieldConfig {
                returned: Some(false),
                ..Default::default()
            },
        );
        session.filter_returned_fields(&config)?;
        assert!(session.active);
        let fields = FieldMap::from(session);
        assert!(!fields.contains_key("id"));
        assert!(!fields.contains_key("expiresAt"));
        assert_eq!(fields.get("ownUndefined"), Some(&FieldValue::Undefined));
        assert_eq!(fields.get("token"), Some(&"public-token".into()));
        assert_eq!(fields.get("active"), Some(&"extension".into()));
        assert!(fields["createdAt"].strict_equals(&fields["alias"]));
        assert!(!fields["createdAt"].strict_equals(&date.into()));
        Ok(())
    }

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
                .typed()?
                .same_object(snapshot.additional_fields["alias"].as_date().unwrap())
        );
        assert!(
            snapshot
                .expires_at
                .typed()?
                .same_object(snapshot.created_at.typed()?)
        );
        assert!(!snapshot.expires_at.typed()?.same_object(&date));
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
        let field_order = fields
            .keys()
            .filter(|name| name.as_str() != "active")
            .cloned()
            .collect();
        let visible_fields = Some(
            ["impersonatedBy", "activeOrganizationId", "activeTeamId"]
                .into_iter()
                .filter(|name| fields.contains_key(*name))
                .map(str::to_owned)
                .collect(),
        );
        Ok(Self {
            field_order,
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
        let fields = crate::field_value::serde::map::deserialize(deserializer)?;
        Self::from_field_values(fields).map_err(serde::de::Error::custom)
    }
}

impl SessionView {
    /// Move projected native replacements into their typed slots without narrowing their values.
    pub(crate) fn into_projected_fields(mut self) -> Self {
        macro_rules! apply {
            ($($field:ident => $name:literal),* $(,)?) => {$(
                if let Some(value) = self.additional_fields.remove($name) {
                    self.$field = SchemaValue::from_field(value);
                }
            )*};
        }
        for name in ["impersonatedBy", "activeOrganizationId", "activeTeamId"] {
            if self.additional_fields.contains_key(name)
                && let Some(visible) = &mut self.visible_fields
            {
                let _ = visible.insert(name.into());
            }
        }
        apply!(
            id => "id", user_id => "userId", token => "token", expires_at => "expiresAt",
            created_at => "createdAt", updated_at => "updatedAt", ip_address => "ipAddress",
            user_agent => "userAgent", impersonated_by => "impersonatedBy",
            active_organization_id => "activeOrganizationId", active_team_id => "activeTeamId",
        );
        self
    }
}

impl PartialEq for SessionView {
    fn eq(&self, other: &Self) -> bool {
        self.active == other.active && FieldMap::from(self.clone()) == FieldMap::from(other.clone())
    }
}

#[cfg(test)]
mod native_field_tests {
    use super::*;

    #[test]
    fn equality_preserves_enumerable_presence_and_private_liveness() -> AuthResult<()> {
        let mut left = SessionView::from_field_values(FieldMap::from([
            ("id".into(), "session".into()),
            ("token".into(), "token".into()),
        ]))?;
        let mut right = SessionView::from_field_values(FieldMap::from([
            ("token".into(), "token".into()),
            ("id".into(), "session".into()),
        ]))?;
        assert_eq!(
            FieldMap::from(left.clone())
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["id", "token"],
        );
        assert_eq!(
            FieldMap::from(right.clone())
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["token", "id"],
        );
        right.impersonated_by = Some("non-enumerable-storage-value".into()).into();
        assert_eq!(left, right);
        let _ = left
            .additional_fields
            .insert("extra".into(), FieldValue::Undefined);
        assert_ne!(left, right);
        let _ = right
            .additional_fields
            .insert("extra".into(), FieldValue::Null);
        assert_ne!(left, right);
        let _ = right
            .additional_fields
            .insert("extra".into(), FieldValue::Undefined);
        assert_eq!(left, right);
        right.active = true;
        assert_ne!(left, right);
        Ok(())
    }

    #[test]
    fn session_fields_preserve_native_values_omission_and_source_order() -> AuthResult<()> {
        let token = FieldValue::from(vec![FieldValue::from("native-token")]);
        let source = FieldMap::from([
            ("updatedAt".into(), "unparsed-date".into()),
            ("token".into(), token.clone()),
            ("expiresAt".into(), FieldValue::Null),
            ("ipAddress".into(), FieldValue::Undefined),
            ("ownUndefined".into(), FieldValue::Undefined),
        ]);
        let mut session = SessionView::from_field_values(source.clone())?;
        assert!(session.created_at.is_undefined());
        assert!(session.user_agent.is_undefined());
        assert!(session.token.field_value().strict_equals(&token));
        assert_eq!(FieldMap::from(session.clone()), source);
        assert_eq!(
            FieldMap::from(session.clone()).keys().collect::<Vec<_>>(),
            source.keys().collect::<Vec<_>>()
        );
        assert!(session.expires_at.date_milliseconds().is_err());
        assert_eq!(
            serde_json::to_value(&session)?,
            serde_json::json!({
                "updatedAt": "unparsed-date", "token": ["native-token"], "expiresAt": null
            })
        );
        session.token = SchemaValue::from_field(7.into());
        let updated = FieldMap::from(session);
        assert_eq!(updated.get("token"), Some(&7.into()));
        assert_eq!(
            updated.keys().collect::<Vec<_>>(),
            source.keys().collect::<Vec<_>>()
        );
        let decoded: SessionView =
            serde_json::from_str(r#"{"createdAt":"2030-01-02T03:04:05.000Z"}"#)?;
        assert_eq!(
            decoded.created_at.field_value(),
            FieldValue::from("2030-01-02T03:04:05.000Z"),
        );
        Ok(())
    }
}
