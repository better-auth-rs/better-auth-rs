use crate::{AuthRecordFields, AuthResult, FieldDate, FieldValue, FromFieldMap, SchemaValue};
use serde::{Deserialize, Serialize};

/// A database projection or an untransformed secondary verification snapshot.
/// Omitted core fields remain omitted; pure secondary creation does not generate an adapter ID.
#[derive(Debug, Clone, Default)]
pub struct VerificationView {
    /// Source property order, independent of the current typed values.
    pub field_order: Vec<String>,
    pub id: SchemaValue<String>,
    pub identifier: SchemaValue<String>,
    pub value: SchemaValue<String>,
    pub expires_at: SchemaValue<crate::FieldDate>,
    pub created_at: SchemaValue<crate::FieldDate>,
    pub updated_at: SchemaValue<crate::FieldDate>,
    pub additional_fields: crate::FieldMap,
}

impl VerificationView {
    /// Decode cached or adapter-projected fields without running field policies again.
    /// Preserve projected date values before JSON serialization loses invalid-date provenance.
    pub fn from_adapter_fields(mut fields: crate::FieldMap) -> Self {
        let field_order = fields.keys().cloned().collect();
        Self {
            field_order,
            id: SchemaValue::from_field(fields.shift_remove("id").unwrap_or_default()),
            identifier: SchemaValue::from_field(
                fields.shift_remove("identifier").unwrap_or_default(),
            ),
            value: SchemaValue::from_field(fields.shift_remove("value").unwrap_or_default()),
            expires_at: SchemaValue::from_field(
                fields.shift_remove("expiresAt").unwrap_or_default(),
            ),
            created_at: SchemaValue::from_field(
                fields.shift_remove("createdAt").unwrap_or_default(),
            ),
            updated_at: SchemaValue::from_field(
                fields.shift_remove("updatedAt").unwrap_or_default(),
            ),
            additional_fields: fields,
        }
    }

    pub fn from_fields(fields: crate::FieldMap) -> AuthResult<Self> {
        Self::from_field_values(fields)
    }

    pub fn fields(&self) -> AuthResult<crate::FieldMap> {
        self.field_values()
    }
}

impl Serialize for VerificationView {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        crate::field_value::serde::map::serialize(
            &self.field_values().map_err(serde::ser::Error::custom)?,
            serializer,
        )
    }
}

impl<'de> Deserialize<'de> for VerificationView {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut fields = crate::field_value::serde::map::deserialize(deserializer)?;
        for name in ["expiresAt", "createdAt", "updatedAt"] {
            if let Some(FieldValue::String(text)) = fields.get(name)
                && let Some(date) = crate::utils::json::parse_json_date(text)
            {
                let _ = fields.insert(name.into(), FieldDate::from(date).into());
            }
        }
        Ok(Self::from_adapter_fields(fields))
    }
}

impl PartialEq for VerificationView {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.identifier == other.identifier
            && self.value == other.value
            && self.expires_at == other.expires_at
            && self.created_at == other.created_at
            && self.updated_at == other.updated_at
            && self.additional_fields == other.additional_fields
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FieldMap;

    #[test]
    fn verification_fields_keep_order_and_dynamic_dates_without_static_placeholders()
    -> AuthResult<()> {
        let fields = FieldMap::from([
            ("value".into(), FieldValue::Null),
            ("expiresAt".into(), "not-a-date".into()),
            ("identifier".into(), FieldValue::Undefined),
            ("additional".into(), FieldValue::Undefined),
        ]);
        let mut view = VerificationView::from_adapter_fields(fields.clone());
        assert_eq!(view.fields()?, fields);
        assert!(view.created_at.is_undefined());
        assert!(view.expires_at.date_milliseconds().is_err());
        assert_eq!(
            serde_json::to_value(&view)?,
            serde_json::json!({"value": null, "expiresAt": "not-a-date"})
        );
        view.value = "changed".into();
        assert_eq!(view.fields()?.get("value"), Some(&"changed".into()));
        assert_eq!(
            view.fields()?.keys().collect::<Vec<_>>(),
            fields.keys().collect::<Vec<_>>()
        );
        Ok(())
    }
}
