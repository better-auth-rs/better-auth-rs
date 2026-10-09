use serde::{Deserialize, Serialize, Serializer};

use crate::{
    ApiKeyStart, AuthApiKey, AuthRecordFields, AuthResult, FieldDate, FieldMap, FieldValue,
    FromFieldMap, SchemaValue,
};

/// Public API key response. The stored key hash is never returned.
#[derive(Debug, Clone, Default)]
pub struct ApiKeyView {
    /// Declared application fields after adapter output projection.
    pub additional_fields: FieldMap,
    /// Source property order for native records and JSON responses.
    pub field_order: Vec<String>,
    pub id: SchemaValue<String>,
    pub name: SchemaValue<Option<String>>,
    pub start: SchemaValue<Option<ApiKeyStart>>,
    pub prefix: SchemaValue<Option<String>>,
    pub reference_id: SchemaValue<String>,
    pub config_id: SchemaValue<String>,
    pub refill_interval: SchemaValue<Option<f64>>,
    pub refill_amount: SchemaValue<Option<f64>>,
    pub last_refill_at: SchemaValue<Option<FieldDate>>,
    pub enabled: SchemaValue<bool>,
    pub rate_limit_enabled: SchemaValue<bool>,
    pub rate_limit_time_window: SchemaValue<Option<f64>>,
    pub rate_limit_max: SchemaValue<Option<f64>>,
    pub request_count: SchemaValue<Option<f64>>,
    pub remaining: SchemaValue<Option<f64>>,
    pub last_request: SchemaValue<Option<FieldDate>>,
    pub expires_at: SchemaValue<Option<FieldDate>>,
    pub created_at: SchemaValue<FieldDate>,
    pub updated_at: SchemaValue<FieldDate>,
    pub permissions: FieldValue,
    pub metadata: FieldValue,
}

// Source property order controls projection and does not affect typed value equality.
impl PartialEq for ApiKeyView {
    fn eq(&self, other: &Self) -> bool {
        self.additional_fields == other.additional_fields
            && self.id == other.id
            && self.name == other.name
            && self.start == other.start
            && self.prefix == other.prefix
            && self.reference_id == other.reference_id
            && self.config_id == other.config_id
            && self.refill_interval == other.refill_interval
            && self.refill_amount == other.refill_amount
            && self.last_refill_at == other.last_refill_at
            && self.enabled == other.enabled
            && self.rate_limit_enabled == other.rate_limit_enabled
            && self.rate_limit_time_window == other.rate_limit_time_window
            && self.rate_limit_max == other.rate_limit_max
            && self.request_count == other.request_count
            && self.remaining == other.remaining
            && self.last_request == other.last_request
            && self.expires_at == other.expires_at
            && self.created_at == other.created_at
            && self.updated_at == other.updated_at
            && self.permissions == other.permissions
            && self.metadata == other.metadata
    }
}

fn permissions(value: FieldValue) -> AuthResult<FieldValue> {
    if value.is_truthy() {
        crate::utils::json::safe_parse_field(&value)
    } else {
        Ok(FieldValue::Null)
    }
}

impl ApiKeyView {
    /// Project a native API key without reviving dates or changing property order.
    pub fn from_api_key_fields(fields: FieldMap) -> AuthResult<Self> {
        let mut view = Self::from_field_values(fields)?;
        view.permissions = permissions(view.permissions)?;
        // Upstream appends these response properties only when the source omits them.
        for name in ["metadata", "permissions"] {
            if !view.field_order.iter().any(|field| field == name) {
                view.field_order.push(name.into());
            }
        }
        Ok(view)
    }
}

impl Serialize for ApiKeyView {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let fields = self.field_values().map_err(serde::ser::Error::custom)?;
        crate::field_value::serde::map::serialize(&fields, serializer)
    }
}

impl<'de> Deserialize<'de> for ApiKeyView {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut fields = crate::field_value::serde::map::deserialize(deserializer)?;
        for name in [
            "createdAt",
            "updatedAt",
            "expiresAt",
            "lastRequest",
            "lastRefillAt",
        ] {
            if let Some(FieldValue::String(text)) = fields.get(name)
                && let Some(date) = crate::utils::json::parse_json_date(text)
            {
                let _ = fields.insert(name.into(), FieldDate::from(date).into());
            }
        }
        Self::from_field_values(fields).map_err(serde::de::Error::custom)
    }
}

impl ApiKeyView {
    /// Project a stored key through native fields and propagate dynamic read errors.
    pub fn try_from_api_key(key: &impl AuthApiKey) -> AuthResult<Self> {
        Self::from_api_key_fields(key.field_values()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(
        clippy::expect_used,
        clippy::panic_in_result_fn,
        reason = "Regression assertions require the complete native and serialized response shapes."
    )]
    fn native_projection_retains_order_and_uses_current_public_fields() -> AuthResult<()> {
        let mut fields = FieldMap::from_json(
            serde_json::json!({
                "extra": {"nested": true}, "updatedAt": null, "id": "original",
                "key": "private", "createdAt": "raw-date", "metadata": "old",
                "permissions": "{\"resource\":[\"read\"]}"
            })
            .as_object()
            .expect("fixture object")
            .clone(),
        )?;
        let _ = fields.insert("omitted".into(), FieldValue::Undefined);
        let mut view = ApiKeyView::from_api_key_fields(fields)?;
        let restored = ApiKeyView::from_field_values(view.field_values()?)?;
        assert_eq!(restored.field_order, view.field_order);
        assert_eq!(restored, view);
        view.id = "changed".to_owned().into();
        view.metadata = FieldValue::from_json(serde_json::json!({"migrated": true}))?;
        let _ = view
            .additional_fields
            .insert("newUndefined".into(), FieldValue::Undefined);
        let native = view.field_values()?;
        assert_eq!(
            native.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "extra",
                "updatedAt",
                "id",
                "createdAt",
                "metadata",
                "permissions",
                "omitted",
                "newUndefined"
            ]
        );
        assert_eq!(native.get("omitted"), Some(&FieldValue::Undefined));
        assert_eq!(native.get("newUndefined"), Some(&FieldValue::Undefined));
        assert!(!native.contains_key("lastRequest"));
        assert!(view.last_request.is_undefined());
        assert_eq!(view.created_at.field_value(), FieldValue::from("raw-date"));
        let response = serde_json::to_value(&view)?;
        assert_eq!(
            response,
            serde_json::json!({
                "extra": {"nested": true}, "updatedAt": null, "id": "changed",
                "createdAt": "raw-date", "metadata": {"migrated": true},
                "permissions": {"resource": ["read"]}
            })
        );
        assert_eq!(
            response
                .as_object()
                .expect("response object")
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [
                "extra",
                "updatedAt",
                "id",
                "createdAt",
                "metadata",
                "permissions"
            ]
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Regression assertions verify that every public construction path hides the stored key."
    )]
    fn public_projections_exclude_stored_keys() -> AuthResult<()> {
        #[derive(Serialize)]
        struct CreatedKey<'a> {
            key: &'a str,
            #[serde(flatten)]
            api_key: &'a ApiKeyView,
        }

        let decoded: ApiKeyView = serde_json::from_value(serde_json::json!({
            "id": "key-id", "key": "stored-hash", "permissions": null
        }))?;
        let native = ApiKeyView::from_field_values(FieldMap::from_iter([
            ("id".into(), "key-id".into()),
            ("key".into(), "stored-hash".into()),
            ("permissions".into(), FieldValue::Null),
        ]))?;
        let mut mutated = ApiKeyView {
            id: "key-id".to_owned().into(),
            permissions: FieldValue::Null,
            ..Default::default()
        };
        let _ = mutated
            .additional_fields
            .insert("key".into(), "stored-hash".into());
        let mut stored = crate::ApiKey::from_field_values(FieldMap::from_iter([
            ("id".into(), "key-id".into()),
            ("key".into(), "stored-hash".into()),
        ]))?;
        let _ = stored
            .additional_fields
            .insert("key".into(), "shadow-hash".into());
        let projected = ApiKeyView::try_from_api_key(&stored)?;
        for view in [decoded, native, mutated, projected] {
            assert!(!view.field_values()?.contains_key("key"));
            assert_eq!(
                serde_json::to_value(&view)?,
                serde_json::json!({"id": "key-id", "permissions": null})
            );
            assert_eq!(
                serde_json::to_value(CreatedKey {
                    key: "issued-plaintext",
                    api_key: &view,
                })?,
                serde_json::json!({"key": "issued-plaintext", "id": "key-id", "permissions": null})
            );
        }
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Regression assertions distinguish typed equality from source property order."
    )]
    fn equality_compares_typed_values_without_source_order() -> AuthResult<()> {
        let left = ApiKeyView::from_field_values(FieldMap::from_iter([
            ("id".into(), "key-id".into()),
            ("metadata".into(), FieldValue::Null),
            ("first".into(), "one".into()),
            ("second".into(), "two".into()),
        ]))?;
        let mut right = ApiKeyView::from_field_values(FieldMap::from_iter([
            ("second".into(), "two".into()),
            ("first".into(), "one".into()),
            ("metadata".into(), FieldValue::Null),
            ("id".into(), "key-id".into()),
        ]))?;
        assert_ne!(left.field_order, right.field_order);
        assert_eq!(left, right);
        right.id = "other-id".to_owned().into();
        assert_ne!(left, right);
        Ok(())
    }
}
