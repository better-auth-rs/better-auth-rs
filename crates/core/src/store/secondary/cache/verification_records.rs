#![expect(
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Assertions report exact contract mismatches while Result propagates fixture errors."
)]

use super::*;
use crate::field_value::{FieldObjectSource, FieldPropertyDescriptor};
use crate::{AuthError, FieldArray, FieldFunction, FieldObject};
use std::sync::Mutex;

#[tokio::test]
async fn consume_native_verification_preserves_values_and_checks_expiry_before_spreading()
-> AuthResult<()> {
    let (store, cache) = storage()?;
    let payload: FieldValue = FieldMap::from([("dateText".into(), DATE_TEXT.into())]).into();
    for kind in ["object", "array", "date"] {
        let properties = FieldObject::from(FieldMap::from([
            ("value".into(), DATE_TEXT.into()),
            ("payload".into(), payload.clone()),
            ("expiresAt".into(), EXPIRY.into()),
            ("createdAt".into(), DATE_TEXT.into()),
        ]));
        let raw = match kind {
            "array" => FieldArray::from_values_with_properties(vec![7.into()], properties).into(),
            "date" => FieldDate::from_milliseconds_with_properties(NOW as f64, properties).into(),
            _ => FieldValue::Object(properties),
        };
        cache
            .set_native(&"verification:native".into(), &raw, None)
            .await?;
        let consumed = store
            .consume_verification_including_expired("native")
            .await?
            .unwrap();
        let fields = consumed.fields()?;
        assert_eq!(fields.get("value"), Some(&DATE_TEXT.into()));
        assert_eq!(fields.get("createdAt"), Some(&DATE_TEXT.into()));
        assert!(fields.get("payload").unwrap().strict_equals(&payload));
        assert_eq!(consumed.expires_at.date_milliseconds()?, EXPIRY as f64);
        assert_eq!(fields.contains_key("0"), kind == "array");
        assert!(
            cache
                .get_native(&"verification:native".into())
                .await?
                .is_none()
        );
    }
    for raw in [
        true.into(),
        1.into(),
        FieldFunction::contextual(|_, _| Ok(FieldValue::Undefined)).into(),
        "true".into(),
        "1".into(),
        r#""text""#.into(),
    ] {
        cache
            .set_native(&"verification:primitive".into(), &raw, None)
            .await?;
        assert!(
            store
                .consume_verification_including_expired("primitive")
                .await?
                .is_none()
        );
        assert!(
            cache
                .get_native(&"verification:primitive".into())
                .await?
                .is_none()
        );
    }
    Ok(())
}

struct Properties {
    fields: FieldMap,
    reads: Arc<Mutex<Vec<String>>>,
    reject: Option<&'static str>,
    error: FieldValue,
}

impl FieldObjectSource for Properties {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        self.reads.lock().unwrap().push("ownKeys".into());
        crate::FieldObject::from(self.fields.clone()).own_keys()
    }

    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        Ok(self
            .fields
            .get(name)
            .cloned()
            .map(FieldPropertyDescriptor::data))
    }

    fn get_with_receiver(
        &self,
        name: &str,
        _receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        self.reads.lock().unwrap().push(name.into());
        if self.reject == Some(name) {
            return Err(AuthError::from_thrown(self.error.clone()));
        }
        Ok(self.fields.get(name).cloned())
    }

    fn set_with_receiver(
        &self,
        _: String,
        _: FieldValue,
        _receiver: &FieldValue,
    ) -> AuthResult<bool> {
        Err(AuthError::internal(
            "The verification getter contract is read-only",
        ))
    }

    fn delete(&self, _: &str) -> AuthResult<bool> {
        Err(AuthError::internal(
            "The verification getter contract is read-only",
        ))
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "Verification consumption must spread the live record",
        ))
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self).addr()
    }

    fn define_own_property(
        &self,
        _name: String,
        _definition: crate::FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        Err(AuthError::internal(
            "This contract source does not define properties",
        ))
    }
}

#[tokio::test]
async fn consume_getter_order_and_original_errors_follow_atomic_removal() -> AuthResult<()> {
    let (store, cache) = storage()?;
    let original: FieldValue = FieldMap::from([("original".into(), true.into())]).into();
    for (expiry, reject, expected) in [
        (
            EXPIRY.into(),
            None,
            vec!["expiresAt", "ownKeys", "value", "expiresAt"],
        ),
        (FieldValue::Undefined, Some("value"), vec!["expiresAt"]),
        (EXPIRY.into(), Some("expiresAt"), vec!["expiresAt"]),
        (
            EXPIRY.into(),
            Some("value"),
            vec!["expiresAt", "ownKeys", "value"],
        ),
    ] {
        let invalid = expiry.is_undefined();
        let reads = Arc::new(Mutex::new(Vec::new()));
        let raw = FieldObject::from_source(Arc::new(Properties {
            fields: FieldMap::from([
                ("value".into(), DATE_TEXT.into()),
                ("expiresAt".into(), expiry),
            ]),
            reads: reads.clone(),
            reject,
            error: original.clone(),
        }))
        .into();
        cache
            .set_native(&"verification:live".into(), &raw, None)
            .await?;
        let outcome = store.consume_verification_including_expired("live").await;
        if invalid {
            assert!(outcome?.is_none());
        } else if reject.is_some() {
            assert!(
                outcome
                    .unwrap_err()
                    .into_thrown_value()?
                    .strict_equals(&original)
            );
        } else {
            assert!(outcome?.is_some());
        }
        assert_eq!(*reads.lock().unwrap(), expected);
        assert!(
            cache
                .get_native(&"verification:live".into())
                .await?
                .is_none()
        );
    }
    Ok(())
}
