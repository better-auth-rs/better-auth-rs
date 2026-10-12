use super::*;
use crate::{FromFieldMap, SchemaField, SchemaValue};

struct DecodedRecord {
    fields: FieldMap,
    strings: Vec<Vec<String>>,
    json: serde_json::Value,
}

impl AuthRecordFields for DecodedRecord {
    fn field_values(&self) -> AuthResult<FieldMap> {
        Ok(self.fields.clone())
    }
}

impl FromFieldMap for DecodedRecord {
    fn from_field_values(fields: FieldMap) -> AuthResult<Self> {
        if fields["gate"].model_property("allowed")? != true.into() {
            return Err(AuthError::internal("Native decoder rejected the record"));
        }
        Ok(Self {
            strings: fields["strings"].decode()?,
            json: fields["json"].decode()?,
            fields,
        })
    }
}

#[test]
fn default_record_restoration_reads_populated_targets_and_retries_after_decode_failure()
-> AuthResult<()> {
    let gate = FieldObject::from(FieldMap::from([("allowed".into(), false.into())]));
    let strings = vec![vec!["first".to_owned(), "second".to_owned()], vec![]];
    let json = serde_json::json!({"nested": [{"label": "kept"}], "empty": []});
    let source = DecodedRecord {
        fields: [
            ("strings".into(), strings.clone().into_field()),
            ("json".into(), json.clone().into()),
            ("gate".into(), FieldValue::Object(gate.clone())),
        ]
        .into(),
        strings: Vec::new(),
        json: serde_json::Value::Null,
    };
    let mut context = StructuredCloneContext::new();
    let rejected = source.structured_clone(&mut context);
    assert!(
        matches!(rejected, Err(AuthError::Internal(message)) if message == "Native decoder rejected the record")
    );
    assert!(context.copies.is_empty());
    gate.set("allowed", true.into())?;
    let cloned = source.structured_clone(&mut context)?;
    assert_eq!(cloned.strings, strings);
    assert_eq!(cloned.json, json);
    assert_eq!(cloned.fields, source.fields);
    assert!(!cloned.fields["gate"].strict_equals(&FieldValue::Object(gate.clone())));
    assert!(!cloned.fields["strings"].strict_equals(&source.fields["strings"]));
    Ok(())
}

#[test]
fn clone_field_retains_nested_schema_variants_and_typed_json_values() -> AuthResult<()> {
    let source = SchemaValue::Typed(vec![
        Some(SchemaValue::<String>::Dynamic("dynamic".into())),
        Some(SchemaValue::Dynamic(FieldValue::Undefined)),
        Some(SchemaValue::Undefined),
        Some(SchemaValue::Typed("typed".to_owned())),
        None,
    ]);
    let cloned = StructuredCloneContext::new().clone_field(&source)?;
    assert_eq!(cloned, source);
    assert!(matches!(
        cloned.typed()?.as_slice(),
        [
            Some(SchemaValue::Dynamic(FieldValue::String(_))),
            Some(SchemaValue::Dynamic(FieldValue::Undefined)),
            Some(SchemaValue::Undefined),
            Some(SchemaValue::Typed(_)),
            None,
        ]
    ));

    let json = SchemaValue::Typed(serde_json::json!({"items": [1, {"name": "nested"}]}));
    assert_eq!(StructuredCloneContext::new().clone_field(&json)?, json);

    let date = FieldDate::from_milliseconds(42.0);
    let source = vec![
        SchemaValue::Typed(date.clone()),
        SchemaValue::Dynamic(date.clone().into()),
    ];
    let cloned = StructuredCloneContext::new().clone_field(&source)?;
    assert!(matches!(
        cloned.as_slice(),
        [SchemaValue::Typed(_), SchemaValue::Dynamic(_)]
    ));
    assert!(
        cloned[0]
            .field_value()
            .strict_equals(&cloned[1].field_value())
    );
    assert!(!cloned[0].field_value().strict_equals(&date.into()));
    Ok(())
}

#[test]
#[expect(
    clippy::panic,
    reason = "The contract injects an unwinding native decoder to verify staged graph cleanup."
)]
fn restoration_errors_and_panics_clear_new_cycles_without_polluting_the_context() -> AuthResult<()>
{
    for panics in [false, true] {
        let object = FieldObject::from(FieldMap::from([("value".into(), 1.into())]));
        let array = FieldArray::from(vec![FieldValue::Object(object.clone()), "tail".into()]);
        object.set("array", array.clone().into())?;
        let date = FieldValue::from(FieldDate::from_milliseconds(42.0));
        let mut context = StructuredCloneContext::new();
        let existing = context.clone_value(&date)?;
        let fields = FieldMap::from([("date".into(), date), ("root".into(), array.clone().into())]);
        let message = "native-restoration-original".to_owned();
        let allocation = message.as_ptr() as usize;
        let mut targets = None;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            context.clone_with(&fields, &[], |fields, _| -> AuthResult<()> {
                let array = fields["root"]
                    .as_array()
                    .ok_or_else(|| AuthError::internal("Expected restored array"))?
                    .clone();
                let object = array
                    .get(0)?
                    .and_then(|value| value.as_object().cloned())
                    .ok_or_else(|| AuthError::internal("Expected restored object"))?;
                assert_eq!(array.len()?, 2);
                assert_eq!(object.get("value")?, Some(1.into()));
                assert!(
                    object
                        .get("array")?
                        .is_some_and(|value| value.strict_equals(&fields["root"]))
                );
                targets = Some((array, object));
                if panics {
                    panic!("Native decoder panicked");
                }
                Err(AuthError::Internal(message))
            })
        }));
        match outcome {
            Ok(result) => {
                assert!(!panics);
                assert!(
                    matches!(result, Err(AuthError::Internal(message)) if message.as_ptr() as usize == allocation)
                );
            }
            Err(_) => assert!(panics),
        }
        assert_eq!(context.copies.len(), 1);
        let (failed_array, failed_object) =
            targets.ok_or_else(|| AuthError::internal("Expected staged restoration targets"))?;
        assert_eq!(failed_array.len()?, 0);
        assert!(failed_object.snapshot_fields()?.is_empty());
        object.set("value", 2.into())?;
        let cloned = context.clone_map(&fields)?;
        assert!(cloned["date"].strict_equals(&existing));
        let copied_object = cloned["root"]
            .as_array()
            .ok_or_else(|| AuthError::internal("Expected retried array"))?
            .get(0)?
            .and_then(|value| value.as_object().cloned())
            .ok_or_else(|| AuthError::internal("Expected retried object"))?;
        assert_eq!(copied_object.get("value")?, Some(2.into()));
        assert!(
            copied_object
                .get("array")?
                .is_some_and(|value| value.strict_equals(&cloned["root"]))
        );
        let _ = object.delete("array")?;
        let _ = copied_object.delete("array")?;
    }
    Ok(())
}

#[test]
fn restoration_reads_deferred_aliases_without_publishing_them_on_failure_or_success()
-> AuthResult<()> {
    let source = FieldValue::from(vec![FieldValue::from("previous")]);
    let fresh = FieldValue::from(vec![FieldValue::from("fresh")]);
    let mut context = StructuredCloneContext::deferred();
    let previous = context.clone_value(&source)?;
    let count = context.copies.len();
    let pending = context.pending.as_ref().map(Vec::len);
    let fields = FieldMap::from([("previous".into(), source), ("fresh".into(), fresh)]);
    let mut failed_target = None;
    let result = context.clone_with(&fields, &[], |fields, _| -> AuthResult<()> {
        assert!(fields["previous"].strict_equals(&previous));
        assert_eq!(fields["previous"].decode::<Vec<String>>()?, ["previous"]);
        assert_eq!(fields["fresh"].decode::<Vec<String>>()?, ["fresh"]);
        failed_target = fields["fresh"].as_array().cloned();
        Err(AuthError::internal("Deferred restoration failed"))
    });
    assert!(
        matches!(result, Err(AuthError::Internal(message)) if message == "Deferred restoration failed")
    );
    assert_eq!(context.copies.len(), count);
    assert_eq!(context.pending.as_ref().map(Vec::len), pending);
    assert_eq!(
        failed_target
            .ok_or_else(|| AuthError::internal("Expected deferred failure target"))?
            .len()?,
        0
    );
    let previous_array = previous
        .as_array()
        .ok_or_else(|| AuthError::internal("Expected previous deferred array"))?;
    assert_eq!(previous_array.len()?, 0);
    let restored = context.clone_with(&fields, &[], |fields, _| {
        assert_eq!(fields["previous"].decode::<Vec<String>>()?, ["previous"]);
        assert_eq!(fields["fresh"].decode::<Vec<String>>()?, ["fresh"]);
        Ok(fields)
    })?;
    assert_eq!(previous_array.len()?, 0);
    assert_eq!(
        restored["fresh"]
            .as_array()
            .ok_or_else(|| AuthError::internal("Expected restored deferred array"))?
            .len()?,
        0
    );
    context.publish();
    assert_eq!(previous.decode::<Vec<String>>()?, ["previous"]);
    assert_eq!(restored["fresh"].decode::<Vec<String>>()?, ["fresh"]);
    assert!(restored["previous"].strict_equals(&previous));
    Ok(())
}
