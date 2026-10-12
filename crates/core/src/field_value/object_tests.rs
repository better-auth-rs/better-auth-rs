#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare shared identity and conversion boundaries; setup and source errors propagate."
)]

use super::*;
use crate::{SchemaField, SchemaValue};

#[test]
fn omitted_data_and_accessor_updates_preserve_the_existing_property_kind() -> AuthResult<()> {
    for property in [
        FieldProperty::Data {
            value: 1.into(),
            writable: false,
        },
        FieldProperty::Accessor {
            get: Some(FieldFunction::contextual(|_, _| {
                Err(AuthError::internal(
                    "Descriptor updates must not read the getter",
                ))
            })),
            set: None,
        },
    ] {
        let descriptor = FieldPropertyDescriptor {
            enumerable: true,
            configurable: false,
            property,
        };
        let value: FieldValue = FieldObject::from(indexmap::IndexMap::from([(
            "value".into(),
            descriptor.clone(),
        )]))
        .into();
        for property in [
            FieldPropertyUpdate::Data {
                value: None,
                writable: None,
            },
            FieldPropertyUpdate::Accessor {
                get: None,
                set: None,
            },
        ] {
            assert!(value.define_own_property(
                "value",
                FieldPropertyDefinition {
                    property,
                    ..Default::default()
                }
            )?);
            assert_eq!(
                value.own_property_descriptor("value")?,
                Some(descriptor.clone())
            );
        }
    }
    Ok(())
}

#[test]
fn owned_accessor_probes_and_diagnostics_do_not_read_or_discard_the_original_error()
-> AuthResult<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    for enumerable in [false, true] {
        let reads = Arc::new(AtomicUsize::new(0));
        let observed = reads.clone();
        let original: FieldValue = FieldMap::from([("failure".into(), "original".into())]).into();
        let thrown = original.clone();
        let descriptor = FieldPropertyDescriptor {
            enumerable,
            configurable: true,
            property: FieldProperty::Accessor {
                get: Some(FieldFunction::contextual(move |receiver, _| {
                    observed.fetch_add(1, Ordering::SeqCst);
                    receiver.set_model_property("mutation", "retained".into())?;
                    Err(AuthError::from_thrown(thrown.clone()))
                })),
                set: None,
            },
        };
        let fields = indexmap::IndexMap::from([("selected".into(), descriptor.clone())]);
        let object = FieldObject::from(fields.clone());
        let other = FieldObject::from(fields);
        let value: FieldValue = object.clone().into();
        assert_eq!(object, other);
        assert!(format!("{object:?}").contains("Accessor"));
        assert_eq!(
            object.own_property_descriptor("selected")?,
            Some(descriptor)
        );
        let narrowed = SchemaValue::<serde_json::Value>::from_field(value.clone());
        assert!(matches!(narrowed, SchemaValue::Dynamic(_)));
        assert!(narrowed.field_value().strict_equals(&value));
        assert!(
            matches!(<serde_json::Value as SchemaField>::from_field(value.clone()),
            Err(retained) if retained.strict_equals(&value))
        );
        assert!(other.delete("selected")?);
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        let error = object
            .get("selected")
            .err()
            .ok_or_else(|| AuthError::internal("The accessor must retain its failure"))?;
        assert!(error.into_thrown_value()?.strict_equals(&original));
        assert_eq!(object.get("mutation")?, Some("retained".into()));
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }
    for flags in [
        (false, true, true),
        (true, false, true),
        (true, true, false),
    ] {
        let (enumerable, configurable, writable) = flags;
        let value: FieldValue = FieldObject::from(indexmap::IndexMap::from([(
            "value".into(),
            FieldPropertyDescriptor {
                enumerable,
                configurable,
                property: FieldProperty::Data {
                    value: 1.into(),
                    writable,
                },
            },
        )]))
        .into();
        let narrowed = SchemaValue::<serde_json::Value>::from_field(value.clone());
        assert!(matches!(narrowed, SchemaValue::Dynamic(_)));
        assert!(narrowed.field_value().strict_equals(&value));
    }
    Ok(())
}

#[test]
fn live_key_order_reaches_reflection_and_enumeration_without_wrapper_reordering() -> AuthResult<()>
{
    struct Source(FieldObject);
    impl FieldObjectSource for Source {
        fn own_keys(&self) -> AuthResult<Vec<String>> {
            Ok(["tail", "2", "1"].map(str::to_owned).to_vec())
        }
        fn own_property_descriptor(
            &self,
            name: &str,
        ) -> AuthResult<Option<FieldPropertyDescriptor>> {
            self.0.own_property_descriptor(name)
        }
        fn get_with_receiver(
            &self,
            name: &str,
            receiver: &FieldValue,
        ) -> AuthResult<Option<FieldValue>> {
            self.0.get_with_receiver(name, receiver)
        }
        fn set_with_receiver(
            &self,
            name: String,
            value: FieldValue,
            receiver: &FieldValue,
        ) -> AuthResult<bool> {
            self.0.set_with_receiver(&name, value, receiver)
        }
        fn define_own_property(
            &self,
            name: String,
            definition: FieldPropertyDefinition,
        ) -> AuthResult<bool> {
            self.0.define_own_property(name, definition)
        }
        fn delete(&self, name: &str) -> AuthResult<bool> {
            self.0.delete(name)
        }
        fn snapshot_fields(&self) -> AuthResult<FieldMap> {
            Err(AuthError::internal(
                "Property enumeration must retain the source key order",
            ))
        }
        fn identity(&self) -> usize {
            std::ptr::from_ref(self) as usize
        }
    }
    let owned: FieldObject = FieldMap::from([
        ("tail".into(), "tail".into()),
        ("2".into(), 2.into()),
        ("1".into(), 1.into()),
    ])
    .into();
    assert_eq!(owned.own_keys()?, ["1", "2", "tail"]);
    let live = FieldObject::from_source(Arc::new(Source(owned)));
    assert_eq!(live.own_keys()?, ["tail", "2", "1"]);
    let value: FieldValue = live.into();
    assert_eq!(value.own_property_keys()?, ["tail", "2", "1"]);
    assert_eq!(
        value
            .enumerable_fields()?
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["tail", "2", "1"]
    );
    Ok(())
}

#[test]
fn aliases_preserve_presence_and_property_order_through_mutation() -> AuthResult<()> {
    let object = FieldObject::from(FieldMap::from([
        ("first".into(), 1.into()),
        ("tail".into(), 2.into()),
        ("ownUndefined".into(), FieldValue::Undefined),
    ]));
    let alias = object.clone();
    assert_eq!(alias.get("absent")?, None);
    assert_eq!(alias.get("ownUndefined")?, Some(FieldValue::Undefined));
    assert_eq!(object.get("first")?, Some(1.into()));
    object.set("first", FieldValue::Null)?;
    assert_eq!(alias.get("first")?, Some(FieldValue::Null));
    assert!(alias.delete("first")?);
    assert_eq!(alias.get("first")?, None);
    object.set("first", false.into())?;
    assert_eq!(alias.get("ownUndefined")?, Some(FieldValue::Undefined));
    assert!(alias.delete("ownUndefined")?);
    assert_eq!(alias.get("ownUndefined")?, None);
    assert!(alias.delete("ownUndefined")?);
    assert_eq!(object.get("2")?, None);
    object.set("2", "two".into())?;
    assert_eq!(alias.get("1")?, None);
    alias.set("1", "one".into())?;
    assert!(object.same_object(&alias));
    let value = FieldValue::Object(object);
    let expected = ["1", "2", "tail", "first"];
    assert_eq!(
        alias
            .snapshot_fields()?
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(
        value
            .enumerable_fields()?
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(
        value.json()?.and_then(|value| value
            .as_object()
            .map(|fields| fields.keys().cloned().collect::<Vec<_>>())),
        Some(expected.map(str::to_owned).to_vec())
    );
    assert_eq!(
        value.stringify()?.as_deref(),
        Some("{\"1\":\"one\",\"2\":\"two\",\"tail\":2,\"first\":false}")
    );
    Ok(())
}

#[test]
fn schema_decoding_preserves_handles_and_explicit_rust_copies_remain_available() -> AuthResult<()> {
    let object = FieldObject::from(FieldMap::from([("answer".into(), 1.into())]));
    let value = FieldValue::Object(object.clone());
    let json = SchemaValue::<serde_json::Value>::from_field(value.clone());
    let object_field = SchemaValue::<FieldObject>::from_field(value.clone());
    let value_field = SchemaValue::<FieldValue>::from_field(value.clone());
    assert!(matches!(json, SchemaValue::Dynamic(_)));
    assert!(object_field.typed()?.same_object(&object));
    assert!(value_field.typed()?.strict_equals(&value));
    object.set("answer", 2.into())?;
    assert_eq!(json.json()?, Some(serde_json::json!({"answer": 2})));
    assert!(json.field_value().strict_equals(&value));

    let array = FieldValue::from(vec![FieldValue::Number(1.0), FieldValue::Number(2.0)]);
    let vector = SchemaValue::<Vec<f64>>::from_field(array.clone());
    let optional = SchemaValue::<Option<Vec<f64>>>::from_field(array.clone());
    let json_array = SchemaValue::<serde_json::Value>::from_field(array.clone());
    for retained in [
        vector.field_value(),
        optional.field_value(),
        json_array.field_value(),
    ] {
        assert!(retained.strict_equals(&array));
    }
    assert!(matches!(vector, SchemaValue::Dynamic(_)));
    assert!(matches!(optional, SchemaValue::Dynamic(_)));
    assert_eq!(vector.field_value().decode::<Vec<f64>>()?, vec![1.0, 2.0]);
    assert_eq!(
        array.decode::<serde_json::Value>()?,
        serde_json::json!([1, 2])
    );

    let date = FieldDate::from_milliseconds(42.0);
    let date_field = SchemaValue::<FieldDate>::from_field(date.clone().into());
    assert!(date_field.typed()?.same_object(&date));
    assert_eq!(
        SchemaValue::<String>::from_field("ordinary".into()).typed()?,
        "ordinary"
    );
    assert_eq!(SchemaValue::<f64>::from_field(42.into()).typed()?, &42.0);
    assert_eq!(
        <Vec<f64> as SchemaField>::from_field(array),
        Ok(vec![1.0, 2.0])
    );
    Ok(())
}

#[test]
fn owned_cycles_have_finite_comparison_and_debug_but_require_explicit_unlinking() -> AuthResult<()>
{
    let left = FieldObject::from(FieldMap::from([("value".into(), 1.into())]));
    let right = FieldObject::from(FieldMap::from([("value".into(), 1.into())]));
    left.set("self", FieldValue::Object(left.clone()))?;
    right.set("self", FieldValue::Object(right.clone()))?;
    let equal = left == right;
    let debug = format!("{left:?}");
    let value = FieldValue::Object(left.clone());
    let json = value.json();
    let text = value.stringify();
    let clone = StructuredCloneContext::new().clone_value(&value);
    right.set("value", 2.into())?;
    let changed = left != right;
    // Break strong reference cycles before assertions or dropping the external handles.
    let _ = left.delete("self")?;
    let _ = right.delete("self")?;
    assert!(equal);
    assert!(changed);
    assert!(debug.contains("[Circular]"));
    assert!(
        matches!(json, Err(AuthError::TypeError(message)) if message == "Converting circular structure to JSON")
    );
    assert!(
        matches!(text, Err(AuthError::TypeError(message)) if message == "Converting circular structure to JSON")
    );
    let cloned = clone?;
    assert!(!cloned.strict_equals(&value));
    assert!(cloned.model_property("self")?.strict_equals(&cloned));
    assert_eq!(cloned.model_property("value")?, 1.into());
    let _ = cloned
        .as_object()
        .ok_or_else(|| AuthError::internal("Expected cloned object"))?
        .delete("self")?;
    Ok(())
}

#[test]
fn object_enumeration_preserves_descriptor_schedules_deletion_and_child_identity() -> AuthResult<()>
{
    use std::sync::Mutex;

    struct RestSource {
        fields: FieldObject,
        reads: Mutex<Vec<String>>,
    }

    impl FieldObjectSource for RestSource {
        fn own_keys(&self) -> AuthResult<Vec<String>> {
            self.reads
                .lock()
                .map_err(|_| AuthError::internal("Rest read events poisoned"))?
                .push("keys".into());
            self.fields.own_keys()
        }

        fn own_property_descriptor(
            &self,
            name: &str,
        ) -> AuthResult<Option<FieldPropertyDescriptor>> {
            if name == "excluded" {
                return Err(AuthError::internal("The excluded descriptor must not run"));
            }
            self.reads
                .lock()
                .map_err(|_| AuthError::internal("Rest read events poisoned"))?
                .push(format!("descriptor:{name}"));
            Ok(self
                .fields
                .own_property_descriptor(name)?
                .map(|mut descriptor| {
                    descriptor.enumerable = name != "hidden";
                    descriptor
                }))
        }

        fn get_with_receiver(
            &self,
            name: &str,
            receiver: &FieldValue,
        ) -> AuthResult<Option<FieldValue>> {
            if matches!(name, "excluded" | "hidden") {
                return Err(AuthError::internal("The unselected getter must not run"));
            }
            self.reads
                .lock()
                .map_err(|_| AuthError::internal("Rest read events poisoned"))?
                .push(format!("get:{name}"));
            let value = self.fields.get_with_receiver(name, receiver)?;
            if name == "first" {
                let _ = self.fields.delete("deleted")?;
                self.fields.set("added", "not-enumerated".into())?;
            }
            Ok(value)
        }

        fn set_with_receiver(
            &self,
            name: String,
            value: FieldValue,
            receiver: &FieldValue,
        ) -> AuthResult<bool> {
            self.fields.set_with_receiver(&name, value, receiver)
        }

        fn delete(&self, name: &str) -> AuthResult<bool> {
            self.fields.delete(name)
        }

        fn snapshot_fields(&self) -> AuthResult<FieldMap> {
            Err(AuthError::internal(
                "Rest must read only selected properties",
            ))
        }

        fn identity(&self) -> usize {
            std::ptr::from_ref(self) as usize
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

    let child = FieldValue::from(FieldMap::from([("value".into(), 1.into())]));
    let source = || {
        Arc::new(RestSource {
            fields: FieldMap::from([
                ("excluded".into(), "unread".into()),
                ("first".into(), child.clone()),
                ("deleted".into(), "removed-by-first".into()),
                ("hidden".into(), "not-enumerable".into()),
                ("alias".into(), child.clone()),
                ("ownUndefined".into(), FieldValue::Undefined),
            ])
            .into(),
            reads: Mutex::default(),
        })
    };
    for operation in ["rest", "spread", "json", "keys"] {
        let source = source();
        if operation != "rest" {
            let _ = source.fields.delete("excluded")?;
        }
        let object = FieldObject::from_source(source.clone());
        let value = FieldValue::Object(object.clone());
        let expected = match operation {
            "json" => {
                assert_eq!(
                    value.json()?,
                    Some(serde_json::json!({
                        "first": {"value": 1}, "alias": {"value": 1},
                    }))
                );
                vec![
                    "get:toJSON",
                    "keys",
                    "descriptor:first",
                    "descriptor:deleted",
                    "descriptor:hidden",
                    "descriptor:alias",
                    "descriptor:ownUndefined",
                    "get:first",
                    "get:deleted",
                    "get:alias",
                    "get:ownUndefined",
                ]
            }
            "keys" => {
                assert_eq!(
                    object.enumerable_keys()?,
                    ["first", "deleted", "alias", "ownUndefined"]
                );
                vec![
                    "keys",
                    "descriptor:first",
                    "descriptor:deleted",
                    "descriptor:hidden",
                    "descriptor:alias",
                    "descriptor:ownUndefined",
                ]
            }
            _ => {
                let fields = if operation == "rest" {
                    value.enumerable_fields_except(&["excluded"])?
                } else {
                    value.enumerable_fields()?
                };
                assert_eq!(
                    fields.keys().map(String::as_str).collect::<Vec<_>>(),
                    ["first", "alias", "ownUndefined"]
                );
                assert!(fields["first"].strict_equals(&child));
                assert!(fields["alias"].strict_equals(&child));
                assert!(fields["ownUndefined"].is_undefined());
                vec![
                    "keys",
                    "descriptor:first",
                    "get:first",
                    "descriptor:deleted",
                    "descriptor:hidden",
                    "descriptor:alias",
                    "get:alias",
                    "descriptor:ownUndefined",
                    "get:ownUndefined",
                ]
            }
        };
        assert_eq!(
            *source
                .reads
                .lock()
                .map_err(|_| AuthError::internal("Rest read events poisoned"))?,
            expected,
            "{operation}",
        );
        if operation != "keys" {
            assert_eq!(source.fields.get("deleted")?, None);
            assert_eq!(source.fields.get("added")?, Some("not-enumerated".into()));
        }
    }
    Ok(())
}

#[test]
fn record_consumers_keep_undefined_when_a_selected_descriptor_deletes_its_property()
-> AuthResult<()> {
    struct DeletingDescriptor(FieldObject);

    impl FieldObjectSource for DeletingDescriptor {
        fn own_keys(&self) -> AuthResult<Vec<String>> {
            self.0.own_keys()
        }

        fn own_property_descriptor(
            &self,
            name: &str,
        ) -> AuthResult<Option<FieldPropertyDescriptor>> {
            let descriptor = self.0.own_property_descriptor(name)?;
            if name == "selected" {
                let _ = self.0.delete(name)?;
            }
            Ok(descriptor)
        }

        fn get_with_receiver(
            &self,
            name: &str,
            receiver: &FieldValue,
        ) -> AuthResult<Option<FieldValue>> {
            self.0.get_with_receiver(name, receiver)
        }

        fn set_with_receiver(
            &self,
            name: String,
            value: FieldValue,
            receiver: &FieldValue,
        ) -> AuthResult<bool> {
            self.0.set_with_receiver(&name, value, receiver)
        }

        fn delete(&self, name: &str) -> AuthResult<bool> {
            self.0.delete(name)
        }

        fn snapshot_fields(&self) -> AuthResult<FieldMap> {
            Err(AuthError::internal(
                "Enumeration must inspect property descriptors",
            ))
        }

        fn identity(&self) -> usize {
            std::ptr::from_ref(self) as usize
        }

        fn define_own_property(
            &self,
            name: String,
            definition: crate::FieldPropertyDefinition,
        ) -> AuthResult<bool> {
            self.0.define_own_property(name, definition)
        }
    }

    let source = || {
        Arc::new(DeletingDescriptor(
            FieldMap::from([("selected".into(), 1.into()), ("excluded".into(), 2.into())]).into(),
        ))
    };
    for rest in [false, true] {
        let source = source();
        let value: FieldValue = FieldObject::from_source(source.clone()).into();
        let fields = if rest {
            value.enumerable_fields_except(&["excluded"])?
        } else {
            value.enumerable_fields()?
        };
        assert_eq!(fields.get("selected"), Some(&FieldValue::Undefined));
        assert_eq!(source.0.get("selected")?, None);
        assert_eq!(fields.contains_key("excluded"), !rest);
        assert_eq!(source.0.get("excluded")?, Some(2.into()));
    }
    let source = source();
    let value: FieldValue = FieldObject::from_source(source.clone()).into();
    let headers = crate::Headers::from_field_value(&value)?;
    assert_eq!(headers.get("selected"), Some(&"undefined".to_owned()));
    assert_eq!(headers.get("excluded"), Some(&"2".to_owned()));
    assert_eq!(source.0.get("selected")?, None);
    Ok(())
}
