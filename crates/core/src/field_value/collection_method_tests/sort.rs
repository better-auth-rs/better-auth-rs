use super::*;
use crate::field_value::FieldArraySource;

#[test]
fn builtin_sort_keeps_the_receiver_and_orders_undefined_before_holes() -> AuthResult<()> {
    let array: FieldValue = FieldArray::with_length(5).into();
    array.set_model_property("0", 2.into())?;
    array.set_model_property("1", FieldValue::Undefined)?;
    array.set_model_property("3", 1.into())?;
    array.set_model_property("marker", "retained".into())?;
    let calls = Arc::new(Mutex::new(Vec::new()));
    let observed = calls.clone();
    let comparator = FieldFunction::contextual(move |receiver, arguments| {
        assert!(receiver.is_undefined());
        assert_eq!(arguments, [1.into(), 2.into()]);
        observed
            .lock()
            .map_err(|_| AuthError::internal("Sort observation lock poisoned"))?
            .push("compare");
        let observed = observed.clone();
        Ok(FieldMap::from([(
            "valueOf".into(),
            FieldFunction::contextual(move |_, _| {
                observed
                    .lock()
                    .map_err(|_| AuthError::internal("Sort observation lock poisoned"))?
                    .push("number");
                Ok((-1).into())
            })
            .into(),
        )])
        .into())
    });
    let sorted = array.sort_method(&comparator, "array")?;
    assert!(sorted.strict_equals(&array));
    assert_eq!(array.model_property("length")?, 5.into());
    assert_eq!(array.model_property("0")?, 1.into());
    assert_eq!(array.model_property("1")?, 2.into());
    assert!(array.model_property("2")?.is_undefined());
    assert!(array.has_property("2")?);
    assert!(!array.has_property("3")?);
    assert!(!array.has_property("4")?);
    assert_eq!(array.model_property("marker")?, "retained".into());
    assert_eq!(
        *calls
            .lock()
            .map_err(|_| AuthError::internal("Sort observation lock poisoned"))?,
        ["compare", "number"]
    );

    let array: FieldValue = vec![2.into(), 1.into()].into();
    let comparator = FieldFunction::contextual(|_, _| Ok(FieldValue::Number(f64::NAN)));
    let _ = array.sort_method(&comparator, "array")?;
    assert_eq!(array, vec![2.into(), 1.into()].into());
    Ok(())
}

#[test]
fn comparison_errors_preserve_callback_mutations_without_publishing_sorted_values() -> AuthResult<()>
{
    let array: FieldValue = vec![2.into(), 1.into()].into();
    let original = array.clone();
    let error: FieldValue = FieldMap::from([("nativeError".into(), true.into())]).into();
    let thrown = error.clone();
    let comparator = FieldFunction::contextual(move |_, _| {
        original.set_model_property("0", "callback change".into())?;
        Err(AuthError::from_thrown(thrown.clone()))
    });
    assert!(
        matches!(array.sort_method(&comparator, "array"), Err(actual) if actual.raw_value().is_some_and(|actual| actual.strict_equals(&error)))
    );
    assert_eq!(array, vec!["callback change".into(), 1.into()].into());
    Ok(())
}

struct Writable {
    values: FieldArray,
    failure: &'static str,
    error: FieldValue,
    events: Mutex<Vec<String>>,
}

impl Writable {
    fn observe(&self, operation: &str, index: usize) -> AuthResult<()> {
        let event = format!("{operation}:{index}");
        self.events
            .lock()
            .map_err(|_| AuthError::internal("Sort write observation lock poisoned"))?
            .push(event.clone());
        if event == self.failure {
            return Err(AuthError::from_thrown(self.error.clone()));
        }
        Ok(())
    }
}

impl FieldArraySource for Writable {
    fn properties(&self) -> &crate::FieldObject {
        self.values.properties()
    }
    fn len(&self) -> AuthResult<usize> {
        self.values.len()
    }
    fn own_indices(&self) -> AuthResult<Vec<usize>> {
        self.values.own_indices()
    }
    fn get(&self, index: usize, receiver: &FieldValue) -> AuthResult<Option<FieldValue>> {
        self.observe("get", index)?;
        self.values.get_with_receiver(index, receiver)
    }
    fn own_property_descriptor(
        &self,
        index: usize,
    ) -> AuthResult<Option<crate::FieldPropertyDescriptor>> {
        self.values.own_property_descriptor(index)
    }
    fn length_descriptor(&self) -> AuthResult<crate::FieldPropertyDescriptor> {
        self.values.length_descriptor()
    }
    fn define_index(
        &self,
        index: usize,
        definition: crate::FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        self.values.define_index(index, definition)
    }
    fn define_length(&self, definition: crate::FieldPropertyDefinition) -> AuthResult<bool> {
        self.values.define_length(definition)
    }
    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }
    fn set(&self, index: usize, value: FieldValue, receiver: &FieldValue) -> AuthResult<bool> {
        self.observe("set", index)?;
        self.values.assign_index(index, value, receiver)
    }
    fn delete(&self, index: usize) -> AuthResult<bool> {
        self.observe("delete", index)?;
        self.values.delete_index(index)
    }
}

#[test]
fn write_and_delete_errors_keep_completed_sort_writes_and_the_original_error() -> AuthResult<()> {
    for failure in ["set:1", "delete:3"] {
        let values = FieldArray::with_length(4);
        values.set(0, 2.into())?;
        values.set(1, FieldValue::Undefined)?;
        values.set(3, 1.into())?;
        let error: FieldValue = FieldMap::from([("failure".into(), failure.into())]).into();
        let source = Arc::new(Writable {
            values: values.clone(),
            failure,
            error: error.clone(),
            events: Mutex::new(Vec::new()),
        });
        let array: FieldValue = FieldArray::from_source(source.clone()).into();
        let comparator = FieldFunction::contextual(|_, arguments| {
            let [left, right] = arguments else {
                return Err(AuthError::internal("Sort must receive two values"));
            };
            Ok((crate::query::field_number(left)? - crate::query::field_number(right)?).into())
        });
        assert!(
            matches!(array.sort_method(&comparator, "array"), Err(actual) if actual.raw_value().is_some_and(|actual| actual.strict_equals(&error)))
        );
        assert_eq!(values.get(0)?, Some(1.into()));
        assert_eq!(values.get(3)?, Some(1.into()));
        assert_eq!(values.len()?, 4);
        if failure == "set:1" {
            assert_eq!(values.get(1)?, Some(FieldValue::Undefined));
            assert_eq!(values.get(2)?, None);
            assert_eq!(
                *source
                    .events
                    .lock()
                    .map_err(|_| AuthError::internal("Sort write observation lock poisoned"))?,
                ["get:0", "get:1", "get:2", "get:3", "set:0", "set:1"]
            );
        } else {
            assert_eq!(values.get(1)?, Some(2.into()));
            assert_eq!(values.get(2)?, Some(FieldValue::Undefined));
            assert_eq!(
                *source
                    .events
                    .lock()
                    .map_err(|_| AuthError::internal("Sort write observation lock poisoned"))?,
                [
                    "get:0", "get:1", "get:2", "get:3", "set:0", "set:1", "set:2", "delete:3"
                ]
            );
        }
    }
    Ok(())
}
