//! Rows preserve object identity when a transaction commits into the live table.

use crate::user_fields::UserRowState;
use crate::{
    AuthError, AuthRecordFields, AuthResult, FieldMap, FieldObject, FieldValue, FromFieldMap,
    field_value::{FieldObjectSource, FieldPropertyDefinition, FieldPropertyDescriptor},
};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, MutexGuard};

use super::operation::MemoryGate;

/// Snapshot guards retain property presence and native identity, including unchanged NaN values.
pub(super) fn same_field_value(actual: Option<&FieldValue>, before: Option<&FieldValue>) -> bool {
    match (actual, before) {
        (Some(actual), Some(before)) => actual.same_value_zero(before),
        (None, None) => true,
        _ => false,
    }
}

#[derive(Clone)]
pub(super) enum RowValue<T> {
    Typed(T),
    Properties(FieldObject),
}

#[derive(Clone)]
pub(super) struct RowCell<T> {
    pub(super) value: RowValue<T>,
    user_state: Option<UserRowState>,
}

impl<T> RowCell<T> {
    pub(super) fn new(value: T) -> Self {
        Self {
            value: RowValue::Typed(value),
            user_state: None,
        }
    }
}

#[cfg(test)]
impl RowCell<FieldMap> {
    pub(super) fn from_user_state(user: crate::UserView) -> Self {
        let (value, state) = user.into_row_parts();
        Self {
            value: RowValue::Typed(value),
            user_state: Some(state),
        }
    }
}

enum RowStorage<T> {
    Record(Arc<Mutex<RowCell<T>>>),
    Native(FieldObject),
}

pub(super) struct RowRef<T> {
    storage: RowStorage<T>,
    gate: MemoryGate,
}

impl<T> Clone for RowRef<T> {
    fn clone(&self) -> Self {
        Self {
            storage: match &self.storage {
                RowStorage::Record(value) => RowStorage::Record(value.clone()),
                RowStorage::Native(value) => RowStorage::Native(value.clone()),
            },
            gate: self.gate.clone(),
        }
    }
}

#[derive(Clone)]
pub(super) enum RecordSource {
    Live(RowRef<FieldMap>),
    LiveWithPatch(RowRef<FieldMap>, Box<FieldMap>),
    Snapshot(Box<FieldMap>),
}

impl RecordSource {
    pub(super) fn with_patch(self, patch: FieldMap) -> Self {
        if patch.is_empty() {
            return self;
        }
        match self {
            Self::Live(source) => Self::LiveWithPatch(source, Box::new(patch)),
            Self::LiveWithPatch(source, mut fields) => {
                fields.extend(patch);
                Self::LiveWithPatch(source, fields)
            }
            Self::Snapshot(mut fields) => {
                fields.extend(patch);
                Self::Snapshot(fields)
            }
        }
    }

    pub(super) fn joined(
        mut parent: FieldMap,
        relations: impl IntoIterator<Item = (String, FieldValue)>,
    ) -> Self {
        // Native adapters attach relations to a shallow parent copy before field output.
        parent.extend(relations);
        Self::Snapshot(Box::new(parent))
    }

    pub(super) fn field(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        match self {
            Self::Live(source) => source.field(name),
            Self::LiveWithPatch(source, patch) => {
                let live = source.field(name)?;
                Ok(patch.get(name).cloned().or(live))
            }
            Self::Snapshot(record) => Ok(record.get(name).cloned()),
        }
    }

    pub(super) fn shallow_fields(&self) -> AuthResult<FieldMap> {
        match self {
            Self::Live(source) => source.shallow_fields(),
            Self::LiveWithPatch(source, patch) => {
                let mut fields = source.shallow_fields()?;
                fields.extend(
                    patch
                        .iter()
                        .map(|(name, value)| (name.clone(), value.clone())),
                );
                Ok(fields)
            }
            Self::Snapshot(record) => Ok((**record).clone()),
        }
    }
}

/// Read properties as shallow handles; implementations must not evaluate child values.
pub(super) trait ObjectRow:
    AuthRecordFields + FromFieldMap + Clone + Send + Sync + 'static
{
    fn property(&self, name: &str) -> AuthResult<Option<FieldValue>>;
}

impl ObjectRow for FieldMap {
    fn property(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        Ok(self.get(name).cloned())
    }
}

impl<T: ObjectRow> FieldObjectSource for RowRef<T> {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        let _operation = self.gate.lock();
        self.with_storage(
            |value| {
                let mut fields = value.field_values()?;
                fields.sort_property_order();
                Ok(fields.keys().cloned().collect())
            },
            FieldObject::own_keys,
        )
    }

    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        let _operation = self.gate.lock();
        self.with_storage(
            |value| Ok(value.property(name)?.map(FieldPropertyDescriptor::data)),
            |object| object.own_property_descriptor(name),
        )
    }

    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        let _operation = self.gate.lock();
        self.with_storage(
            |value| value.property(name),
            |object| object.get_with_receiver(name, receiver),
        )
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        self.shallow_fields()
    }

    fn set_with_receiver(
        &self,
        name: String,
        value: FieldValue,
        receiver: &FieldValue,
    ) -> AuthResult<bool> {
        let _operation = self.gate.lock();
        self.discard_user_state()?;
        self.property_storage()?
            .set_with_receiver(&name, value, receiver)
    }

    fn define_own_property(
        &self,
        name: String,
        definition: FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        let _operation = self.gate.lock();
        self.discard_user_state()?;
        self.property_storage()?
            .define_own_property(name, definition)
    }

    fn delete(&self, name: &str) -> AuthResult<bool> {
        let _operation = self.gate.lock();
        self.discard_user_state()?;
        self.property_storage()?.delete(name)
    }

    fn identity(&self) -> usize {
        match &self.storage {
            RowStorage::Record(row) => Arc::as_ptr(row) as usize,
            RowStorage::Native(object) => match object.identity() {
                crate::field_value::ObjectIdentity::Owned(identity)
                | crate::field_value::ObjectIdentity::Live(identity) => identity,
            },
        }
    }

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }

    fn clone_seed(&self) -> AuthResult<Option<crate::field_value::ObjectCloneSeed>> {
        let source = match &self.storage {
            RowStorage::Record(source) => source,
            RowStorage::Native(object) => return object.clone_seed().map(Some),
        };
        let before = {
            let _operation = self.gate.lock();
            Arc::new(lock(source)?.clone())
        };
        let state = before
            .user_state
            .as_ref()
            .map_or_else(Vec::new, |state| state.hidden_values().to_vec());
        let target_cell = Arc::new(Mutex::new((*before).clone()));
        let target = Self {
            storage: RowStorage::Record(target_cell.clone()),
            gate: self.gate.clone(),
        };
        let object = FieldObject::from_source(Arc::new(target));
        Ok(Some(crate::field_value::ObjectCloneSeed {
            object,
            state,
            original_record: Some(before.clone()),
            prepare: Box::new(move |fields, state, original_fields| {
                let user_state = before
                    .user_state
                    .as_ref()
                    .map(|user| user.with_cloned_fields(&original_fields, &fields, state))
                    .transpose()?;
                let value = match &before.value {
                    RowValue::Typed(_) => RowValue::Typed(T::from_field_values(fields)?),
                    RowValue::Properties(_) => RowValue::Properties(fields.into()),
                };
                Ok(crate::field_value::prepare_clone(
                    target_cell,
                    RowCell { value, user_state },
                ))
            }),
        }))
    }
}

impl<T: ObjectRow> RowRef<T> {
    fn with_storage<R>(
        &self,
        typed: impl FnOnce(&T) -> AuthResult<R>,
        properties: impl FnOnce(&FieldObject) -> AuthResult<R>,
    ) -> AuthResult<R> {
        let object = match &self.storage {
            RowStorage::Record(source) => {
                let row = lock(source)?;
                match &row.value {
                    RowValue::Typed(value) => return typed(value),
                    RowValue::Properties(object) => object.clone(),
                }
            }
            RowStorage::Native(object) => object.clone(),
        };
        properties(&object)
    }

    fn current_value(&self) -> AuthResult<RowValue<T>> {
        match &self.storage {
            RowStorage::Record(row) => Ok(lock(row)?.value.clone()),
            RowStorage::Native(object) => Ok(RowValue::Properties(object.clone())),
        }
    }

    // Promotion changes property storage, while the public row retains its original identity.
    fn property_storage(&self) -> AuthResult<FieldObject> {
        let source = match &self.storage {
            RowStorage::Record(source) => source,
            RowStorage::Native(object) => return Ok(object.clone()),
        };
        let mut row = lock(source)?;
        let object = match &row.value {
            RowValue::Properties(object) => return Ok(object.clone()),
            RowValue::Typed(value) => FieldObject::from(value.field_values()?),
        };
        let previous = std::mem::replace(&mut row.value, RowValue::Properties(object.clone()));
        drop(row);
        drop(previous);
        Ok(object)
    }

    fn discard_user_state(&self) -> AuthResult<()> {
        if let RowStorage::Record(source) = &self.storage {
            let previous = lock(source)?.user_state.take();
            drop(previous);
        }
        Ok(())
    }

    pub(super) fn field(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        self.get_with_receiver(name, &self.field_value())
    }

    pub(super) fn shallow_fields(&self) -> AuthResult<FieldMap> {
        let _operation = self.gate.lock();
        self.field_value().enumerable_fields()
    }

    #[cfg(test)]
    pub(super) fn set_field(&self, name: String, value: FieldValue) -> AuthResult<()> {
        let _operation = self.gate.lock();
        self.discard_user_state()?;
        self.field_value().set_model_property(&name, value)
    }

    #[cfg(test)]
    pub(super) fn delete_field(&self, name: &str) -> AuthResult<bool> {
        self.delete(name)
    }

    pub(super) fn apply_patch(&self, mut patch: FieldMap) -> AuthResult<()> {
        let _operation = self.gate.lock();
        self.discard_user_state()?;
        patch.sort_property_order();
        let receiver = self.field_value();
        for (name, value) in patch {
            receiver.set_model_property(&name, value)?;
        }
        Ok(())
    }

    pub(super) fn increment_number_fields(&self, increments: &[(String, f64)]) -> AuthResult<()> {
        let _operation = self.gate.lock();
        self.discard_user_state()?;
        let receiver = self.field_value();
        for (name, delta) in increments {
            let previous = if self.field(name)?.is_some_and(|value| value.is_number()) {
                self.field(name)?.unwrap_or_default()
            } else {
                FieldValue::Number(0.0)
            };
            receiver.set_model_property(
                name,
                crate::query::field_add(&previous, &FieldValue::Number(*delta))?,
            )?;
        }
        Ok(())
    }
}

impl<T: ObjectRow> RowRef<T> {
    pub(super) fn field_value(&self) -> FieldValue {
        match &self.storage {
            RowStorage::Record(_) => FieldObject::from_source(Arc::new(self.clone())).into(),
            RowStorage::Native(object) => object.clone().into(),
        }
    }

    pub(super) fn structured_clone(
        &self,
        context: &mut crate::StructuredCloneContext,
    ) -> AuthResult<(Self, T)> {
        if let RowStorage::Native(object) = &self.storage {
            let (cloned, before) = context.clone_object_fields(object)?;
            return Ok((
                Self::from_object(cloned, self.gate.clone()),
                T::from_field_values(before)?,
            ));
        }
        let original = self.field_value();
        let (value, before) = context.clone_record::<RowCell<T>>(&original)?;
        let row = value
            .as_object()
            .and_then(crate::FieldObject::source::<Self>)
            .cloned()
            .ok_or_else(|| AuthError::internal("Structured clone lost its native row type"))?;
        let before = match before.value {
            RowValue::Typed(value) => value,
            RowValue::Properties(_) => {
                let object = original.as_object().ok_or_else(|| {
                    AuthError::internal("Structured clone lost its native row object")
                })?;
                T::from_field_values(context.clone_object_fields(object)?.1)?
            }
        };
        Ok((row, before))
    }
}

impl<T: ObjectRow> crate::store::JoinValue<RowRef<T>> {
    pub(super) fn raw_value(&self) -> FieldValue {
        match self {
            Self::One(row) => row.as_ref().map_or(FieldValue::Null, RowRef::field_value),
            Self::Many(rows) => rows
                .iter()
                .map(RowRef::field_value)
                .collect::<Vec<_>>()
                .into(),
        }
    }
}

impl<T> RowRef<T> {
    pub(super) fn from_cell(value: RowCell<T>, gate: MemoryGate) -> Self {
        Self {
            storage: RowStorage::Record(Arc::new(Mutex::new(value))),
            gate,
        }
    }

    pub(super) fn from_object(object: FieldObject, gate: MemoryGate) -> Self {
        Self {
            storage: RowStorage::Native(object),
            gate,
        }
    }

    pub(super) fn same_row(&self, other: &Self) -> bool {
        match (&self.storage, &other.storage) {
            (RowStorage::Record(left), RowStorage::Record(right)) => Arc::ptr_eq(left, right),
            (RowStorage::Native(left), RowStorage::Native(right)) => left.same_object(right),
            (RowStorage::Record(row), RowStorage::Native(object))
            | (RowStorage::Native(object), RowStorage::Record(row)) => {
                object.identity()
                    == crate::field_value::ObjectIdentity::Live(Arc::as_ptr(row) as usize)
            }
        }
    }
}

impl<T: ObjectRow> RowRef<T> {
    fn replace_cell(&self, value: RowCell<T>) -> AuthResult<()> {
        let _operation = self.gate.lock();
        if let RowStorage::Record(target) = &self.storage {
            let mut row = lock(target)?;
            if matches!(row.value, RowValue::Typed(_)) {
                let previous = std::mem::replace(&mut *row, value);
                drop(row);
                drop(previous);
                return Ok(());
            }
        }
        self.discard_user_state()?;
        let fields = match value.value {
            RowValue::Typed(value) => value.field_values()?,
            RowValue::Properties(object) => FieldValue::Object(object).enumerable_fields()?,
        };
        let receiver = self.field_value();
        for name in self.own_keys()? {
            if !fields.contains_key(&name) {
                receiver.delete_model_property(&name)?;
            }
        }
        self.apply_patch(fields)?;
        if let RowStorage::Record(target) = &self.storage {
            let previous = std::mem::replace(&mut lock(target)?.user_state, value.user_state);
            drop(previous);
        }
        Ok(())
    }

    pub(super) fn replace(&self, value: T) -> AuthResult<()> {
        self.replace_cell(RowCell::new(value))
    }

    pub(super) fn snapshot(&self) -> AuthResult<T> {
        let _operation = self.gate.lock();
        match self.current_value()? {
            RowValue::Typed(value) => Ok(value),
            RowValue::Properties(_) => T::from_field_values(self.shallow_fields()?),
        }
    }

    pub(super) fn from_value(value: FieldValue, gate: MemoryGate) -> AuthResult<Self> {
        match value {
            FieldValue::Object(object) => Ok(match object.source::<Self>() {
                Some(row) => row.clone(),
                None => Self::from_object(object, gate),
            }),
            _ => Err(AuthError::internal("Memory table row must be an object")),
        }
    }
}

#[cfg(test)]
impl RowRef<FieldMap> {
    pub(super) fn replace_user_state(&self, user: crate::UserView) -> AuthResult<()> {
        self.replace_cell(RowCell::from_user_state(user))
    }

    pub(super) fn user_state_snapshot(&self) -> AuthResult<crate::UserView> {
        let RowStorage::Record(source) = &self.storage else {
            return crate::UserView::from_field_values(self.shallow_fields()?);
        };
        let cell = {
            let _operation = self.gate.lock();
            lock(source)?.clone()
        };
        let fields = match cell.value {
            RowValue::Typed(fields) => fields,
            RowValue::Properties(_) => self.shallow_fields()?,
        };
        match cell.user_state {
            Some(state) => state.into_user(fields),
            None => crate::UserView::from_field_values(fields),
        }
    }
}

fn lock<T>(row: &Mutex<T>) -> AuthResult<MutexGuard<'_, T>> {
    row.lock()
        .map_err(|_| AuthError::internal("Ephemeral row lock poisoned"))
}
pub(super) struct TransactionId(pub(super) FieldValue);

impl PartialEq for TransactionId {
    fn eq(&self, other: &Self) -> bool {
        self.0.same_value_zero(&other.0)
    }
}

impl Eq for TransactionId {}

impl Hash for TransactionId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match &self.0 {
            FieldValue::Undefined => 0_u8.hash(state),
            FieldValue::Null => 1_u8.hash(state),
            FieldValue::Bool(value) => (2_u8, value).hash(state),
            FieldValue::Number(value) => {
                let bits = if value.is_nan() {
                    f64::NAN.to_bits()
                } else if *value == 0.0 {
                    0
                } else {
                    value.to_bits()
                };
                (3_u8, bits).hash(state);
            }
            FieldValue::String(value) => {
                (4_u8, value.encode_utf16().collect::<Vec<_>>()).hash(state);
            }
            FieldValue::Utf16String(value) => (4_u8, value.as_utf16()).hash(state),
            FieldValue::Date(value) => (5_u8, value.milliseconds().to_bits()).hash(state),
            FieldValue::Array(value) => (6_u8, value.identity()).hash(state),
            FieldValue::Object(value) => (7_u8, value.identity()).hash(state),
            FieldValue::Function(value) => (8_u8, value.identity()).hash(state),
        }
    }
}
#[cfg(test)]
mod object_tests;

#[cfg(test)]
mod descriptor_tests;

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]
mod tests {
    use super::*;
    use crate::store::ephemeral::table::TableRef;
    use crate::{SchemaValue, StructuredCloneContext};
    use std::collections::HashSet;

    #[derive(Clone, Debug, PartialEq)]
    struct Record {
        id: SchemaValue<String>,
        label: String,
    }
    impl AuthRecordFields for Record {
        fn field_values(&self) -> AuthResult<FieldMap> {
            Ok([
                ("id".into(), self.id.field_value()),
                ("label".into(), self.label.clone().into()),
            ]
            .into())
        }
    }
    impl FromFieldMap for Record {
        fn from_field_values(mut fields: FieldMap) -> AuthResult<Self> {
            Ok(Self {
                id: SchemaValue::from_field(fields.remove("id").unwrap_or_default()),
                label: fields.remove("label").unwrap_or_default().decode()?,
            })
        }
    }

    impl ObjectRow for Record {
        fn property(&self, name: &str) -> AuthResult<Option<FieldValue>> {
            Ok(self.field_values()?.get(name).cloned())
        }
    }

    #[test]
    #[expect(
        clippy::mutable_key_type,
        reason = "TransactionId hashes immutable scalars and stable object handles; this test verifies native HashSet membership."
    )]
    fn transaction_keys_preserve_native_types_and_object_identity() {
        let date = FieldValue::Date(crate::FieldDate::from_milliseconds(1.0));
        let array = FieldValue::from(vec![FieldValue::Number(1.0)]);
        let object = FieldValue::from(FieldMap::new());
        let keys: HashSet<_> = [
            FieldValue::Undefined,
            FieldValue::Null,
            FieldValue::Bool(false),
            FieldValue::Bool(true),
            FieldValue::Number(0.0),
            FieldValue::Number(1.0),
            FieldValue::Number(f64::NAN),
            FieldValue::String("1".into()),
            FieldValue::String("😀".into()),
            FieldValue::Utf16String(crate::Utf16String::from_units(vec![0xd800])),
            date.clone(),
            array.clone(),
            object.clone(),
        ]
        .into_iter()
        .map(TransactionId)
        .collect();
        assert_eq!(keys.len(), 13);
        for equivalent in [
            FieldValue::Number(-0.0),
            FieldValue::Number(f64::from_bits(0x7ff8_0000_0000_0001)),
            FieldValue::Utf16String("😀".into()),
            date,
            array,
            object,
        ] {
            assert!(keys.contains(&TransactionId(equivalent)));
        }
        for distinct in [
            FieldValue::Number(2.0),
            FieldValue::String("0".into()),
            FieldValue::Date(crate::FieldDate::from_milliseconds(1.0)),
            FieldValue::from(vec![FieldValue::Number(1.0)]),
            FieldValue::from(FieldMap::new()),
        ] {
            assert!(!keys.contains(&TransactionId(distinct)));
        }
    }

    #[test]
    fn transaction_numeric_ids_merge_updates_deletes_and_creates_independently() -> AuthResult<()> {
        let mut live = TableRef::new(Arc::default());
        for (id, label) in [
            (FieldValue::Number(1.0), "Alice"),
            (FieldValue::Number(2.0), "Bob"),
            (FieldValue::String("1".into()), "String ID"),
            (FieldValue::Number(3.0), "Deleted"),
        ] {
            let _ = live.push(Record {
                id: SchemaValue::from_field(id),
                label: label.into(),
            })?;
        }
        let base = live.deep_clone(&mut StructuredCloneContext::new())?;
        let mut working = base.deep_clone(&mut StructuredCloneContext::new())?;
        for source in working.snapshot_refs()? {
            let mut row = source.snapshot()?;
            if row.label == "Alice" {
                row.label = "Updated Alice".into();
                source.replace(row)?;
            }
        }
        let deleted = working.select_refs(|row| Ok(row.snapshot()?.label == "Deleted"))?;
        working = working.without_refs(&deleted)?;
        let _ = working.push(Record {
            id: SchemaValue::from_field(FieldValue::Number(4.0)),
            label: "Created".into(),
        })?;
        let bob = live
            .select_refs(|row| Ok(row.snapshot()?.label == "Bob"))?
            .into_iter()
            .next()
            .ok_or_else(|| AuthError::internal("missing Bob fixture"))?;
        let mut updated = bob.snapshot()?;
        updated.label = "Concurrent Bob".into();
        bob.replace(updated)?;
        assert_eq!(
            live.snapshot()?.first().map(|row| row.label.clone()),
            Some("Alice".into())
        );
        assert_eq!(live.len()?, 4);
        live = live.reconcile(&base, &working)?;
        assert_eq!(
            live.snapshot()?
                .iter()
                .map(|row| row.label.as_str())
                .collect::<Vec<_>>(),
            ["Updated Alice", "Concurrent Bob", "String ID", "Created"]
        );
        assert!(live.contains_ref(&bob)?);
        for expected in working.select_refs(|row| {
            Ok(matches!(
                row.snapshot()?.label.as_str(),
                "Updated Alice" | "Created"
            ))
        })? {
            assert!(live.contains_ref(&expected)?);
        }
        Ok(())
    }

    #[test]
    fn transaction_native_duplicate_ids_keep_the_last_row_limitation() -> AuthResult<()> {
        for (first, last) in [
            (Some(FieldValue::Number(1.0)), Some(FieldValue::Number(1.0))),
            (
                Some(FieldValue::Number(f64::NAN)),
                Some(FieldValue::Number(-f64::NAN)),
            ),
            (
                Some(FieldValue::Number(-0.0)),
                Some(FieldValue::Number(0.0)),
            ),
            (None, Some(FieldValue::Undefined)),
        ] {
            let mut live = TableRef::new(Arc::default());
            for (id, label) in [(first, "First"), (last, "Last")] {
                let mut row = FieldMap::from([("label".into(), FieldValue::from(label))]);
                if let Some(id) = id {
                    let _ = row.insert("id".into(), id);
                }
                let _ = live.push(row)?;
            }
            let base = live.deep_clone(&mut StructuredCloneContext::new())?;
            let working = base.deep_clone(&mut StructuredCloneContext::new())?;
            for row in working.snapshot_refs()? {
                if row.field("label")?.as_ref().and_then(FieldValue::as_str) == Some("Last") {
                    row.set_field("label".into(), "Updated".into())?;
                }
            }
            live = live.reconcile(&base, &working)?;
            assert_eq!(live.len()?, 2);
            for row in live.snapshot()? {
                assert_eq!(
                    row.get("label").and_then(FieldValue::as_str),
                    Some("Updated")
                );
            }
        }
        Ok(())
    }

    #[test]
    fn transaction_public_id_merge_matches_pinned_missing_duplicate_and_changed_ids()
    -> AuthResult<()> {
        for kind in ["undefined", "duplicate", "changed"] {
            let mut live = TableRef::new(Arc::default());
            for (index, label) in ["Alice", "Bob"].into_iter().enumerate() {
                let id = match kind {
                    "undefined" => SchemaValue::Undefined,
                    "duplicate" => SchemaValue::Typed("duplicate".into()),
                    _ => SchemaValue::Typed((index + 1).to_string()),
                };
                let _ = live.push(Record {
                    id,
                    label: label.into(),
                })?;
            }
            let base = live.deep_clone(&mut StructuredCloneContext::new())?;
            let working = base.deep_clone(&mut StructuredCloneContext::new())?;
            {
                let first = working
                    .select_refs(|row| Ok(row.snapshot()?.label == "Alice"))?
                    .into_iter()
                    .next()
                    .ok_or_else(|| AuthError::internal("missing Alice fixture"))?;
                let mut updated = first.snapshot()?;
                if kind == "changed" {
                    updated.id = SchemaValue::Typed("changed-public-id".into());
                }
                updated.label = "Updated Alice".into();
                first.replace(updated)?;
            }
            live = live.reconcile(&base, &working)?;
            let rows = live.snapshot()?;
            let expected = if kind == "changed" {
                ["Bob", "Updated Alice"]
            } else {
                ["Alice", "Bob"]
            };
            assert_eq!(
                rows.iter()
                    .map(|row| row.label.as_str())
                    .collect::<Vec<_>>(),
                expected
            );
            assert_eq!(
                working.snapshot()?.first().map(|row| row.label.clone()),
                Some("Updated Alice".to_owned())
            );
        }
        Ok(())
    }
}
