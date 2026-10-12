//! Captured arrays retain their identity when an operation replaces an active table.

use super::operation::MemoryGate;
use super::rows::{ObjectRow, RowCell, RowRef, TransactionId};
use crate::field_value::{ArrayIdentity, FieldPropertyDefinition, FieldPropertyDescriptor};
use crate::{AuthError, AuthResult, FieldArray, FieldValue, StructuredCloneContext};
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::sync::Arc;

pub(super) struct TableRef<T> {
    rows: FieldArray,
    gate: MemoryGate,
    record: PhantomData<fn() -> T>,
}

pub(super) struct ReconcilePlan<T> {
    changed: Vec<(RowRef<T>, Option<RowRef<T>>)>,
    appended: Vec<RowRef<T>>,
}

impl<T: ObjectRow> ReconcilePlan<T> {
    pub(super) fn is_empty(&self) -> bool {
        self.changed.is_empty() && self.appended.is_empty()
    }

    pub(super) fn apply(&self, latest: &TableRef<T>) -> AuthResult<TableRef<T>> {
        let _operation = latest.gate.lock();
        if self.is_empty() {
            return Ok(latest.clone());
        }
        let mut rows = Vec::new();
        for row in latest.snapshot_refs()? {
            match self
                .changed
                .iter()
                .find(|(original, _)| row.same_row(original))
            {
                Some((_, Some(replacement))) => rows.push(replacement.clone()),
                Some((_, None)) => {}
                None => rows.push(row),
            }
        }
        rows.extend(self.appended.iter().cloned());
        Ok(TableRef::from_refs(latest.gate.clone(), rows))
    }
}

impl<T> Clone for TableRef<T> {
    fn clone(&self) -> Self {
        Self {
            rows: self.rows.clone(),
            gate: self.gate.clone(),
            record: PhantomData,
        }
    }
}

impl<T> TableRef<T> {
    pub(super) fn new(gate: MemoryGate) -> Self {
        Self::from_array(gate, FieldArray::new())
    }

    fn from_array(gate: MemoryGate, rows: FieldArray) -> Self {
        Self {
            rows,
            gate,
            record: PhantomData,
        }
    }

    pub(super) fn len(&self) -> AuthResult<usize> {
        let _operation = self.gate.lock();
        self.rows.len()
    }
}

impl<T: ObjectRow> TableRef<T> {
    pub(super) fn from_refs(gate: MemoryGate, rows: Vec<RowRef<T>>) -> Self {
        Self::from_array(gate, rows.iter().map(RowRef::field_value).collect())
    }

    fn value_at(&self, index: usize) -> AuthResult<Option<FieldValue>> {
        let _operation = self.gate.lock();
        self.rows
            .get_with_receiver(index, &FieldValue::Array(self.array()))
    }

    pub(super) fn row_at(&self, index: usize) -> AuthResult<Option<RowRef<T>>> {
        let _operation = self.gate.lock();
        self.value_at(index)?
            .map(|value| RowRef::from_value(value, self.gate.clone()))
            .transpose()
    }

    pub(super) fn snapshot_refs(&self) -> AuthResult<Vec<RowRef<T>>> {
        let _operation = self.gate.lock();
        let length = self.len()?;
        let mut rows = Vec::new();
        for index in 0..length {
            rows.extend(self.row_at(index)?);
        }
        Ok(rows)
    }

    pub(super) fn shallow_copy(&self) -> AuthResult<Self> {
        let _operation = self.gate.lock();
        Ok(Self::from_array(self.gate.clone(), self.array().map(Ok)?))
    }

    pub(super) fn push(&self, value: T) -> AuthResult<RowRef<T>> {
        self.push_cell(RowCell::new(value))
    }

    fn push_cell(&self, value: RowCell<T>) -> AuthResult<RowRef<T>> {
        let _operation = self.gate.lock();
        let row = RowRef::from_cell(value, self.gate.clone());
        self.push_ref(&row)?;
        Ok(row)
    }

    fn push_ref(&self, row: &RowRef<T>) -> AuthResult<()> {
        let length = self.len()?;
        let receiver = FieldValue::Array(self.array());
        receiver.set_model_property(&length.to_string(), row.field_value())?;
        receiver.set_model_property("length", (length + 1).into())
    }

    pub(super) fn push_object(&self, object: crate::FieldObject) -> AuthResult<RowRef<T>> {
        let _operation = self.gate.lock();
        let row = RowRef::from_object(object, self.gate.clone());
        self.push_ref(&row)?;
        Ok(row)
    }

    pub(super) fn contains_ref(&self, source: &RowRef<T>) -> AuthResult<bool> {
        let _operation = self.gate.lock();
        Ok(self.snapshot_refs()?.iter().any(|row| row.same_row(source)))
    }

    pub(super) fn select_refs(
        &self,
        mut predicate: impl FnMut(&RowRef<T>) -> AuthResult<bool>,
    ) -> AuthResult<Vec<RowRef<T>>> {
        let _operation = self.gate.lock();
        let length = self.len()?;
        let mut selected = Vec::new();
        for index in 0..length {
            if let Some(row) = self.row_at(index)?
                && predicate(&row)?
            {
                selected.push(row);
            }
        }
        Ok(selected)
    }

    pub(super) fn without_refs(&self, selected: &[RowRef<T>]) -> AuthResult<Self> {
        let _operation = self.gate.lock();
        let rows =
            self.select_refs(|row| Ok(!selected.iter().any(|selected| row.same_row(selected))))?;
        Ok(Self::from_refs(self.gate.clone(), rows))
    }
}

#[cfg(test)]
impl TableRef<crate::FieldMap> {
    pub(super) fn push_user_state(
        &self,
        user: crate::UserView,
    ) -> AuthResult<RowRef<crate::FieldMap>> {
        self.push_cell(RowCell::from_user_state(user))
    }
}

impl<T: ObjectRow> TableRef<T> {
    pub(super) fn snapshot(&self) -> AuthResult<Vec<T>> {
        let _operation = self.gate.lock();
        self.snapshot_refs()?.iter().map(RowRef::snapshot).collect()
    }
}

impl<T: ObjectRow> TableRef<T> {
    pub(super) fn deep_clone(&self, context: &mut StructuredCloneContext) -> AuthResult<Self> {
        self.deep_clone_with(context, |_, _, _| {})
    }

    pub(super) fn deep_clone_with(
        &self,
        context: &mut StructuredCloneContext,
        mut cloned_row: impl FnMut(RowRef<T>, RowRef<T>, T),
    ) -> AuthResult<Self> {
        let _operation = self.gate.lock();
        let (array, original) = context.clone_array(&self.array())?;
        let target = array
            .source::<Self>()
            .cloned()
            .ok_or_else(|| AuthError::internal("Structured clone lost its native table type"))?;
        for value in original {
            let source = RowRef::from_value(value, self.gate.clone())?;
            let (row, before) = source.structured_clone(context)?;
            cloned_row(source, row, before);
        }
        Ok(target)
    }
}

impl<T: ObjectRow> TableRef<T> {
    pub(super) fn array(&self) -> FieldArray {
        FieldArray::from_source(Arc::new(self.clone()))
    }
}

impl<T: ObjectRow> crate::field_value::FieldArraySource for TableRef<T> {
    fn properties(&self) -> &crate::FieldObject {
        self.rows.properties()
    }

    fn len(&self) -> AuthResult<usize> {
        self.len()
    }

    fn own_indices(&self) -> AuthResult<Vec<usize>> {
        let _operation = self.gate.lock();
        self.rows.own_indices()
    }

    fn get(&self, index: usize, receiver: &FieldValue) -> AuthResult<Option<FieldValue>> {
        let _operation = self.gate.lock();
        self.rows.get_with_receiver(index, receiver)
    }

    fn own_property_descriptor(&self, index: usize) -> AuthResult<Option<FieldPropertyDescriptor>> {
        let _operation = self.gate.lock();
        self.rows.own_property_descriptor(index)
    }

    fn length_descriptor(&self) -> AuthResult<FieldPropertyDescriptor> {
        let _operation = self.gate.lock();
        self.rows.length_descriptor()
    }

    fn set(&self, index: usize, value: FieldValue, receiver: &FieldValue) -> AuthResult<bool> {
        let _operation = self.gate.lock();
        self.rows.assign_index(index, value, receiver)
    }

    fn define_index(&self, index: usize, definition: FieldPropertyDefinition) -> AuthResult<bool> {
        let _operation = self.gate.lock();
        self.rows.define_index(index, definition)
    }

    fn define_length(&self, definition: FieldPropertyDefinition) -> AuthResult<bool> {
        let _operation = self.gate.lock();
        self.rows.define_length(definition)
    }

    fn delete(&self, index: usize) -> AuthResult<bool> {
        let _operation = self.gate.lock();
        self.rows.delete_index(index)
    }

    fn identity(&self) -> usize {
        match self.rows.identity() {
            ArrayIdentity::Owned(identity) | ArrayIdentity::Live(identity) => identity,
        }
    }

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }

    fn clone_seed(&self) -> AuthResult<Option<crate::field_value::ArrayCloneSeed>> {
        let seed = self.rows.clone_seed()?;
        let target = Self::from_array(self.gate.clone(), seed.array);
        Ok(Some(crate::field_value::ArrayCloneSeed {
            array: target.array(),
            prepare: seed.prepare,
        }))
    }
}

impl<T: ObjectRow> TableRef<T> {
    pub(super) fn reconcile(&self, base: &Self, working: &Self) -> AuthResult<Self> {
        self.reconcile_with_plan(base, working)
            .map(|(table, _)| table)
    }

    #[expect(
        clippy::mutable_key_type,
        reason = "TransactionId hashes and compares mutable objects by stable identity, never by their mutable fields."
    )]
    pub(super) fn reconcile_with_plan(
        &self,
        base: &Self,
        working: &Self,
    ) -> AuthResult<(Self, ReconcilePlan<T>)> {
        let _operation = self.gate.lock();
        let index = |table: &Self| -> AuthResult<HashMap<TransactionId, RowRef<T>>> {
            let mut indexed = HashMap::new();
            let mut position = 0;
            while position < table.len()? {
                if let Some(row) = table.row_at(position)? {
                    let id = TransactionId(row.field("id")?.unwrap_or_default());
                    let _ = indexed.insert(id, row);
                }
                position += 1;
            }
            Ok(indexed)
        };
        let base_by_id = index(base)?;
        let working_by_id = index(working)?;
        let mut placed = HashSet::new();
        let mut merged = Vec::new();
        let mut plan = ReconcilePlan {
            changed: Vec::new(),
            appended: Vec::new(),
        };
        let mut position = 0;
        while position < self.len()? {
            if let Some(live) = self.row_at(position)? {
                let id = TransactionId(live.field("id")?.unwrap_or_default());
                let original = base_by_id.get(&id);
                let changed = working_by_id.get(&id);
                if original.is_some() && changed.is_none() {
                    plan.changed.push((live, None));
                    position += 1;
                    continue;
                }
                let replacement = match (original, changed) {
                    (None, Some(changed)) => {
                        plan.changed.push((live, Some(changed.clone())));
                        changed.clone()
                    }
                    (Some(original), Some(changed)) => {
                        let before = original.field_value().stringify()?;
                        let after = changed.field_value().stringify()?;
                        if before != after {
                            plan.changed.push((live, Some(changed.clone())));
                            changed.clone()
                        } else {
                            live
                        }
                    }
                    (_, None) => live,
                };
                merged.push(replacement);
                let _ = placed.insert(id);
            }
            position += 1;
        }
        let mut position = 0;
        while position < working.len()? {
            if let Some(row) = working.row_at(position)? {
                let id = TransactionId(row.field("id")?.unwrap_or_default());
                if !base_by_id.contains_key(&id) && !placed.contains(&id) {
                    plan.appended.push(row.clone());
                    merged.push(row);
                }
            }
            position += 1;
        }
        Ok((Self::from_refs(self.gate.clone(), merged), plan))
    }
}

#[cfg(test)]
#[path = "table_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "table_property_tests.rs"]
mod property_tests;
