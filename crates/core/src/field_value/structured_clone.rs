//! Traverse getters, prepare graph writes, and restore native records before committing clone identities.

#![expect(
    clippy::indexing_slicing,
    reason = "Graph indices originate from the node table; source, node, and value tables retain identical lengths."
)]

use super::{
    ArrayIdentity, FieldArray, FieldDate, FieldMap, FieldObject, FieldValue, ObjectIdentity,
};
use crate::{AuthError, AuthResult};
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

#[expect(
    clippy::expect_used,
    reason = "Clone writes only swap private target state; public accessors release their guards before callbacks run."
)]
pub(crate) fn prepare_clone<T: Send + Sync + 'static>(
    target: Arc<std::sync::Mutex<T>>,
    mut value: T,
) -> CloneWrite {
    CloneWrite::new(move || {
        let mut target = target
            .lock()
            .expect("A private clone target cannot be poisoned");
        std::mem::swap(&mut *target, &mut value);
    })
}

/// Swap prepared state with a private target without running callbacks or dropping either state under its lock.
pub(crate) struct CloneWrite(Box<dyn FnMut() + Send + Sync>);

impl CloneWrite {
    pub(crate) fn new(swap: impl FnMut() + Send + Sync + 'static) -> Self {
        Self(Box::new(swap))
    }

    fn swap(&mut self) {
        (self.0)();
    }
}

struct StagedWrites<'a> {
    writes: &'a mut [CloneWrite],
    applied: usize,
}

impl<'a> StagedWrites<'a> {
    fn new(writes: &'a mut [CloneWrite]) -> Self {
        let mut staged = Self { writes, applied: 0 };
        for write in staged.writes.iter_mut() {
            write.swap();
            staged.applied += 1;
        }
        staged
    }
}

impl Drop for StagedWrites<'_> {
    fn drop(&mut self) {
        for write in self.writes.iter_mut().take(self.applied).rev() {
            write.swap();
        }
    }
}

type Prepare = Box<dyn FnOnce(FieldMap, Vec<FieldValue>, FieldMap) -> AuthResult<CloneWrite>>;
type PrepareArray = Box<dyn FnOnce(usize, Vec<(usize, FieldValue)>) -> AuthResult<CloneWrite>>;

pub(crate) struct ArrayCloneSeed {
    pub(crate) array: FieldArray,
    pub(crate) prepare: PrepareArray,
}

type NativeRecord = Arc<dyn Any + Send + Sync>;

/// A fresh object retains its native record shape until every graph conversion succeeds.
#[doc(hidden)]
pub struct ObjectCloneSeed {
    pub(crate) object: FieldObject,
    pub(crate) state: Vec<FieldValue>,
    pub(crate) original_record: Option<NativeRecord>,
    pub(crate) prepare: Prepare,
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
enum Identity {
    Date(usize),
    Array(ArrayIdentity),
    Object(ObjectIdentity),
}

struct CloneEntry {
    _source: FieldValue,
    value: FieldValue,
    original_record: Option<NativeRecord>,
    original_fields: Option<FieldMap>,
    original_elements: Option<Vec<FieldValue>>,
}

type Copies = Vec<(Identity, CloneEntry)>;
type PreparedGraph = (Vec<FieldValue>, Copies, Vec<CloneWrite>);

/// Copy one value graph with fresh object identities and preserved aliases.
/// Reuse one context across all records in a transaction snapshot.
/// Create a new context for each independent snapshot.
#[derive(Default)]
pub struct StructuredCloneContext {
    // Source handles prevent pointer reuse between calls through the same context.
    copies: HashMap<Identity, CloneEntry>,
    pending: Option<Vec<CloneWrite>>,
}

impl StructuredCloneContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn deferred() -> Self {
        Self {
            copies: HashMap::new(),
            pending: Some(Vec::new()),
        }
    }

    pub(crate) fn publish(mut self) {
        // Prepared writes contain no getters or fallible conversions, so publication cannot leave half-filled cycles.
        if let Some(pending) = self.pending.take() {
            for mut write in pending {
                write.swap();
            }
        }
    }

    fn complete(&mut self, copies: Copies, publish: Vec<CloneWrite>) {
        if let Some(pending) = &mut self.pending {
            pending.extend(publish);
        } else {
            for mut write in publish {
                write.swap();
            }
        }
        self.copies.extend(copies);
    }

    fn restore<T>(
        &mut self,
        (values, copies, mut publish): PreparedGraph,
        restore: impl FnOnce(&[FieldValue]) -> AuthResult<T>,
    ) -> AuthResult<T> {
        let value = {
            // Deferred aliases must also be readable during restoration, then return to their unpublished state.
            let _pending = self
                .pending
                .as_mut()
                .map(|writes| StagedWrites::new(writes));
            let _staged = StagedWrites::new(&mut publish);
            restore(&values)
        }?;
        self.complete(copies, publish);
        Ok(value)
    }

    fn clone_value_with<T>(
        &mut self,
        value: &FieldValue,
        restore: impl FnOnce(FieldValue) -> AuthResult<T>,
    ) -> AuthResult<T> {
        let mut graph = Graph::new(self);
        let edge = graph.visit(value)?;
        let prepared = graph.materialize()?;
        self.restore(prepared, |values| restore(edge.resolve(values)))
    }

    /// Copy a value while preserving aliases already copied by this context.
    pub fn clone_value(&mut self, value: &FieldValue) -> AuthResult<FieldValue> {
        let mut graph = Graph::new(self);
        let edge = graph.visit(value)?;
        let (values, copies, publish) = graph.materialize()?;
        let value = edge.resolve(&values);
        self.complete(copies, publish);
        Ok(value)
    }

    /// Copy record fields using the same alias map as other records in this context.
    pub fn clone_map(&mut self, fields: &FieldMap) -> AuthResult<FieldMap> {
        let (fields, _, (_, copies, publish)) = self.prepare_fields(fields, &[])?;
        self.complete(copies, publish);
        Ok(fields)
    }

    /// Clone enumerable fields in property order, then hidden state through the same object graph.
    /// Restore the native record while cloned targets are readable. Commit new identities only after restoration succeeds.
    pub fn clone_with<T>(
        &mut self,
        fields: &FieldMap,
        state: &[FieldValue],
        restore: impl FnOnce(FieldMap, Vec<FieldValue>) -> AuthResult<T>,
    ) -> AuthResult<T> {
        let (fields, state, prepared) = self.prepare_fields(fields, state)?;
        self.restore(prepared, |_| restore(fields, state))
    }

    fn prepare_fields(
        &self,
        fields: &FieldMap,
        state: &[FieldValue],
    ) -> AuthResult<(FieldMap, Vec<FieldValue>, PreparedGraph)> {
        let mut ordered = fields.clone();
        ordered.sort_property_order();
        let mut graph = Graph::new(self);
        let edges = ordered
            .iter()
            .map(|(name, value)| Ok((name.clone(), graph.visit(value)?)))
            .collect::<AuthResult<Vec<_>>>()?;
        let state = state
            .iter()
            .map(|value| graph.visit(value))
            .collect::<AuthResult<Vec<_>>>()?;
        let prepared = graph.materialize()?;
        let values = &prepared.0;
        let fields = edges
            .into_iter()
            .map(|(name, edge)| (name, edge.resolve(values)))
            .collect();
        let state = state.iter().map(|edge| edge.resolve(values)).collect();
        Ok((fields, state, prepared))
    }

    /// Clone one native schema field using the same object graph as its containing record.
    pub fn clone_field<T: crate::SchemaField>(&mut self, value: &T) -> AuthResult<T> {
        self.clone_value_with(&value.clone().into_field(), |cloned| {
            value.restore_cloned_field(cloned)
        })
    }

    pub(crate) fn clone_array(
        &mut self,
        array: &FieldArray,
    ) -> AuthResult<(FieldArray, Vec<FieldValue>)> {
        let value = self.clone_value(&FieldValue::Array(array.clone()))?;
        let original = self
            .copies
            .get(&Identity::Array(array.identity()))
            .and_then(|copy| copy.original_elements.clone())
            .ok_or_else(|| {
                AuthError::internal("Structured clone lost its original array elements")
            })?;
        let FieldValue::Array(copied) = value else {
            return Err(AuthError::internal("Structured clone lost its array type"));
        };
        Ok((copied, original))
    }

    pub(crate) fn clone_record<T: Clone + 'static>(
        &mut self,
        value: &FieldValue,
    ) -> AuthResult<(FieldValue, T)> {
        let copied = self.clone_value(value)?;
        let original = value
            .as_object()
            .and_then(|source| self.copies.get(&Identity::Object(source.identity())))
            .and_then(|copy| copy.original_record.as_deref())
            .and_then(|record| record.downcast_ref::<T>())
            .ok_or_else(|| AuthError::internal("Structured clone lost its original native row"))?;
        Ok((copied, original.clone()))
    }

    /// Return the values captured by the clone traversal without evaluating source getters again.
    pub(crate) fn clone_object_fields(
        &mut self,
        object: &FieldObject,
    ) -> AuthResult<(FieldObject, FieldMap)> {
        let copied = self.clone_value(&FieldValue::Object(object.clone()))?;
        let original = self
            .copies
            .get(&Identity::Object(object.identity()))
            .and_then(|copy| copy.original_fields.clone())
            .ok_or_else(|| {
                AuthError::internal("Structured clone lost its original object fields")
            })?;
        let FieldValue::Object(copied) = copied else {
            return Err(AuthError::internal("Structured clone lost its object type"));
        };
        Ok((copied, original))
    }
}

enum Edge {
    Value(FieldValue),
    Node(usize),
}

impl Edge {
    fn resolve(&self, values: &[FieldValue]) -> FieldValue {
        match self {
            Self::Value(value) => value.clone(),
            Self::Node(index) => values[*index].clone(),
        }
    }
}

enum Node {
    Pending,
    Date(FieldDate),
    Array {
        seed: ArrayCloneSeed,
        length: usize,
        entries: Vec<(usize, FieldValue, Edge)>,
        properties: Vec<(String, Edge)>,
    },
    Object {
        seed: ObjectCloneSeed,
        fields: Vec<(String, FieldValue, Edge)>,
        state: Vec<Edge>,
    },
}

struct Graph<'a> {
    context: &'a StructuredCloneContext,
    indices: HashMap<Identity, usize>,
    sources: Vec<(Identity, FieldValue)>,
    nodes: Vec<Node>,
}

impl<'a> Graph<'a> {
    fn new(context: &'a StructuredCloneContext) -> Self {
        Self {
            context,
            indices: HashMap::new(),
            sources: Vec::new(),
            nodes: Vec::new(),
        }
    }

    fn visit(&mut self, value: &FieldValue) -> AuthResult<Edge> {
        let identity = match value {
            FieldValue::Function(_) => return Err(AuthError::DataClone),
            FieldValue::Date(date) => Identity::Date(Arc::as_ptr(&date.0) as usize),
            FieldValue::Array(array) => Identity::Array(array.identity()),
            FieldValue::Object(object) => Identity::Object(object.identity()),
            value => return Ok(Edge::Value(value.clone())),
        };
        if let Some(copy) = self.context.copies.get(&identity) {
            return Ok(Edge::Value(copy.value.clone()));
        }
        if let Some(index) = self.indices.get(&identity) {
            return Ok(Edge::Node(*index));
        }
        let index = self.nodes.len();
        let _ = self.indices.insert(identity, index);
        self.sources.push((identity, value.clone()));
        self.nodes.push(Node::Pending);
        let node = match value {
            FieldValue::Date(date) => Node::Date(FieldDate::from_milliseconds(date.milliseconds())),
            FieldValue::Array(array) => {
                let seed = array.clone_seed()?;
                let length = array.len()?;
                let mut entries = Vec::new();
                // Bun captures length, then reads current own indices regardless of enumerability.
                for index in 0..length {
                    if array.own_property_descriptor(index)?.is_some()
                        && let Some(value) = array.get(index)?
                    {
                        let edge = self.visit(&value)?;
                        entries.push((index, value, edge));
                    }
                }
                let mut properties = Vec::new();
                for name in array.named_property_keys()? {
                    if array
                        .properties()
                        .own_property_descriptor(&name)?
                        .is_some_and(|descriptor| descriptor.enumerable)
                        && let Some(child) = array.properties().get_with_receiver(&name, value)?
                    {
                        properties.push((name, self.visit(&child)?));
                    }
                }
                Node::Array {
                    seed,
                    length,
                    entries,
                    properties,
                }
            }
            FieldValue::Object(object) => {
                let mut seed = object.clone_seed()?;
                let mut fields = Vec::new();
                for name in object.enumerable_keys()? {
                    if object.own_property_descriptor(&name)?.is_some()
                        && let Some(value) = object.get(&name)?
                    {
                        let edge = self.visit(&value)?;
                        fields.push((name, value, edge));
                    }
                }
                let state = std::mem::take(&mut seed.state)
                    .iter()
                    .map(|value| self.visit(value))
                    .collect::<AuthResult<_>>()?;
                Node::Object {
                    seed,
                    fields,
                    state,
                }
            }
            _ => {
                return Err(AuthError::internal(
                    "Structured clone graph contains a non-object node",
                ));
            }
        };
        self.nodes[index] = node;
        Ok(Edge::Node(index))
    }

    fn materialize(self) -> AuthResult<PreparedGraph> {
        let values = self
            .nodes
            .iter()
            .map(|node| match node {
                Node::Date(date) => Some(date.clone().into()),
                Node::Object { seed, .. } => Some(FieldValue::Object(seed.object.clone())),
                Node::Array { seed, .. } => Some(FieldValue::Array(seed.array.clone())),
                Node::Pending => None,
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| {
                AuthError::internal("Structured clone graph contains an unfinished node")
            })?;
        let originals = self
            .nodes
            .iter()
            .map(|node| match node {
                Node::Object { seed, fields, .. } => (
                    seed.original_record.clone(),
                    Some(
                        fields
                            .iter()
                            .map(|(name, value, _)| (name.clone(), value.clone()))
                            .collect(),
                    ),
                    None,
                ),
                Node::Array { entries, .. } => (
                    None,
                    None,
                    Some(entries.iter().map(|(_, value, _)| value.clone()).collect()),
                ),
                _ => (None, None, None),
            })
            .collect::<Vec<_>>();
        let mut publish = Vec::new();
        for node in self.nodes {
            match node {
                Node::Object {
                    seed,
                    fields,
                    state,
                } => {
                    let original_fields = fields
                        .iter()
                        .map(|(name, value, _)| (name.clone(), value.clone()))
                        .collect();
                    let fields = fields
                        .into_iter()
                        .map(|(name, _, edge)| (name, edge.resolve(&values)))
                        .collect();
                    let state = state.iter().map(|edge| edge.resolve(&values)).collect();
                    publish.push((seed.prepare)(fields, state, original_fields)?);
                }
                Node::Array {
                    seed,
                    length,
                    entries,
                    properties,
                } => {
                    let entries = entries
                        .into_iter()
                        .map(|(index, _, edge)| (index, edge.resolve(&values)))
                        .collect();
                    let properties = properties
                        .into_iter()
                        .map(|(name, edge)| (name, edge.resolve(&values)))
                        .collect();
                    publish.push(seed.array.properties().prepare_fields(properties)?);
                    publish.push((seed.prepare)(length, entries)?);
                }
                _ => {}
            }
        }
        let copies = self
            .sources
            .into_iter()
            .zip(values.iter().cloned())
            .zip(originals)
            .map(
                |(
                    ((identity, source), value),
                    (original_record, original_fields, original_elements),
                )| {
                    (
                        identity,
                        CloneEntry {
                            _source: source,
                            value,
                            original_record,
                            original_fields,
                            original_elements,
                        },
                    )
                },
            )
            .collect();
        Ok((values, copies, publish))
    }
}

#[cfg(test)]
#[path = "structured_clone_tests.rs"]
mod tests;
