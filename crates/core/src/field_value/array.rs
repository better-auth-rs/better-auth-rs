use super::{
    FieldMap, FieldObject, FieldProperty, FieldPropertyDefinition, FieldPropertyDescriptor,
    FieldValue,
    structured_clone::{ArrayCloneSeed, CloneWrite},
};
use crate::{AuthError, AuthResult};
use parking_lot::Mutex;
use std::{
    any::Any,
    cell::RefCell,
    collections::{BTreeMap, HashSet},
    fmt,
    sync::Arc,
};

mod methods;
mod properties;

/// A stable array handle. Live arrays read each index from their current source.
/// Use `snapshot` only when an independent list of shallow values is required.
/// `PartialEq` compares owned arrays structurally and live arrays by identity.
/// Elements retain strong handles. Cycles retain their memory; this handle has no tracing garbage collection.
/// Live arrays remain dynamic during infallible schema decoding so fallible getters retain their original errors.
#[derive(Clone)]
pub struct FieldArray {
    storage: ArrayStorage,
    properties: FieldObject,
}

#[derive(Clone)]
enum ArrayStorage {
    // Native restoration can inspect a prepared clone before success commits the array or failure resets the array.
    Owned(Arc<Mutex<Option<ArrayValues>>>),
    Live(Arc<dyn FieldArraySource>),
}

#[derive(Clone)]
struct ArrayValues {
    length: usize,
    entries: BTreeMap<usize, FieldPropertyDescriptor>,
    length_writable: bool,
}

pub(crate) trait FieldArraySource: Send + Sync {
    fn len(&self) -> AuthResult<usize>;
    fn own_indices(&self) -> AuthResult<Vec<usize>>;
    fn get(&self, index: usize, receiver: &FieldValue) -> AuthResult<Option<FieldValue>>;
    fn identity(&self) -> usize;
    fn properties(&self) -> &FieldObject;
    fn own_property_descriptor(&self, index: usize) -> AuthResult<Option<FieldPropertyDescriptor>>;
    fn length_descriptor(&self) -> AuthResult<FieldPropertyDescriptor>;
    fn set(&self, index: usize, value: FieldValue, receiver: &FieldValue) -> AuthResult<bool>;
    fn define_index(&self, index: usize, definition: FieldPropertyDefinition) -> AuthResult<bool>;
    fn define_length(&self, definition: FieldPropertyDefinition) -> AuthResult<bool>;
    fn delete(&self, index: usize) -> AuthResult<bool>;
    fn clone_seed(&self) -> AuthResult<Option<ArrayCloneSeed>> {
        Ok(None)
    }
    fn as_any(&self) -> Option<&dyn Any> {
        None
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum ArrayIdentity {
    Owned(usize),
    Live(usize),
}

impl FieldArray {
    /// Create an empty array with a distinct identity.
    pub fn new() -> Self {
        Vec::new().into()
    }

    /// Create a sparse array with the given length and no own indexed properties.
    pub fn with_length(length: u32) -> Self {
        Self::with_length_and_properties(length, FieldMap::new().into())
    }

    /// Create a sparse array while retaining a live source for non-index properties.
    pub fn with_length_and_properties(length: u32, properties: FieldObject) -> Self {
        Self {
            storage: ArrayStorage::Owned(Arc::new(Mutex::new(Some(ArrayValues {
                length: length as usize,
                entries: BTreeMap::new(),
                length_writable: true,
            })))),
            properties,
        }
    }

    /// Create a distinct array whose named property source owns accessors and descriptors.
    /// Numeric indices and length remain part of the array's indexed storage.
    /// Enumeration rejects those reserved names in the property source without reading their getters.
    pub fn from_values_with_properties(values: Vec<FieldValue>, properties: FieldObject) -> Self {
        Self {
            storage: ArrayStorage::Owned(Arc::new(Mutex::new(Some(ArrayValues {
                length: values.len(),
                entries: values
                    .into_iter()
                    .enumerate()
                    .map(|(index, value)| (index, FieldPropertyDescriptor::data(value)))
                    .collect(),
                length_writable: true,
            })))),
            properties,
        }
    }

    /// Borrow non-index properties. Array indices and length use indexed operations.
    pub(crate) fn properties(&self) -> &FieldObject {
        &self.properties
    }

    pub(crate) fn named_property_keys(&self) -> AuthResult<Vec<String>> {
        let names = self.properties.own_keys()?;
        for name in &names {
            if name == "length" || crate::utils::json::array_index(name).is_some() {
                return Err(AuthError::type_error(format!(
                    "Array named property source contains reserved property '{name}'"
                )));
            }
        }
        Ok(names)
    }

    pub(crate) fn from_source(source: Arc<dyn FieldArraySource>) -> Self {
        Self {
            properties: source.properties().clone(),
            storage: ArrayStorage::Live(source),
        }
    }

    /// Read the current array length, including missing indices.
    pub fn len(&self) -> AuthResult<usize> {
        match &self.storage {
            ArrayStorage::Owned(values) => {
                Ok(values.lock().as_ref().map_or(0, |values| values.length))
            }
            ArrayStorage::Live(source) => source.len(),
        }
    }

    /// Return whether the current array length is zero.
    pub fn is_empty(&self) -> AuthResult<bool> {
        Ok(self.len()? == 0)
    }

    /// Read one current index. `None` is a hole or an index outside the array.
    pub fn get(&self, index: usize) -> AuthResult<Option<FieldValue>> {
        self.get_with_receiver(index, &FieldValue::Array(self.clone()))
    }

    pub(crate) fn get_with_receiver(
        &self,
        index: usize,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        match &self.storage {
            ArrayStorage::Owned(values) => {
                let descriptor = values
                    .lock()
                    .as_ref()
                    .and_then(|values| values.entries.get(&index))
                    .cloned();
                descriptor
                    .map(|descriptor| descriptor.read(receiver))
                    .transpose()
            }
            ArrayStorage::Live(source) => source.get(index, receiver),
        }
    }

    /// Read the first index without reading later values.
    pub fn first(&self) -> AuthResult<Option<FieldValue>> {
        self.get(0)
    }

    /// Capture present indices in numeric order without evaluating their values.
    pub fn own_indices(&self) -> AuthResult<Vec<usize>> {
        let mut indices = match &self.storage {
            ArrayStorage::Owned(values) => values
                .lock()
                .as_ref()
                .map_or_else(Vec::new, |values| values.entries.keys().copied().collect()),
            ArrayStorage::Live(source) => source.own_indices()?,
        };
        indices.sort_unstable();
        Ok(indices)
    }

    /// Capture the length, then read indices lazily. Missing indices yield `Undefined`.
    pub fn iter(&self) -> AuthResult<FieldArrayIter> {
        Ok(FieldArrayIter {
            array: self.clone(),
            next: 0,
            length: self.len()?,
        })
    }

    /// Copy the current indexed values. Missing indices become `Undefined` in this dense list.
    pub fn snapshot(&self) -> AuthResult<Vec<FieldValue>> {
        self.iter()?.collect()
    }

    /// Test membership with JavaScript SameValueZero, including undefined for missing indices.
    pub fn includes(&self, expected: &FieldValue) -> AuthResult<bool> {
        for value in self.iter()? {
            if value?.same_value_zero(expected) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Test present indices in order, stopping at the first false result or error.
    /// Missing indices are skipped, as in JavaScript `Array.prototype.every`.
    pub fn every(
        &self,
        mut predicate: impl FnMut(&FieldValue) -> AuthResult<bool>,
    ) -> AuthResult<bool> {
        let length = self.len()?;
        for index in 0..length {
            if let Some(value) = self.get(index)?
                && !predicate(&value)?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Map present indices in order, preserving missing indices and the captured length.
    pub fn map(
        &self,
        mut transform: impl FnMut(FieldValue) -> AuthResult<FieldValue>,
    ) -> AuthResult<Self> {
        self.map_with_index(|value, _| transform(value))
    }

    pub(crate) fn map_with_index(
        &self,
        mut transform: impl FnMut(FieldValue, usize) -> AuthResult<FieldValue>,
    ) -> AuthResult<Self> {
        let length = self.len()?;
        let mut entries = BTreeMap::new();
        for index in 0..length {
            if let Some(value) = self.get(index)? {
                let _ = entries.insert(index, transform(value, index)?);
            }
        }
        Ok(Self {
            storage: ArrayStorage::Owned(Arc::new(Mutex::new(Some(ArrayValues {
                length,
                entries: entries
                    .into_iter()
                    .map(|(index, value)| (index, FieldPropertyDescriptor::data(value)))
                    .collect(),
                length_writable: true,
            })))),
            properties: FieldMap::new().into(),
        })
    }

    /// Filter present indices in order, omitting missing indices from the new dense array.
    pub fn filter(
        &self,
        mut predicate: impl FnMut(&FieldValue) -> AuthResult<bool>,
    ) -> AuthResult<Self> {
        self.filter_with_index(|value, _| predicate(value))
    }

    pub(crate) fn filter_with_index(
        &self,
        mut predicate: impl FnMut(&FieldValue, usize) -> AuthResult<bool>,
    ) -> AuthResult<Self> {
        let length = self.len()?;
        let mut values = Vec::new();
        for index in 0..length {
            if let Some(value) = self.get(index)?
                && predicate(&value, index)?
            {
                values.push(value);
            }
        }
        Ok(values.into())
    }

    /// Compare array identity without reading indices.
    pub fn same_array(&self, other: &Self) -> bool {
        self.identity() == other.identity()
    }

    /// Return whether length and index reads invoke a live source.
    /// Named properties do not affect the array's indexed storage.
    pub fn has_live_indices(&self) -> bool {
        matches!(&self.storage, ArrayStorage::Live(_))
    }

    pub(crate) fn identity(&self) -> ArrayIdentity {
        match &self.storage {
            ArrayStorage::Owned(values) => ArrayIdentity::Owned(Arc::as_ptr(values) as usize),
            ArrayStorage::Live(source) => ArrayIdentity::Live(source.identity()),
        }
    }

    pub(crate) fn source<T: 'static>(&self) -> Option<&T> {
        match &self.storage {
            ArrayStorage::Live(source) => source.as_any()?.downcast_ref(),
            ArrayStorage::Owned(_) => None,
        }
    }

    // Infallible typed narrowing must preserve holes and must not evaluate fallible live getters.
    pub(crate) fn owned_values(&self) -> Option<Vec<FieldValue>> {
        // A Vec cannot retain named properties or a dynamic property source.
        if self.properties.is_live() || !self.properties.own_keys().ok()?.is_empty() {
            return None;
        }
        let ArrayStorage::Owned(values) = &self.storage else {
            return None;
        };
        let values = values.lock();
        let values = values.as_ref()?;
        if values.entries.len() != values.length || !values.length_writable {
            return None;
        }
        values
            .entries
            .values()
            .map(|descriptor| match descriptor {
                FieldPropertyDescriptor {
                    enumerable: true,
                    configurable: true,
                    property:
                        FieldProperty::Data {
                            value,
                            writable: true,
                        },
                } => Some(value.clone()),
                _ => None,
            })
            .collect()
    }

    pub(crate) fn clone_seed(&self) -> AuthResult<ArrayCloneSeed> {
        if let ArrayStorage::Live(source) = &self.storage
            && let Some(seed) = source.clone_seed()?
        {
            return Ok(seed);
        }
        let target = Arc::new(Mutex::new(None));
        Ok(ArrayCloneSeed {
            array: Self {
                storage: ArrayStorage::Owned(target.clone()),
                properties: FieldMap::new().into(),
            },
            prepare: Box::new(move |length, entries| {
                let length = entries
                    .iter()
                    .map(|(index, _)| index + 1)
                    .fold(length, usize::max);
                let mut values = Some(ArrayValues {
                    length,
                    entries: entries
                        .into_iter()
                        .map(|(index, value)| (index, FieldPropertyDescriptor::data(value)))
                        .collect(),
                    length_writable: true,
                });
                Ok(CloneWrite::new(move || {
                    std::mem::swap(&mut *target.lock(), &mut values);
                }))
            }),
        })
    }
}

impl Default for FieldArray {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Vec<FieldValue>> for FieldArray {
    fn from(values: Vec<FieldValue>) -> Self {
        Self::from_values_with_properties(values, FieldMap::new().into())
    }
}

impl FromIterator<FieldValue> for FieldArray {
    fn from_iter<T: IntoIterator<Item = FieldValue>>(values: T) -> Self {
        values.into_iter().collect::<Vec<_>>().into()
    }
}

/// A fallible array iterator that retains the source identity and captures its initial length.
pub struct FieldArrayIter {
    array: FieldArray,
    next: usize,
    length: usize,
}

impl Iterator for FieldArrayIter {
    type Item = AuthResult<FieldValue>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.length {
            return None;
        }
        let index = self.next;
        self.next += 1;
        Some(self.array.get(index).map(Option::unwrap_or_default))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.length - self.next;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for FieldArrayIter {}

thread_local! {
    static COMPARING: RefCell<HashSet<(ArrayIdentity, ArrayIdentity)>> = RefCell::new(HashSet::new());
    static FORMATTING: RefCell<HashSet<ArrayIdentity>> = RefCell::new(HashSet::new());
}

impl PartialEq for FieldArray {
    fn eq(&self, other: &Self) -> bool {
        match (&self.storage, &other.storage) {
            (ArrayStorage::Owned(left), ArrayStorage::Owned(right)) => {
                let identity = (self.identity(), other.identity());
                let Some(_guard) = ComparisonGuard::enter(identity) else {
                    return true;
                };
                // Recursive comparisons must not retain either array lock.
                let left = left.lock().clone();
                let right = right.lock().clone();
                match (left, right) {
                    (Some(left), Some(right)) => {
                        left.length == right.length
                            && left.length_writable == right.length_writable
                            && left.entries == right.entries
                            && self.properties == other.properties
                    }
                    (None, None) => true,
                    _ => false,
                }
            }
            _ => self.same_array(other),
        }
    }
}

impl fmt::Debug for FieldArray {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.storage {
            ArrayStorage::Owned(values) => {
                let identity = self.identity();
                let Some(_guard) = FormattingGuard::enter(identity) else {
                    return formatter.write_str("[Circular]");
                };
                let values = values.lock().clone();
                formatter
                    .debug_struct("Array")
                    .field("length", &values.as_ref().map_or(0, |values| values.length))
                    .field("entries", &values.as_ref().map(|values| &values.entries))
                    .finish()
            }
            ArrayStorage::Live(_) => formatter
                .debug_struct("LiveArray")
                .field("identity", &self.identity())
                .finish(),
        }
    }
}

struct ComparisonGuard((ArrayIdentity, ArrayIdentity));
impl ComparisonGuard {
    fn enter(identity: (ArrayIdentity, ArrayIdentity)) -> Option<Self> {
        COMPARING
            .with(|active| active.borrow_mut().insert(identity))
            .then(|| Self(identity))
    }
}
impl Drop for ComparisonGuard {
    fn drop(&mut self) {
        COMPARING.with(|active| {
            let _ = active.borrow_mut().remove(&self.0);
        });
    }
}
struct FormattingGuard(ArrayIdentity);
impl FormattingGuard {
    fn enter(identity: ArrayIdentity) -> Option<Self> {
        FORMATTING
            .with(|active| active.borrow_mut().insert(identity))
            .then(|| Self(identity))
    }
}
impl Drop for FormattingGuard {
    fn drop(&mut self) {
        FORMATTING.with(|active| {
            let _ = active.borrow_mut().remove(&self.0);
        });
    }
}

#[cfg(test)]
#[path = "array_tests.rs"]
mod tests;
