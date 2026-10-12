use super::{
    FieldMap, FieldProperty, FieldPropertyDefinition, FieldPropertyDescriptor, FieldValue,
};
use crate::{AuthError, AuthResult};
use indexmap::IndexMap;
use std::{
    any::Any,
    cell::RefCell,
    collections::HashSet,
    fmt,
    sync::{Arc, Mutex},
};

/// A stable object handle. Property reads retain child handles and observe the current source.
/// Owned objects compare structurally. Live objects compare source identity without reading the source.
/// Object properties retain strong handles. Cycles retain their memory until a property is deleted
/// to break the cycle; this handle does not provide tracing garbage collection.
#[derive(Clone)]
pub struct FieldObject(ObjectStorage);

#[derive(Clone)]
enum ObjectStorage {
    Owned(Arc<Mutex<IndexMap<String, FieldPropertyDescriptor>>>),
    Live(Arc<dyn FieldObjectSource>),
}

/// A live object source. Property access must retain native values and child identities.
pub trait FieldObjectSource: Send + Sync {
    /// Return the completed native OwnPropertyKeys order or its original error.
    /// The source validates operation invariants; wrappers do not sort or deduplicate this result.
    fn own_keys(&self) -> AuthResult<Vec<String>>;
    /// Inspect one current own property without evaluating its value or enumerating other keys.
    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>>;
    fn has_property(&self, name: &str) -> AuthResult<bool> {
        Ok(self.own_keys()?.iter().any(|key| key == name))
    }
    /// Read a property with the native receiver without performing a descriptor preflight.
    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>>;
    /// Assign without reading the previous value. `false` reports a rejected assignment.
    fn set_with_receiver(
        &self,
        name: String,
        value: FieldValue,
        receiver: &FieldValue,
    ) -> AuthResult<bool>;
    /// Define a current own property. The source owns validation and operation ordering.
    fn define_own_property(
        &self,
        name: String,
        definition: FieldPropertyDefinition,
    ) -> AuthResult<bool>;
    /// Delete an own property without reading its value. An absent property succeeds.
    fn delete(&self, name: &str) -> AuthResult<bool>;
    fn snapshot_fields(&self) -> AuthResult<FieldMap>;
    fn identity(&self) -> usize;

    #[doc(hidden)]
    fn clone_seed(&self) -> AuthResult<Option<super::ObjectCloneSeed>> {
        Ok(None)
    }

    fn as_any(&self) -> Option<&dyn Any> {
        None
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum ObjectIdentity {
    Owned(usize),
    Live(usize),
}

thread_local! {
    static COMPARING: RefCell<HashSet<(ObjectIdentity, ObjectIdentity)>> = RefCell::new(HashSet::new());
    static FORMATTING: RefCell<HashSet<ObjectIdentity>> = RefCell::new(HashSet::new());
}

struct ComparisonGuard(ObjectIdentity, ObjectIdentity);

impl ComparisonGuard {
    fn enter(left: ObjectIdentity, right: ObjectIdentity) -> Option<Self> {
        COMPARING
            .with(|active| active.borrow_mut().insert((left, right)))
            .then(|| Self(left, right))
    }
}

impl Drop for ComparisonGuard {
    fn drop(&mut self) {
        COMPARING.with(|active| {
            let _ = active.borrow_mut().remove(&(self.0, self.1));
        });
    }
}

struct FormattingGuard(ObjectIdentity);

impl FormattingGuard {
    fn enter(identity: ObjectIdentity) -> Option<Self> {
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

impl FieldObject {
    /// Retain a live source without reading its properties.
    pub fn from_source(source: Arc<dyn FieldObjectSource>) -> Self {
        Self(ObjectStorage::Live(source))
    }

    /// Capture property names without evaluating property values.
    pub fn own_keys(&self) -> AuthResult<Vec<String>> {
        let mut keys = match &self.0 {
            ObjectStorage::Owned(fields) => fields
                .lock()
                .map_err(|_| AuthError::internal("Field object lock poisoned"))?
                .keys()
                .cloned()
                .collect(),
            ObjectStorage::Live(source) => return source.own_keys(),
        };
        keys.sort_by_key(|name| {
            crate::utils::json::array_index(name).map_or((true, 0), |index| (false, index))
        });
        Ok(keys)
    }

    /// Inspect a current own property. Absence differs from a non-enumerable property.
    pub fn own_property_descriptor(
        &self,
        name: &str,
    ) -> AuthResult<Option<FieldPropertyDescriptor>> {
        match &self.0 {
            ObjectStorage::Owned(fields) => Ok(fields
                .lock()
                .map_err(|_| AuthError::internal("Field object lock poisoned"))?
                .get(name)
                .cloned()),
            ObjectStorage::Live(source) => source.own_property_descriptor(name),
        }
    }

    /// Capture enumerable keys before reading values, as required by JSON and `Object.keys`.
    pub fn enumerable_keys(&self) -> AuthResult<Vec<String>> {
        let mut keys = Vec::new();
        for name in self.own_keys()? {
            if self
                .own_property_descriptor(&name)?
                .is_some_and(|descriptor| descriptor.enumerable)
            {
                keys.push(name);
            }
        }
        Ok(keys)
    }

    pub(crate) fn source<T: 'static>(&self) -> Option<&T> {
        match &self.0 {
            ObjectStorage::Live(source) => source.as_any()?.downcast_ref(),
            ObjectStorage::Owned(_) => None,
        }
    }

    pub(crate) fn clone_seed(&self) -> AuthResult<super::ObjectCloneSeed> {
        if let ObjectStorage::Live(source) = &self.0
            && let Some(seed) = source.clone_seed()?
        {
            return Ok(seed);
        }
        let fields = Arc::new(Mutex::new(IndexMap::new()));
        let object = Self(ObjectStorage::Owned(fields.clone()));
        Ok(super::ObjectCloneSeed {
            object,
            state: Vec::new(),
            original_record: None,
            prepare: Box::new(move |values, _, _| {
                Ok(super::structured_clone::prepare_clone(
                    fields,
                    data_properties(values),
                ))
            }),
        })
    }

    /// Read one current property without retaining a source lock.
    pub fn get(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        self.get_with_receiver(name, &FieldValue::Object(self.clone()))
    }

    /// Read with an explicit native receiver while preserving source operation traps.
    pub fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        match &self.0 {
            ObjectStorage::Owned(fields) => {
                let descriptor = fields
                    .lock()
                    .map_err(|_| AuthError::internal("Field object lock poisoned"))?
                    .get(name)
                    .cloned();
                descriptor
                    .map(|descriptor| descriptor.read(receiver))
                    .transpose()
            }
            ObjectStorage::Live(source) => source.get_with_receiver(name, receiver),
        }
    }

    /// Check property presence without evaluating the property value.
    /// Sources with prototype properties must provide their own presence check.
    pub fn has_property(&self, name: &str) -> AuthResult<bool> {
        match &self.0 {
            ObjectStorage::Owned(fields) => Ok(fields
                .lock()
                .map_err(|_| AuthError::internal("Field object lock poisoned"))?
                .contains_key(name)),
            ObjectStorage::Live(source) => source.has_property(name),
        }
    }

    /// Assign in strict mode without reading the previous value.
    pub fn set(&self, name: impl Into<String>, value: FieldValue) -> AuthResult<()> {
        self.assign(&name.into(), value, &FieldValue::Object(self.clone()))
    }

    pub(crate) fn assign(
        &self,
        name: &str,
        value: FieldValue,
        receiver: &FieldValue,
    ) -> AuthResult<()> {
        if self.set_with_receiver(name, value, receiver)? {
            Ok(())
        } else {
            Err(AuthError::type_error(
                "Attempted to assign to readonly property.",
            ))
        }
    }

    /// Apply ordinary assignment or delegate directly to the live source operation.
    pub fn set_with_receiver(
        &self,
        name: &str,
        value: FieldValue,
        receiver: &FieldValue,
    ) -> AuthResult<bool> {
        if let ObjectStorage::Live(source) = &self.0 {
            return source.set_with_receiver(name.into(), value, receiver);
        }
        if let Some(descriptor) = self.own_property_descriptor(name)?
            && let Some(result) = descriptor.assign(receiver, value.clone())?
        {
            return Ok(result);
        }
        receiver.write_data_property(name, value)
    }

    /// Validate a partial own-property definition without evaluating accessors.
    pub fn define_own_property(
        &self,
        name: impl Into<String>,
        definition: FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        let name = name.into();
        match &self.0 {
            ObjectStorage::Owned(fields) => {
                let mut fields = fields
                    .lock()
                    .map_err(|_| AuthError::internal("Field object lock poisoned"))?;
                let Some(descriptor) = definition.apply(fields.get(&name)) else {
                    return Ok(false);
                };
                let previous = fields.insert(name, descriptor);
                drop(fields);
                drop(previous);
                Ok(true)
            }
            ObjectStorage::Live(source) => source.define_own_property(name, definition),
        }
    }

    pub(crate) fn prepare_fields(
        &self,
        fields: FieldMap,
    ) -> AuthResult<super::structured_clone::CloneWrite> {
        match &self.0 {
            ObjectStorage::Owned(target) => Ok(super::structured_clone::prepare_clone(
                target.clone(),
                data_properties(fields),
            )),
            ObjectStorage::Live(_) => Err(AuthError::internal(
                "Structured clone requires an owned property target",
            )),
        }
    }

    /// Delete an own property without evaluating its value. An absent property succeeds.
    pub fn delete(&self, name: &str) -> AuthResult<bool> {
        match &self.0 {
            ObjectStorage::Owned(fields) => {
                let mut fields = fields
                    .lock()
                    .map_err(|_| AuthError::internal("Field object lock poisoned"))?;
                if fields
                    .get(name)
                    .is_some_and(|descriptor| !descriptor.configurable)
                {
                    return Ok(false);
                }
                let previous = fields.shift_remove(name);
                drop(fields);
                drop(previous);
                Ok(true)
            }
            ObjectStorage::Live(source) => source.delete(name),
        }
    }

    /// Explicitly read current own fields while retaining child identities.
    /// Owned accessors run in property order; live sources own their projection boundary.
    pub fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        let mut fields = match &self.0 {
            ObjectStorage::Owned(_) => {
                let mut fields = FieldMap::new();
                for name in self.own_keys()? {
                    if let Some(value) = self.get(&name)? {
                        let _ = fields.insert(name, value);
                    }
                }
                fields
            }
            ObjectStorage::Live(source) => source.snapshot_fields()?,
        };
        fields.sort_property_order();
        Ok(fields)
    }

    fn snapshot_descriptors(&self) -> AuthResult<IndexMap<String, FieldPropertyDescriptor>> {
        match &self.0 {
            ObjectStorage::Owned(fields) => fields
                .lock()
                .map_err(|_| AuthError::internal("Field object lock poisoned"))
                .map(|fields| fields.clone()),
            ObjectStorage::Live(_) => Err(AuthError::internal(
                "Live object descriptors require explicit reflection",
            )),
        }
    }

    /// Compare object identity without reading either object's properties.
    pub fn same_object(&self, other: &Self) -> bool {
        self.identity() == other.identity()
    }

    pub(crate) fn identity(&self) -> ObjectIdentity {
        match &self.0 {
            ObjectStorage::Owned(fields) => ObjectIdentity::Owned(Arc::as_ptr(fields) as usize),
            ObjectStorage::Live(source) => ObjectIdentity::Live(source.identity()),
        }
    }

    pub(crate) fn is_live(&self) -> bool {
        matches!(self.0, ObjectStorage::Live(_))
    }

    // Infallible typed probing must retain descriptors and must not evaluate fallible accessors.
    pub(crate) fn owned_fields(&self) -> Option<FieldMap> {
        let ObjectStorage::Owned(fields) = &self.0 else {
            return None;
        };
        let fields = fields.lock().ok()?;
        let mut result = FieldMap::new();
        for (name, descriptor) in fields.iter() {
            let FieldPropertyDescriptor {
                enumerable: true,
                configurable: true,
                property:
                    FieldProperty::Data {
                        value,
                        writable: true,
                    },
            } = descriptor
            else {
                return None;
            };
            let _ = result.insert(name.clone(), value.clone());
        }
        result.sort_property_order();
        Some(result)
    }
}

impl From<IndexMap<String, FieldPropertyDescriptor>> for FieldObject {
    fn from(properties: IndexMap<String, FieldPropertyDescriptor>) -> Self {
        Self(ObjectStorage::Owned(Arc::new(Mutex::new(properties))))
    }
}

impl From<FieldMap> for FieldObject {
    fn from(fields: FieldMap) -> Self {
        Self(ObjectStorage::Owned(Arc::new(Mutex::new(data_properties(
            fields,
        )))))
    }
}

impl From<FieldObject> for FieldValue {
    fn from(value: FieldObject) -> Self {
        Self::Object(value)
    }
}

impl PartialEq for FieldObject {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (ObjectStorage::Owned(_), ObjectStorage::Owned(_)) => {
                let Some(_guard) = ComparisonGuard::enter(self.identity(), other.identity()) else {
                    return true;
                };
                // Snapshot each side separately; recursive comparisons must not retain either lock.
                match (self.snapshot_descriptors(), other.snapshot_descriptors()) {
                    (Ok(left), Ok(right)) => left == right,
                    // Infallible equality cannot report a poisoned source. Explicit reads return the error.
                    _ => false,
                }
            }
            (ObjectStorage::Live(left), ObjectStorage::Live(right)) => {
                left.identity() == right.identity()
            }
            _ => false,
        }
    }
}

impl fmt::Debug for FieldObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            ObjectStorage::Owned(_) => {
                let Some(_guard) = FormattingGuard::enter(self.identity()) else {
                    return f.write_str("[Circular]");
                };
                match self.snapshot_descriptors() {
                    Ok(fields) => fields.fmt(f),
                    Err(error) => f
                        .debug_struct("UnavailableObject")
                        .field("error", &error)
                        .finish(),
                }
            }
            ObjectStorage::Live(source) => f
                .debug_struct("LiveObject")
                .field("identity", &source.identity())
                .finish_non_exhaustive(),
        }
    }
}

fn data_properties(fields: FieldMap) -> IndexMap<String, FieldPropertyDescriptor> {
    fields
        .into_iter()
        .map(|(name, value)| (name, FieldPropertyDescriptor::data(value)))
        .collect()
}
