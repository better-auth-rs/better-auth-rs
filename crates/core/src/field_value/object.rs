use super::{FieldMap, FieldValue};
use crate::AuthResult;
use std::{fmt, sync::Arc};

/// A stable object handle. Property reads retain child handles and observe the current source.
/// Owned objects compare structurally. Live objects compare source identity without reading the source.
#[derive(Clone)]
pub struct FieldObject(ObjectStorage);

#[derive(Clone)]
enum ObjectStorage {
    Owned(Arc<FieldMap>),
    Live(Arc<dyn FieldObjectSource>),
}

pub(crate) trait FieldObjectSource: Send + Sync {
    fn get(&self, name: &str) -> AuthResult<Option<FieldValue>>;
    fn snapshot_fields(&self) -> AuthResult<FieldMap>;
    fn identity(&self) -> usize;
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum ObjectIdentity {
    Owned(usize),
    Live(usize),
}

impl FieldObject {
    pub(crate) fn from_source(source: Arc<dyn FieldObjectSource>) -> Self {
        Self(ObjectStorage::Live(source))
    }

    /// Read one current property without retaining a source lock.
    pub fn get(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        match &self.0 {
            ObjectStorage::Owned(fields) => Ok(fields.get(name).cloned()),
            ObjectStorage::Live(source) => source.get(name),
        }
    }

    /// Copy current own fields while retaining child identities.
    pub fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        match &self.0 {
            ObjectStorage::Owned(fields) => Ok((**fields).clone()),
            ObjectStorage::Live(source) => source.snapshot_fields(),
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

    /// Borrow fields only when the object already owns an immutable map.
    pub(crate) fn owned_fields(&self) -> Option<&FieldMap> {
        match &self.0 {
            ObjectStorage::Owned(fields) => Some(fields),
            ObjectStorage::Live(_) => None,
        }
    }
}

impl From<FieldMap> for FieldObject {
    fn from(fields: FieldMap) -> Self {
        Self(ObjectStorage::Owned(Arc::new(fields)))
    }
}

impl PartialEq for FieldObject {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (ObjectStorage::Owned(left), ObjectStorage::Owned(right)) => left == right,
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
            ObjectStorage::Owned(fields) => fields.fmt(f),
            ObjectStorage::Live(source) => f
                .debug_struct("LiveObject")
                .field("identity", &source.identity())
                .finish_non_exhaustive(),
        }
    }
}
