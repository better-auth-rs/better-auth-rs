//! Memory adapter tables retain rows with omitted or duplicate IDs.

use crate::SchemaValue;

pub(super) trait MemoryRow {
    fn id(&self) -> &SchemaValue<String>;
}

#[derive(Clone)]
pub(super) struct Rows<T>(Vec<T>);

impl<T> Default for Rows<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}
impl<T> std::ops::Deref for Rows<T> {
    type Target = [T];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<T> Rows<T> {
    pub(super) fn push(&mut self, row: T) {
        self.0.push(row);
    }
    pub(super) fn iter_mut(&mut self) -> std::slice::IterMut<'_, T> {
        self.0.iter_mut()
    }
    pub(super) fn retain(&mut self, predicate: impl FnMut(&T) -> bool) {
        self.0.retain(predicate);
    }
    pub(super) fn into_vec(self) -> Vec<T> {
        self.0
    }
    pub(super) fn as_mut_vec(&mut self) -> &mut Vec<T> {
        &mut self.0
    }
}
impl<T: MemoryRow> Rows<T> {
    pub(super) fn get<Q: ?Sized>(&self, id: &Q) -> Option<&T>
    where
        SchemaValue<String>: PartialEq<Q>,
    {
        self.0.iter().find(|row| row.id() == id)
    }
    pub(super) fn get_mut<Q: ?Sized>(&mut self, id: &Q) -> Option<&mut T>
    where
        SchemaValue<String>: PartialEq<Q>,
    {
        self.0.iter_mut().find(|row| row.id() == id)
    }
    pub(super) fn replace<Q: ?Sized>(&mut self, id: &Q, row: T) -> bool
    where
        SchemaValue<String>: PartialEq<Q>,
    {
        if let Some(stored) = self.get_mut(id) {
            *stored = row;
            true
        } else {
            false
        }
    }
    pub(super) fn remove<Q: ?Sized>(&mut self, id: &Q) -> Option<T>
    where
        SchemaValue<String>: PartialEq<Q>,
    {
        self.0
            .iter()
            .position(|row| row.id() == id)
            .map(|index| self.0.remove(index))
    }
}
macro_rules! row_id {
    ($($record:ty),* $(,)?) => { $(impl MemoryRow for $record {
        fn id(&self) -> &SchemaValue<String> { &self.id }
    })* };
}
row_id!(
    crate::wire::UserView,
    crate::Organization,
    crate::Member,
    crate::Invitation,
    crate::Team,
    crate::OrganizationRole,
    crate::TwoFactor,
    crate::DeviceCode,
    crate::ApiKey,
    crate::Passkey
);
