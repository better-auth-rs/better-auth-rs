//! Rows preserve object identity when a transaction commits into the live table.

use crate::{AuthError, AuthResult, SchemaValue};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

pub(super) trait MemoryRow {
    fn id(&self) -> &SchemaValue<String>;
}

#[derive(Clone)]
pub(super) struct Rows<T>(Vec<Arc<Mutex<T>>>);
impl<T> Default for Rows<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}
fn lock<T>(row: &Mutex<T>) -> AuthResult<MutexGuard<'_, T>> {
    row.lock()
        .map_err(|_| AuthError::internal("Ephemeral row lock poisoned"))
}
impl<T: Clone> Rows<T> {
    pub(super) fn push(&mut self, row: T) {
        self.0.push(Arc::new(Mutex::new(row)));
    }
    pub(super) fn len(&self) -> usize {
        self.0.len()
    }
    pub(super) fn snapshot(&self) -> AuthResult<Vec<T>> {
        self.0
            .iter()
            .map(|row| lock(row).map(|row| row.clone()))
            .collect()
    }
    pub(super) fn deep_clone(&self) -> AuthResult<Self> {
        Ok(Self(
            self.snapshot()?
                .into_iter()
                .map(|row| Arc::new(Mutex::new(row)))
                .collect(),
        ))
    }
    pub(super) fn find_mut(
        &self,
        predicate: impl Fn(&T) -> bool,
    ) -> AuthResult<Option<MutexGuard<'_, T>>> {
        for row in &self.0 {
            let row = lock(row)?;
            if predicate(&row) {
                return Ok(Some(row));
            }
        }
        Ok(None)
    }
    pub(super) fn find(&self, predicate: impl Fn(&T) -> bool) -> AuthResult<Option<T>> {
        self.find_mut(predicate)
            .map(|row| row.map(|row| row.clone()))
    }
    pub(super) fn remove_first(&mut self, predicate: impl Fn(&T) -> bool) -> AuthResult<Option<T>> {
        for (index, row) in self.0.iter().enumerate() {
            let row = lock(row)?;
            if predicate(&row) {
                let value = row.clone();
                drop(row);
                let _ = self.0.remove(index);
                return Ok(Some(value));
            }
        }
        Ok(None)
    }
    pub(super) fn update_each(
        &self,
        mut update: impl FnMut(&mut T) -> AuthResult<()>,
    ) -> AuthResult<()> {
        for row in &self.0 {
            update(&mut *lock(row)?)?;
        }
        Ok(())
    }
    pub(super) fn retain(&mut self, mut predicate: impl FnMut(&T) -> bool) -> AuthResult<()> {
        let keep = self
            .snapshot()?
            .iter()
            .map(&mut predicate)
            .collect::<Vec<_>>();
        self.0 = std::mem::take(&mut self.0)
            .into_iter()
            .zip(keep)
            .filter_map(|(row, keep)| keep.then_some(row))
            .collect();
        Ok(())
    }
}
impl<T: Clone + MemoryRow> Rows<T> {
    pub(super) fn get<Q: ?Sized>(&self, id: &Q) -> AuthResult<Option<T>>
    where
        SchemaValue<String>: PartialEq<Q>,
    {
        self.get_mut(id).map(|row| row.map(|row| row.clone()))
    }
    pub(super) fn get_mut<Q: ?Sized>(&self, id: &Q) -> AuthResult<Option<MutexGuard<'_, T>>>
    where
        SchemaValue<String>: PartialEq<Q>,
    {
        self.find_mut(|row| row.id() == id)
    }
    pub(super) fn replace<Q: ?Sized>(&mut self, id: &Q, row: T) -> AuthResult<bool>
    where
        SchemaValue<String>: PartialEq<Q>,
    {
        if let Some(mut stored) = self.get_mut(id)? {
            *stored = row;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    pub(super) fn remove<Q: ?Sized>(&mut self, id: &Q) -> AuthResult<Option<T>>
    where
        SchemaValue<String>: PartialEq<Q>,
    {
        self.remove_first(|row| row.id() == id)
    }
}
pub(super) trait TransactionRow {
    fn transaction_id(&self) -> Option<String>;
}
impl<T: MemoryRow> TransactionRow for T {
    fn transaction_id(&self) -> Option<String> {
        self.id().as_str().map(str::to_owned)
    }
}
impl TransactionRow for serde_json::Map<String, serde_json::Value> {
    fn transaction_id(&self) -> Option<String> {
        self.get("id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    }
}
impl<T: Clone + PartialEq + TransactionRow> Rows<T> {
    pub(super) fn merge(&mut self, base: &Self, working: Self) -> AuthResult<()> {
        // The pinned memory adapter reconciles by public ID, even when IDs are
        // missing or duplicated. Preserve that observable limitation and row order.
        let base: HashMap<_, _> = base
            .snapshot()?
            .into_iter()
            .map(|row| (row.transaction_id(), row))
            .collect();
        let mut changed = HashMap::new();
        for shared in &working.0 {
            let row = lock(shared)?.clone();
            let _ = changed.insert(row.transaction_id(), (shared.clone(), row));
        }
        let mut placed = HashSet::new();
        let mut live = Vec::new();
        for shared in &self.0 {
            let id = lock(shared)?.transaction_id();
            if base.contains_key(&id) && !changed.contains_key(&id) {
                continue;
            }
            let replacement = match changed.get(&id) {
                Some((changed, value)) if base.get(&id) != Some(value) => changed,
                _ => shared,
            };
            live.push(replacement.clone());
            let _ = placed.insert(id);
        }
        for shared in working.0 {
            let id = lock(&shared)?.transaction_id();
            if !base.contains_key(&id) && !placed.contains(&id) {
                live.push(shared);
            }
        }
        self.0 = live;
        Ok(())
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
    crate::Passkey,
    crate::TeamMember,
    crate::Jwk,
    crate::types::WalletAddress,
    crate::wire::SessionView
);

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq)]
    struct Record {
        id: SchemaValue<String>,
        label: &'static str,
    }
    impl MemoryRow for Record {
        fn id(&self) -> &SchemaValue<String> {
            &self.id
        }
    }

    #[test]
    fn transaction_public_id_merge_matches_pinned_missing_duplicate_and_changed_ids()
    -> AuthResult<()> {
        for kind in ["undefined", "duplicate", "changed"] {
            let mut live = Rows::default();
            for (index, label) in ["Alice", "Bob"].into_iter().enumerate() {
                let id = match kind {
                    "undefined" => SchemaValue::Undefined,
                    "duplicate" => SchemaValue::Typed("duplicate".into()),
                    _ => SchemaValue::Typed((index + 1).to_string()),
                };
                live.push(Record { id, label });
            }
            let base = live.deep_clone()?;
            let working = base.deep_clone()?;
            {
                let mut first = working
                    .find_mut(|row| row.label == "Alice")?
                    .ok_or_else(|| AuthError::internal("missing Alice fixture"))?;
                if kind == "changed" {
                    first.id = SchemaValue::Typed("changed-public-id".into());
                }
                first.label = "Updated Alice";
            }
            live.merge(&base, working.clone())?;
            let rows = live.snapshot()?;
            let expected = if kind == "changed" {
                ["Bob", "Updated Alice"]
            } else {
                ["Alice", "Bob"]
            };
            assert_eq!(
                rows.iter().map(|row| row.label).collect::<Vec<_>>(),
                expected
            );
            assert_eq!(
                working.snapshot()?.first().map(|row| row.label),
                Some("Updated Alice")
            );
        }
        Ok(())
    }
}
