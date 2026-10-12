#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify operation ownership and callback scheduling; adapter errors propagate."
)]

use super::*;
use crate::store::ephemeral::EphemeralStore;
use crate::store::schema::EntityRole;
use crate::{FieldMap, FieldValue};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

fn row(id: &str) -> FieldMap {
    [("id".into(), id.into())].into()
}

#[test]
fn filters_reenter_the_store_and_replace_the_captured_array() -> AuthResult<()> {
    let store = EphemeralStore::default();
    store.operation(|operation| {
        let table = operation.capture_table(EntityRole::Account)?;
        let first = table.push(row("first"))?;
        let second = table.push(row("second"))?;
        let mut visited = Vec::new();
        let selected = table.select_refs(|source| {
            let id = source.field("id")?.unwrap_or_default();
            visited.push(id.clone());
            if id == FieldValue::from("first") {
                store.operation(|nested| {
                    let live = nested.capture_table(EntityRole::Account)?;
                    nested.replace_table(
                        EntityRole::Account,
                        live.without_refs(std::slice::from_ref(&second))?,
                    )?;
                    let rebound = nested.capture_table(EntityRole::Account)?;
                    let _ = rebound.push(row("discarded-by-outer-replacement"))?;
                    Ok(())
                })?;
                let _ = table.push(row("appended-to-captured-array"))?;
            }
            Ok(source.same_row(&first))
        })?;
        assert_eq!(
            visited,
            [FieldValue::from("first"), FieldValue::from("second")]
        );
        operation.replace_table(EntityRole::Account, table.without_refs(&selected)?)?;
        let current = operation.capture_table(EntityRole::Account)?;
        assert_eq!(
            current.snapshot()?,
            [row("second"), row("appended-to-captured-array")]
        );
        assert!(!current.contains_ref(&first)?);
        first.apply_patch([("detached".into(), true.into())].into())?;
        assert_eq!(first.field("detached")?, Some(true.into()));
        assert_eq!(table.len()?, 3);
        Ok(())
    })
}

#[test]
fn later_filter_errors_keep_nested_mutations_without_publishing_the_delete() -> AuthResult<()> {
    let store = EphemeralStore::default();
    let message = "later predicate failed".to_owned();
    let allocation = message.as_ptr();
    let mut failure = Some(AuthError::Internal(message));
    let result = store.operation(|operation| {
        let table = operation.capture_table(EntityRole::Account)?;
        let _ = table.push(row("first"))?;
        let _ = table.push(row("second"))?;
        let selected = table.select_refs(|source| {
            if source.field("id")? == Some("first".into()) {
                source.apply_patch([("nested".into(), true.into())].into())?;
                Ok(true)
            } else {
                Err(failure
                    .take()
                    .ok_or_else(|| AuthError::internal("Repeated failure probe"))?)
            }
        })?;
        operation.replace_table(EntityRole::Account, table.without_refs(&selected)?)
    });
    assert!(matches!(result, Err(AuthError::Internal(message)) if message.as_ptr() == allocation));
    assert_eq!(
        store.operation(|operation| operation.capture_table(EntityRole::Account)?.snapshot())?,
        [
            [
                ("id".into(), "first".into()),
                ("nested".into(), true.into())
            ]
            .into(),
            row("second"),
        ]
    );
    Ok(())
}

struct ComparisonSource {
    name: &'static str,
    events: Arc<Mutex<Vec<&'static str>>>,
    append_to: Option<TableRef<FieldMap>>,
    appended: AtomicBool,
}

impl ComparisonSource {
    fn object(self: &Arc<Self>) -> crate::FieldObject {
        let source = self.clone();
        crate::FieldObject::from(indexmap::IndexMap::from([(
            "value".into(),
            crate::field_value::FieldPropertyDescriptor {
                enumerable: true,
                configurable: true,
                property: crate::field_value::FieldProperty::Accessor {
                    get: Some(crate::FieldFunction::contextual(move |_receiver, _| {
                        Ok(source.read()?.get("value").cloned().unwrap_or_default())
                    })),
                    set: None,
                },
            },
        )]))
    }

    fn read(&self) -> AuthResult<FieldMap> {
        self.events
            .lock()
            .map_err(|_| AuthError::internal("Comparison events poisoned"))?
            .push(self.name);
        if let Some(table) = &self.append_to
            && !self.appended.swap(true, Ordering::SeqCst)
        {
            let _ = table.push(row("appended-during-comparison"))?;
        }
        Ok([("value".into(), 1.into())].into())
    }
}

#[test]
fn reconciliation_compares_each_duplicate_lazily_and_visits_appended_live_rows() -> AuthResult<()> {
    let gate = MemoryGate::default();
    let live = TableRef::new(gate.clone());
    let base = TableRef::new(gate.clone());
    let working = TableRef::new(gate);
    let first = live.push(row("duplicate"))?;
    let second = live.push(row("duplicate"))?;
    let events = Arc::new(Mutex::new(Vec::new()));
    for (table, name, append) in [(&base, "base", false), (&working, "working", true)] {
        let source = ComparisonSource {
            name,
            events: events.clone(),
            append_to: append.then(|| live.clone()),
            appended: AtomicBool::new(false),
        };
        let mut fields = row("duplicate");
        let _ = fields.insert(
            "probe".into(),
            FieldValue::Object(Arc::new(source).object()),
        );
        let _ = table.push(fields)?;
    }
    let merged = live.reconcile(&base, &working)?;
    assert_eq!(
        *events
            .lock()
            .map_err(|_| AuthError::internal("Comparison events poisoned"))?,
        ["base", "working", "base", "working"]
    );
    assert!(merged.contains_ref(&first)?);
    assert!(merged.contains_ref(&second)?);
    assert_eq!(merged.len()?, 3);
    assert_eq!(
        merged
            .row_at(2)?
            .ok_or_else(|| AuthError::internal("Missing appended row"))?
            .field("id")?,
        Some("appended-during-comparison".into())
    );
    Ok(())
}

#[test]
fn transaction_plans_preserve_rebound_rows_without_repeating_callbacks() -> AuthResult<()> {
    let gate = MemoryGate::default();
    let live = TableRef::new(gate.clone());
    let updated = live.push(row("updated"))?;
    let retained = live.push(row("retained"))?;
    let deleted = live.push(row("deleted"))?;
    let detached = live.push(row("detached"))?;
    let base = TableRef::new(gate.clone());
    let working = TableRef::new(gate.clone());
    let events = Arc::new(Mutex::new(Vec::new()));
    for (table, name) in [(&base, "base"), (&working, "working")] {
        let mut fields = row("updated");
        let source = ComparisonSource {
            name,
            events: events.clone(),
            append_to: None,
            appended: AtomicBool::new(false),
        };
        let _ = fields.insert(
            "probe".into(),
            FieldValue::Object(Arc::new(source).object()),
        );
        if name == "working" {
            let _ = fields.insert("changed".into(), true.into());
        }
        let _ = table.push(fields)?;
        let _ = table.push(row("retained"))?;
        let mut fields = row("detached");
        if name == "working" {
            let _ = fields.insert("changed".into(), true.into());
        }
        let _ = table.push(fields)?;
    }
    let _ = base.push(row("deleted"))?;
    let appended = working.push(row("appended"))?;
    let (_, plan) = live.reconcile_with_plan(&base, &working)?;
    assert!(!plan.is_empty());
    assert_eq!(*events.lock().unwrap(), ["base", "working"]);

    retained.set_field("nested".into(), true.into())?;
    let rebound = TableRef::new(gate.clone()).push(row("detached"))?;
    let latest = TableRef::from_refs(
        gate,
        vec![updated, retained.clone(), deleted.clone(), rebound.clone()],
    );
    let merged = plan.apply(&latest)?;
    let replacement = working
        .row_at(0)?
        .ok_or_else(|| AuthError::internal("Missing replacement"))?;
    assert_eq!(
        merged.snapshot()?,
        [
            replacement.snapshot()?,
            retained.snapshot()?,
            rebound.snapshot()?,
            appended.snapshot()?
        ]
    );
    assert!(merged.contains_ref(&replacement)?);
    assert!(merged.contains_ref(&retained)?);
    assert!(merged.contains_ref(&rebound)?);
    assert!(merged.contains_ref(&appended)?);
    assert!(!merged.contains_ref(&deleted)?);
    assert!(!merged.contains_ref(&detached)?);
    assert!(latest.contains_ref(&deleted)?);
    assert_eq!(*events.lock().unwrap(), ["base", "working"]);
    Ok(())
}

#[test]
fn table_arrays_share_clone_identity_keep_first_origins_and_observe_later_appends() -> AuthResult<()>
{
    let table = TableRef::new(MemoryGate::default());
    let array = table.array();
    let source = table.push(row("before"))?;
    source.set_field("table".into(), array.clone().into())?;
    assert_eq!(array.len()?, 1);
    assert!(
        array
            .get(0)?
            .is_some_and(|value| value.strict_equals(&source.field_value()))
    );

    let mut context = StructuredCloneContext::deferred();
    let fields = context.clone_map(
        &[
            ("first".into(), array.clone().into()),
            ("second".into(), table.array().into()),
        ]
        .into(),
    )?;
    let retained = fields
        .get("first")
        .and_then(FieldValue::as_array)
        .ok_or_else(|| AuthError::internal("Missing first array alias"))?;
    let other = fields
        .get("second")
        .and_then(FieldValue::as_array)
        .ok_or_else(|| AuthError::internal("Missing second array alias"))?;
    assert!(retained.same_array(other));
    assert!(!retained.same_array(&array));
    source.set_field("id".into(), "after-first-visit".into())?;
    let mut originals = Vec::new();
    let copied = table.deep_clone_with(&mut context, |original, target, before| {
        originals.push((original, target, before));
    })?;
    assert!(copied.array().same_array(retained));
    assert_eq!(originals.len(), 1);
    let (original, target, before) = originals
        .first()
        .ok_or_else(|| AuthError::internal("Missing cloned row origin"))?;
    assert!(original.same_row(&source));
    assert_eq!(
        before,
        &[
            ("id".into(), "before".into()),
            ("table".into(), array.clone().into())
        ]
        .into()
    );
    assert_eq!(retained.len()?, 0);
    context.publish();
    assert_eq!(retained.len()?, 1);
    assert!(
        retained
            .get(0)?
            .is_some_and(|value| value.strict_equals(&target.field_value()))
    );
    assert!(
        target
            .field("table")?
            .is_some_and(|value| value.strict_equals(&retained.clone().into()))
    );
    assert_eq!(target.field("id")?, Some("before".into()));
    let appended = copied.push(row("appended"))?;
    assert_eq!(retained.len()?, 2);
    assert!(
        retained
            .get(1)?
            .is_some_and(|value| value.strict_equals(&appended.field_value()))
    );
    assert_eq!(array.len()?, 1);
    assert_eq!(source.field("id")?, Some("after-first-visit".into()));
    let _ = source.delete_field("table")?;
    let _ = target.delete_field("table")?;
    Ok(())
}
