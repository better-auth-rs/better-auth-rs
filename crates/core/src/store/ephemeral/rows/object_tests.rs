#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify row ownership; fixture and object access errors propagate."
)]

use super::*;
use crate::store::ephemeral::EphemeralStore;
use crate::store::ephemeral::table::TableRef;
use crate::store::schema::EntityRole;
use std::sync::Weak;
use std::sync::atomic::{AtomicUsize, Ordering};

fn required<T>(value: Option<T>) -> AuthResult<T> {
    value.ok_or_else(|| AuthError::internal("Expected a retained object fixture"))
}

fn detached(
    seed: impl Fn(&TableRef<FieldMap>, FieldMap) -> AuthResult<RowRef<FieldMap>>,
) -> AuthResult<()> {
    let mut rows = TableRef::new(Arc::default());
    let original = seed(
        &rows,
        [
            ("id".into(), "same-id".into()),
            ("name".into(), "original".into()),
        ]
        .into(),
    )?;
    let retained = original.field_value();
    let handle = required(retained.as_object())?;
    rows = rows.without_refs(std::slice::from_ref(&original))?;
    let replacement = seed(
        &rows,
        [
            ("id".into(), "same-id".into()),
            ("name".into(), "replacement".into()),
        ]
        .into(),
    )?;
    assert_eq!(handle.get("name")?, Some("original".into()));
    handle.set("name", false.into())?;
    assert_eq!(handle.get("id")?, Some("same-id".into()));
    assert!(handle.delete("id")?);
    assert_eq!(handle.get("id")?, None);
    handle.set("id", FieldValue::Undefined)?;
    assert_eq!(handle.get("id")?, Some(FieldValue::Undefined));
    assert!(handle.delete("id")?);
    assert_eq!(handle.get("id")?, None);
    assert_eq!(
        original.shallow_fields()?,
        [("name".into(), false.into())].into()
    );
    assert_eq!(
        replacement.shallow_fields()?,
        [
            ("id".into(), "same-id".into()),
            ("name".into(), "replacement".into()),
        ]
        .into()
    );
    assert!(!handle.same_object(required(replacement.field_value().as_object())?));
    Ok(())
}

#[test]
fn retained_map_and_user_handles_do_not_rebind_after_deletion() -> AuthResult<()> {
    detached(TableRef::push)?;
    detached(|table, fields| table.push_user_state(crate::UserView::from_field_values(fields)?))
}

#[test]
fn user_row_clone_preserves_native_state_and_hidden_graph_aliases() -> AuthResult<()> {
    let date = FieldValue::from(crate::FieldDate::from_milliseconds(42.0));
    let mut user = crate::UserView::from_field_values(FieldMap::from([
        ("id".into(), "user".into()),
        ("name".into(), date.clone()),
        ("createdAt".into(), date.clone()),
    ]))?;
    user.visible_fields = None;
    user.is_anonymous = None.into();
    let table = TableRef::new(Arc::default());
    let source = table.push_user_state(user)?;
    let metadata = crate::FieldObject::from(FieldMap::from([
        ("date".into(), date.clone()),
        ("row".into(), source.field_value()),
    ]));
    let mut user = source.user_state_snapshot()?;
    user.metadata = FieldValue::Object(metadata.clone());
    let _ = user
        .additional_fields
        .insert("metadata".into(), FieldValue::Object(metadata.clone()));
    let _ = user
        .additional_fields
        .insert("payload".into(), FieldValue::Object(metadata.clone()));
    source.replace_user_state(user.clone())?;
    let copied = table.deep_clone(&mut crate::StructuredCloneContext::new())?;
    let target = required(copied.row_at(0)?)?;
    let cloned = target.user_state_snapshot()?;
    assert_eq!(cloned.visible_fields, None);
    assert_eq!(cloned.is_anonymous, None);
    assert_eq!(cloned.field_order, user.field_order);
    assert!(!target.same_row(&source));
    let cloned_date = cloned.created_at.field_value();
    assert!(!cloned_date.strict_equals(&date));
    assert!(cloned.name.field_value().strict_equals(&cloned_date));
    let cloned_metadata = required(cloned.metadata.as_object())?;
    assert!(!cloned_metadata.same_object(&metadata));
    assert!(required(cloned.additional_fields.get("metadata"))?.strict_equals(&cloned.metadata));
    assert!(required(cloned.additional_fields.get("payload"))?.strict_equals(&cloned.metadata));
    assert!(required(cloned_metadata.get("date")?)?.strict_equals(&cloned_date));
    assert!(required(cloned_metadata.get("row")?)?.strict_equals(&target.field_value()));
    assert!(!cloned.field_values()?.contains_key("metadata"));
    let _ = metadata.delete("row")?;
    let _ = cloned_metadata.delete("row")?;
    Ok(())
}

#[test]
fn user_row_clone_preserves_presence_order_and_interleaved_native_shadows() -> AuthResult<()> {
    let date = FieldValue::from(crate::FieldDate::from_milliseconds(42.0));
    let mut user = crate::UserView::from_field_values(FieldMap::from([
        ("first".into(), "first".into()),
        ("name".into(), FieldValue::Undefined),
        ("id".into(), "user".into()),
    ]))?;
    user.field_order.push("absent".into());
    user.email = crate::SchemaValue::from_field(date.clone());
    user.metadata = date.clone();
    for name in ["name", "last", "metadata"] {
        let _ = user.additional_fields.insert(name.into(), date.clone());
    }
    let table = TableRef::new(Arc::default());
    let _ = table.push_user_state(user.clone())?;
    let copied = table.deep_clone(&mut crate::StructuredCloneContext::new())?;
    let target = required(copied.row_at(0)?)?;
    let raw = target.snapshot()?;
    assert_eq!(
        raw.keys().map(String::as_str).collect::<Vec<_>>(),
        ["first", "name", "id", "last"]
    );
    assert_eq!(raw.get("name"), Some(&FieldValue::Undefined));
    assert!(!raw.contains_key("email"));
    assert!(!raw.contains_key("metadata"));
    let cloned = target.user_state_snapshot()?;
    assert_eq!(cloned.field_order, user.field_order);
    assert_eq!(cloned.visible_fields, Some(raw.keys().cloned().collect()));
    assert_eq!(
        cloned.additional_fields.keys().collect::<Vec<_>>(),
        user.additional_fields.keys().collect::<Vec<_>>()
    );
    let cloned_date = required(raw.get("last"))?;
    assert!(!cloned_date.strict_equals(&date));
    assert!(cloned.email.field_value().strict_equals(cloned_date));
    assert!(cloned.metadata.strict_equals(cloned_date));
    for name in ["name", "last", "metadata"] {
        assert!(required(cloned.additional_fields.get(name))?.strict_equals(cloned_date));
    }
    Ok(())
}

#[test]
fn ordinary_row_writes_discard_hidden_user_state_even_without_field_changes() -> AuthResult<()> {
    type Write = fn(&RowRef<FieldMap>) -> AuthResult<()>;
    let writes: [Write; 5] = [
        |row| row.set_field("id".into(), "user".into()),
        |row| row.delete_field("absent").map(|_| ()),
        |row| row.apply_patch(FieldMap::new()),
        |row| row.increment_number_fields(&[]),
        |row| row.replace(row.snapshot()?),
    ];
    for write in writes {
        let raw = FieldMap::from([("id".into(), "user".into())]);
        let mut user = crate::UserView::from_field_values(raw.clone())?;
        user.field_order.push("absent".into());
        user.email = crate::SchemaValue::from_field("hidden@example.com".into());
        user.metadata = "hidden metadata".into();
        let _ = user
            .additional_fields
            .insert("name".into(), "hidden name".into());
        let source = TableRef::new(Arc::default()).push_user_state(user)?;
        write(&source)?;
        assert_eq!(source.snapshot()?, raw);
        let user = source.user_state_snapshot()?;
        assert!(user.email.field_value().is_undefined());
        assert!(user.metadata.is_undefined());
        assert!(user.additional_fields.is_empty());
        assert_eq!(user.field_order, ["id"]);
        assert_eq!(user.visible_fields, Some(raw.keys().cloned().collect()));
    }
    Ok(())
}

#[test]
fn memoized_rows_retain_the_first_clone_origin_for_ownership_checks() -> AuthResult<()> {
    let table = TableRef::new(Arc::default());
    let original = FieldMap::from([
        ("id".into(), "device".into()),
        ("userId".into(), "first-owner".into()),
    ]);
    let source = table.push(original.clone())?;
    let mut context = crate::StructuredCloneContext::new();
    let nested = context.clone_value(&source.field_value())?;
    source.set_field("userId".into(), "reassigned-owner".into())?;
    let mut origins = Vec::new();
    let cloned = table.deep_clone_with(&mut context, |live, isolated, before| {
        origins.push((live, isolated, before));
    })?;
    assert_eq!(origins.len(), 1);
    let (live, isolated, before) = required(origins.pop())?;
    assert_eq!(before, original);
    assert_eq!(isolated.shallow_fields()?, original);
    assert!(live.same_row(&source));
    assert_eq!(live.field("userId")?, Some("reassigned-owner".into()));
    assert!(required(cloned.row_at(0)?)?.same_row(&isolated));
    assert!(nested.strict_equals(&isolated.field_value()));
    Ok(())
}

#[tokio::test]
async fn mutable_handles_keep_transaction_rollback_and_commit_ownership() -> AuthResult<()> {
    let store = EphemeralStore::default();
    let live = store.operation(|op| {
        op.capture_table(EntityRole::Account)?.push(
            [
                ("id".into(), "account".into()),
                (
                    "payload".into(),
                    FieldMap::from([("value".into(), 0.into())]).into(),
                ),
            ]
            .into(),
        )
    })?;
    let original = live.shallow_fields()?;
    let (base, rollback, queue) = store.begin_adapter_transaction()?;
    let row = required(rollback.operation(|op| op.capture_table(EntityRole::Account)?.row_at(0))?)?;
    let retained = row.field_value();
    let object = required(retained.as_object())?;
    let payload = required(object.get("payload")?)?;
    required(payload.as_object())?.set("value", 1.into())?;
    object.set("phase", "rolled-back".into())?;
    drop((base, rollback, queue));
    object.set("phase", "retained-after-rollback".into())?;
    assert_eq!(live.shallow_fields()?, original);

    let (base, commit, queue) = store.begin_adapter_transaction()?;
    let committed =
        required(commit.operation(|op| op.capture_table(EntityRole::Account)?.row_at(0))?)?;
    let value = committed.field_value();
    let payload = required(required(value.as_object())?.get("payload")?)?;
    required(payload.as_object())?.set("value", 2.into())?;
    store.commit_transaction(base, commit, queue).await?;
    assert!(store.operation(|op| {
        op.capture_table(EntityRole::Account)?
            .contains_ref(&committed)
    })?);
    assert!(!store.operation(|op| op.capture_table(EntityRole::Account)?.contains_ref(&live))?);
    required(value.as_object())?.set("phase", "after-commit".into())?;
    assert_eq!(
        required(store.operation(|op| op.capture_table(EntityRole::Account)?.row_at(0))?)?
            .shallow_fields()?,
        [
            ("id".into(), "account".into()),
            (
                "payload".into(),
                FieldMap::from([("value".into(), 2.into())]).into()
            ),
            ("phase".into(), "after-commit".into()),
        ]
        .into()
    );
    assert_eq!(live.shallow_fields()?, original);
    Ok(())
}

struct InvitationGraphSource {
    row: Weak<Mutex<RowCell<FieldMap>>>,
    reads: AtomicUsize,
    failure_at: Option<usize>,
    failure: Mutex<Option<AuthError>>,
}

impl InvitationGraphSource {
    fn object(self: &Arc<Self>) -> crate::FieldObject {
        let source = self.clone();
        crate::FieldObject::from(indexmap::IndexMap::from([(
            "name".into(),
            crate::field_value::FieldPropertyDescriptor {
                enumerable: true,
                configurable: true,
                property: crate::field_value::FieldProperty::Accessor {
                    get: Some(crate::FieldFunction::contextual(move |_receiver, _| {
                        Ok(source.read()?.get("name").cloned().unwrap_or_default())
                    })),
                    set: None,
                },
            },
        )]))
    }

    fn read(&self) -> AuthResult<FieldMap> {
        let source = required(self.row.upgrade())?;
        // A failed try_lock reports the regression without blocking the test process.
        let row = source
            .try_lock()
            .map_err(|_| AuthError::internal("Invitation graph copy retained its row lock"))?;
        let read = self.reads.fetch_add(1, Ordering::SeqCst);
        if self.failure_at == Some(read)
            && let Some(error) = lock(&self.failure)?.take()
        {
            return Err(error);
        }
        let value = row.value.clone();
        drop(row);
        let name = match value {
            RowValue::Typed(fields) => fields.get("name").cloned(),
            RowValue::Properties(object) => object.get("name")?,
        };
        Ok([("name".into(), name.unwrap_or_default())].into())
    }
}

#[tokio::test]
async fn invitation_graph_copies_release_rows_and_preserve_aliases_and_failure_ownership()
-> AuthResult<()> {
    use crate::store::{InvitationStore, SessionStore, TeamMemberLimits};
    use chrono::Utc;

    // Guarded acceptance rebases live Team fields after independent base and working snapshots.
    for (phase, failure_at, expected_reads) in [
        ("commit", None, 3),
        ("base", Some(0), 1),
        ("working", Some(1), 2),
        ("rebase", Some(2), 3),
    ] {
        let fail_copy = failure_at.is_some();
        let store = EphemeralStore::default();
        let sources: Vec<_> = ["first", "second"]
            .into_iter()
            .map(|id| {
                store.operation(|op| {
                    op.capture_table(EntityRole::Team)?.push(
                        [
                            ("id".into(), id.into()),
                            ("name".into(), "Shared graph".into()),
                            ("organizationId".into(), "organization".into()),
                            ("createdAt".into(), Utc::now().into()),
                            ("memberCount".into(), 0.into()),
                        ]
                        .into(),
                    )
                })
            })
            .collect::<AuthResult<_>>()?;
        let failure = "Invitation graph source failed".to_owned();
        let original_error = failure.as_ptr() as usize;
        let RowStorage::Record(source) = &required(sources.first())?.storage else {
            return Err(AuthError::internal(
                "Expected an adapter-owned row for the lock probe",
            ));
        };
        let graph = Arc::new(InvitationGraphSource {
            row: Arc::downgrade(source),
            reads: AtomicUsize::new(0),
            failure_at,
            failure: Mutex::new(fail_copy.then_some(AuthError::Internal(failure))),
        });
        let shared = FieldValue::Object(graph.object());
        for row in &sources {
            row.apply_patch(
                [
                    ("graph".into(), shared.clone()),
                    ("alias".into(), shared.clone()),
                ]
                .into(),
            )?;
        }
        let mut input = crate::CreateInvitation::new(
            "organization",
            "recipient@example.com",
            "member",
            "inviter",
            (Utc::now() + chrono::Duration::days(1)).into(),
        );
        input.team_id = Some("first,second".into());
        let invitation = store.create_invitation(input).await?;
        let result = store
            .accept_invitation_with_teams(
                invitation.id.typed()?,
                "recipient",
                None,
                true,
                TeamMemberLimits::Fixed(Some(1)),
            )
            .await;
        assert_eq!(
            graph.reads.load(Ordering::SeqCst),
            expected_reads,
            "{phase}"
        );
        if fail_copy {
            assert!(
                matches!(result, Err(AuthError::Internal(message))
                if message == "Invitation graph source failed"
                    && message.as_ptr() as usize == original_error),
                "{phase}"
            );
        } else {
            let (member, accepted, session) = result?;
            assert_eq!(member.user_id, "recipient");
            assert_eq!(accepted.status.field_value(), "accepted".into());
            assert!(session.is_none());
        }
        let state = store.operation(|op| op.capture_state())?;
        assert_eq!(
            state.fixture_table("member").len()?,
            usize::from(!fail_copy)
        );
        assert_eq!(
            state.fixture_table("teamMember").len()?,
            if fail_copy { 0 } else { 2 }
        );
        assert_eq!(state.fixture_table("session").len()?, 0);
        assert_eq!(
            required(state.fixture_table("invitation").snapshot()?.first())?.get("status"),
            Some(&FieldValue::from(if fail_copy {
                "pending"
            } else {
                "accepted"
            }))
        );
        let teams = state.fixture_table("team").snapshot()?;
        let first = required(teams.first())?;
        let cloned = required(required(first.get("graph"))?.as_object())?;
        if !fail_copy {
            assert_eq!(
                cloned.snapshot_fields()?,
                [("name".into(), "Shared graph".into())].into()
            );
        }
        for (team, original) in teams.iter().zip(&sources) {
            assert_eq!(
                team.get("memberCount"),
                Some(&FieldValue::from(if fail_copy { 0 } else { 1 }))
            );
            assert_eq!(
                state.fixture_table("team").contains_ref(original)?,
                fail_copy
            );
            for name in ["graph", "alias"] {
                let value = required(required(team.get(name))?.as_object())?;
                assert!(cloned.same_object(value));
                assert_eq!(value.same_object(required(shared.as_object())?), fail_copy);
            }
        }
    }
    Ok(())
}
