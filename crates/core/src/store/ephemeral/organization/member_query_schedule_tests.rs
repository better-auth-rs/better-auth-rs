#![expect(
    clippy::expect_used,
    reason = "Required fixture operations must succeed before comparing the contract."
)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "The paired contract checks original errors, retained query peers, request context, and complete storage"
)]

use super::*;
use crate::hooks::{
    RequestHookContext, current_request_hook_context, with_request_hook_context_value,
};
use crate::organization_fields::OrganizationFields;
use crate::store::RuntimeStore;
use crate::user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform};
use crate::{AuthRecordFields, FieldObject, field_value::FieldObjectSource};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Notify;

type Trace = Arc<Mutex<Vec<String>>>;

fn record(trace: &Trace, event: impl Into<String>) -> AuthResult<()> {
    trace
        .lock()
        .map_err(|_| AuthError::internal("Member query trace lock poisoned"))?
        .push(event.into());
    Ok(())
}

fn snapshot(store: &EphemeralStore) -> AuthResult<Vec<Vec<FieldMap>>> {
    [
        EntityRole::User,
        EntityRole::Session,
        EntityRole::Account,
        EntityRole::Verification,
        EntityRole::Organization,
        EntityRole::Member,
        EntityRole::Invitation,
        EntityRole::Team,
        EntityRole::TeamMember,
        EntityRole::OrganizationRole,
    ]
    .into_iter()
    .map(|role| store.storage_rows(role))
    .collect()
}

fn check_context(marker: &Value) -> AuthResult<()> {
    let context = current_request_hook_context()
        .ok_or_else(|| AuthError::internal("Retained Member peer lost its request context"))?;
    assert_eq!(context.path.as_deref(), Some("/organization/list-members"));
    assert_eq!(
        context.headers.get("x-contract").map(String::as_str),
        Some("member-query-peer")
    );
    assert!(context.body.strict_equals(marker));
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    Success,
    PageError,
    CountError,
    BothErrors,
}

struct Operand {
    trace: Trace,
    marker: Value,
    reads: AtomicUsize,
    case: Case,
    mutation: Option<EphemeralStore>,
}

impl FieldObjectSource for Operand {
    fn own_property_descriptor(
        &self,
        _: &str,
    ) -> AuthResult<Option<crate::field_value::FieldPropertyDescriptor>> {
        Ok(None)
    }

    fn own_keys(&self) -> AuthResult<Vec<String>> {
        Err(AuthError::internal(
            "Member query must not enumerate its operand",
        ))
    }

    fn get_with_receiver(&self, name: &str, _receiver: &Value) -> AuthResult<Option<Value>> {
        if name == "toString" {
            check_context(&self.marker)?;
            let read = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
            record(&self.trace, format!("get-{read}"))?;
            if read == 1
                && let Some(store) = &self.mutation
            {
                store.operation(|op| {
                    let row = op
                        .capture_table(EntityRole::Member)?
                        .select_refs(|row| {
                            Ok(row.field("id")?.as_ref().and_then(Value::as_str)
                                == Some("following-member"))
                        })?
                        .into_iter()
                        .next()
                        .ok_or_else(|| AuthError::internal("Expected following Member"))?;
                    row.set_field("role".into(), "zz".into())?;
                    Ok(())
                })?;
            }
            if read == 1 && matches!(self.case, Case::PageError | Case::BothErrors) {
                return Err(AuthError::internal("member-page-original"));
            }
            if read == 2 && matches!(self.case, Case::CountError | Case::BothErrors) {
                return Err(AuthError::internal("member-count-original"));
            }
        }
        Ok(None)
    }
    fn set_with_receiver(&self, _: String, _: Value, _: &Value) -> AuthResult<bool> {
        Err(AuthError::internal(
            "Member query must not mutate its operand",
        ))
    }

    fn define_own_property(
        &self,
        _: String,
        _: crate::field_value::FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        Err(AuthError::internal(
            "Member query must not mutate its operand",
        ))
    }
    fn delete(&self, _: &str) -> AuthResult<bool> {
        Err(AuthError::internal(
            "Member query must not delete operand properties",
        ))
    }
    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "Member query must not snapshot its operand",
        ))
    }
    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }
}

fn visible(role: &str) -> FieldMap {
    FieldMap::from_iter([
        ("organizationId".into(), "organization".into()),
        ("userId".into(), "user-b".into()),
        ("role".into(), role.into()),
        (
            "createdAt".into(),
            crate::FieldDate::from_milliseconds(1_893_456_000_000.0).into(),
        ),
        ("id".into(), "schedule-member".into()),
    ])
}

#[tokio::test]
async fn member_page_and_count_scan_independently_and_retain_started_output_after_count_error()
-> AuthResult<()> {
    for case in [
        Case::Success,
        Case::PageError,
        Case::CountError,
        Case::BothErrors,
    ] {
        let writer = EphemeralStore::default();
        let _ = writer
            .insert_member(<Member as crate::FromFieldMap>::from_field_values(
                visible("z"),
            )?)
            .await?;
        let mut before = snapshot(&writer)?;
        let trace = Trace::default();
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let completed = Arc::new(Notify::new());
        let marker: Value =
            FieldMap::from_iter([("identity".into(), "retained-body".into())]).into();
        let mut context = RequestHookContext::from_request(&crate::AuthRequest::new(
            crate::HttpMethod::Get,
            "/organization/list-members",
        ))?;
        let _ = context
            .headers
            .insert("x-contract".into(), "member-query-peer".into());
        context.body = marker.clone();
        let source = Arc::new(Operand {
            trace: trace.clone(),
            marker: marker.clone(),
            reads: AtomicUsize::new(0),
            case,
            mutation: None,
        });
        let store = writer.with_runtime(
            Arc::new(AuthConfig::default()),
            Vec::new(),
            Default::default(),
        )?;
        let mut fields = OrganizationFields::default();
        let _ = fields.member.fields_mut().insert(
            "role".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(|_| {
                        Err(AuthError::internal("query-input-must-not-run"))
                    })),
                    output: Some(UserFieldTransform::new_async({
                        let trace = trace.clone();
                        let started = started.clone();
                        let release = release.clone();
                        let completed = completed.clone();
                        let writer = writer.clone();
                        let marker = marker.clone();
                        move |value| {
                            let (trace, started, release, completed, writer, marker) = (
                                trace.clone(),
                                started.clone(),
                                release.clone(),
                                completed.clone(),
                                writer.clone(),
                                marker.clone(),
                            );
                            async move {
                                check_context(&marker)?;
                                assert_eq!(value, Value::from("z"));
                                record(&trace, "output-start")?;
                                started.notify_one();
                                if case == Case::CountError {
                                    release.notified().await;
                                    check_context(&marker)?;
                                    let _ = writer
                                        .update_member_role("schedule-member", "after-error")
                                        .await?;
                                }
                                record(&trace, "output-end")?;
                                completed.notify_one();
                                Ok("z:visible".into())
                            }
                        }
                    })),
                }),
                ..Default::default()
            },
        );
        store.configure_organization_fields(fields)?;
        let params = ListOrganizationMembersParams {
            organization_id: "organization".into(),
            filter_field: Some("role".into()),
            filter_operator: Some("gt".into()),
            filter_value: Some(Value::Object(FieldObject::from_source(source.clone()))),
            ..Default::default()
        };
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            with_request_hook_context_value(context, store.query_organization_members(&params)),
        )
        .await
        .expect("Member query must return before the retained output gate opens");
        assert!(current_request_hook_context().is_none());
        assert_eq!(source.reads.load(Ordering::SeqCst), 2, "{case:?}");
        match case {
            Case::Success => {
                let (rows, total) = result?;
                assert_eq!(total, 1);
                assert_eq!(
                    rows.iter()
                        .map(AuthRecordFields::field_values)
                        .collect::<AuthResult<Vec<_>>>()?,
                    [visible("z:visible")]
                );
            }
            Case::PageError | Case::BothErrors => {
                assert!(
                    matches!(result, Err(AuthError::Internal(message)) if message == "member-page-original")
                );
            }
            Case::CountError => {
                assert!(
                    matches!(result, Err(AuthError::Internal(message)) if message == "member-count-original")
                );
                assert_eq!(snapshot(&writer)?, before);
                tokio::time::timeout(std::time::Duration::from_secs(5), started.notified())
                    .await
                    .expect("Started page must reach its output callback after the count error");
                release.notify_one();
                tokio::time::timeout(std::time::Duration::from_secs(5), completed.notified())
                    .await
                    .expect("Retained page must finish its callback after the caller exits");
                let member = before
                    .get_mut(5)
                    .and_then(|rows| rows.first_mut())
                    .ok_or_else(|| AuthError::internal("Expected Member snapshot"))?;
                let _ = member.insert("role".into(), "after-error".into());
            }
        }
        let expected: &[&str] = if matches!(case, Case::PageError | Case::BothErrors) {
            &["get-1", "get-2"]
        } else {
            &["get-1", "get-2", "output-start", "output-end"]
        };
        assert_eq!(
            *trace
                .lock()
                .map_err(|_| AuthError::internal("Member query trace lock poisoned"))?,
            expected
        );
        assert_eq!(snapshot(&writer)?, before, "{case:?}");
    }
    Ok(())
}

#[tokio::test]
async fn member_predicate_reads_following_rows_after_a_getter_mutates_their_storage()
-> AuthResult<()> {
    let writer = EphemeralStore::default();
    let first = visible("z");
    let mut following = visible("A");
    let _ = following.insert("id".into(), "following-member".into());
    let _ = following.insert("userId".into(), "user-following".into());
    for fields in [first.clone(), following.clone()] {
        let _ = writer
            .insert_member(<Member as crate::FromFieldMap>::from_field_values(fields)?)
            .await?;
    }
    let mut expected_storage = snapshot(&writer)?;
    let rows = expected_storage
        .get_mut(5)
        .ok_or_else(|| AuthError::internal("Expected Member snapshot"))?;
    let row = rows
        .iter_mut()
        .find(|row| row.get("id").and_then(Value::as_str) == Some("following-member"))
        .ok_or_else(|| AuthError::internal("Expected following Member snapshot"))?;
    let _ = row.insert("role".into(), "zz".into());
    let _ = following.insert("role".into(), "zz".into());
    let trace = Trace::default();
    let marker: Value = FieldMap::from_iter([("identity".into(), "retained-body".into())]).into();
    let mut context = RequestHookContext::from_request(&crate::AuthRequest::new(
        crate::HttpMethod::Get,
        "/organization/list-members",
    ))?;
    let _ = context
        .headers
        .insert("x-contract".into(), "member-query-peer".into());
    context.body = marker.clone();
    let source = Arc::new(Operand {
        trace: trace.clone(),
        marker: marker.clone(),
        reads: AtomicUsize::new(0),
        case: Case::Success,
        mutation: Some(writer.clone()),
    });
    let store = writer.with_runtime(
        Arc::new(AuthConfig::default()),
        Vec::new(),
        Default::default(),
    )?;
    let mut fields = OrganizationFields::default();
    let _ = fields.member.fields_mut().insert(
        "role".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(|_| {
                    Err(AuthError::internal("query-input-must-not-run"))
                })),
                output: Some(UserFieldTransform::new({
                    let trace = trace.clone();
                    move |value| {
                        check_context(&marker)?;
                        let text = value
                            .as_str()
                            .ok_or_else(|| AuthError::internal("Expected projected Member role"))?;
                        record(&trace, format!("output:{text}"))?;
                        Ok(value)
                    }
                })),
            }),
            ..Default::default()
        },
    );
    store.configure_organization_fields(fields)?;
    let params = ListOrganizationMembersParams {
        organization_id: "organization".into(),
        filter_field: Some("role".into()),
        filter_operator: Some("gt".into()),
        filter_value: Some(Value::Object(FieldObject::from_source(source.clone()))),
        ..Default::default()
    };
    let (rows, total) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        with_request_hook_context_value(context, store.query_organization_members(&params)),
    )
    .await
    .expect("Getter mutation must run outside Member storage locks")?;
    assert_eq!(total, 2);
    assert_eq!(
        rows.iter()
            .map(AuthRecordFields::field_values)
            .collect::<AuthResult<Vec<_>>>()?,
        [first, following]
    );
    assert_eq!(source.reads.load(Ordering::SeqCst), 4);
    assert_eq!(
        *trace
            .lock()
            .map_err(|_| AuthError::internal("Member query trace lock poisoned"))?,
        ["get-1", "get-2", "get-3", "get-4", "output:z", "output:zz"]
    );
    assert_eq!(snapshot(&writer)?, expected_storage);
    Ok(())
}
