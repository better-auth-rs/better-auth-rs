#![expect(
    clippy::panic_in_result_fn,
    reason = "The paired contract asserts property-read order, original errors, complete results, and unchanged storage"
)]

use crate::{
    AuthConfig, AuthError, AuthResult, CreateUser, FieldDate, FieldMap, FieldObject, FieldValue,
    ListUsersParams,
    field_value::FieldObjectSource,
    store::{
        AuthStore, EphemeralStore, RuntimeStore, StatelessSchema, UserStore, schema::EntityRole,
    },
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

type Trace = Arc<Mutex<Vec<&'static str>>>;

fn record(trace: &Trace, event: &'static str) -> AuthResult<()> {
    trace
        .lock()
        .map_err(|_| AuthError::internal("Memory query trace lock poisoned"))?
        .push(event);
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

struct ObservedOperand {
    trace: Trace,
    reads: AtomicUsize,
    reject_second: bool,
}

impl FieldObjectSource for ObservedOperand {
    fn own_property_descriptor(
        &self,
        _: &str,
    ) -> AuthResult<Option<crate::field_value::FieldPropertyDescriptor>> {
        Ok(None)
    }

    fn own_keys(&self) -> AuthResult<Vec<String>> {
        Err(AuthError::internal(
            "The query must not enumerate its operand",
        ))
    }

    fn get_with_receiver(
        &self,
        name: &str,
        _receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        if name == "toString" {
            record(&self.trace, "get toString")?;
            let read = self.reads.fetch_add(1, Ordering::SeqCst);
            if self.reject_second && read == 1 {
                return Err(AuthError::internal("second-property-read-original"));
            }
        }
        // Absence selects the built-in object string conversion without calling an application method.
        Ok(None)
    }

    fn set_with_receiver(&self, _: String, _: FieldValue, _: &FieldValue) -> AuthResult<bool> {
        Err(AuthError::internal("The query must not write its operand"))
    }

    fn define_own_property(
        &self,
        _: String,
        _: crate::field_value::FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        Err(AuthError::internal("The query must not write its operand"))
    }

    fn delete(&self, _: &str) -> AuthResult<bool> {
        Err(AuthError::internal(
            "The query must not delete operand properties",
        ))
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "The query must not snapshot its operand",
        ))
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }
}

async fn reader(
    trace: &Trace,
) -> AuthResult<(EphemeralStore, Arc<dyn AuthStore<StatelessSchema>>)> {
    let writer = EphemeralStore::new(Arc::new(AuthConfig::default()));
    let _ = writer
        .create_user(CreateUser {
            id: Some("seed".into()),
            created_at: Some(FieldDate::from_milliseconds(1_893_456_001_000.0)),
            updated_at: Some(FieldDate::from_milliseconds(1_893_456_001_000.0)),
            ..CreateUser::new()
                .with_name("Middle")
                .with_email("seed@memory-where.test")
        })
        .await?;
    let input = trace.clone();
    let output = trace.clone();
    let mut config = AuthConfig::default();
    let _ = config.user.fields_mut().insert(
        "name".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    record(&input, "input")?;
                    Ok(value)
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    record(&output, "output")?;
                    Ok(value)
                })),
            }),
            ..Default::default()
        },
    );
    let store = writer.with_runtime(Arc::new(config), Vec::new(), Default::default())?;
    Ok((writer, store))
}

#[tokio::test]
async fn memory_user_repeats_first_clause_property_reads_before_projection_and_count()
-> AuthResult<()> {
    for reject_second in [false, true] {
        let trace = Trace::default();
        let (writer, store) = reader(&trace).await?;
        let before = snapshot(&writer)?;
        let source = Arc::new(ObservedOperand {
            trace: trace.clone(),
            reads: AtomicUsize::new(0),
            reject_second,
        });
        let operand = FieldValue::Object(FieldObject::from_source(source));
        let result = store
            .list_users(ListUsersParams {
                filter_field: Some("name".into()),
                filter_operator: Some("gt".into()),
                filter_value: Some(operand),
                ..Default::default()
            })
            .await;
        let events = std::mem::take(
            &mut *trace
                .lock()
                .map_err(|_| AuthError::internal("Memory query trace lock poisoned"))?,
        );
        if reject_second {
            assert!(
                matches!(&result, Err(AuthError::Internal(message)) if message == "second-property-read-original"),
                "{result:?}"
            );
            assert_eq!(events, ["get toString", "get toString"]);
        } else {
            assert_eq!(result?, (Vec::new(), 0));
            assert_eq!(
                events,
                [
                    "get toString",
                    "get toString",
                    "get toString",
                    "get toString"
                ]
            );
        }
        assert_eq!(snapshot(&writer)?, before);
    }
    Ok(())
}

#[tokio::test]
async fn memory_user_callable_clauses_preserve_repetition_and_original_errors() -> AuthResult<()> {
    for reject_second in [false, true] {
        let trace = Trace::default();
        let (writer, store) = reader(&trace).await?;
        let before = snapshot(&writer)?;
        let message = String::from("second-comparison-original");
        let original = message.as_ptr() as usize;
        let failure = Mutex::new(Some(message));
        let calls = AtomicUsize::new(0);
        let events = trace.clone();
        let operand = FieldMap::from([(
            "toString".into(),
            crate::FieldFunction::contextual(move |receiver, arguments| {
                assert!(matches!(receiver, FieldValue::Object(_)));
                assert!(arguments.is_empty());
                record(&events, "toString")?;
                let call = calls.fetch_add(1, Ordering::SeqCst);
                if reject_second && call == 1 {
                    return Err(AuthError::internal(
                        failure
                            .lock()
                            .map_err(|_| AuthError::internal("Memory query error lock poisoned"))?
                            .take()
                            .ok_or_else(|| {
                                AuthError::internal("Original error already returned")
                            })?,
                    ));
                }
                Ok(if call == 0 { "A" } else { "Z" }.into())
            })
            .into(),
        )]);
        let result = store
            .list_users(ListUsersParams {
                filter_field: Some("name".into()),
                filter_operator: Some("gt".into()),
                filter_value: Some(operand.into()),
                ..Default::default()
            })
            .await;
        let events = std::mem::take(
            &mut *trace
                .lock()
                .map_err(|_| AuthError::internal("Memory query trace lock poisoned"))?,
        );
        if reject_second {
            assert!(
                matches!(result, Err(AuthError::Internal(message)) if message.as_ptr() as usize == original)
            );
            assert_eq!(events, ["toString", "toString"]);
        } else {
            assert_eq!(result?, (Vec::new(), 0));
            assert_eq!(events, ["toString", "toString", "toString", "toString"]);
        }
        assert_eq!(snapshot(&writer)?, before);
    }
    Ok(())
}
