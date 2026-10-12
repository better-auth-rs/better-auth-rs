#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "The reviver contracts assert sparse properties, callback timing, and original error identity."
)]

use super::*;
use crate::{FieldArray, FieldFunction, FieldObject};

#[path = "native_contract.rs"]
mod native_contract;

#[test]
fn native_revival_preserves_holes_and_uses_overridden_map_results() -> AuthResult<()> {
    let sparse = FieldArray::with_length(3);
    sparse.set(1, "2030-01-02T03:04:05.000Z".into())?;
    let revived = safe_parse_field(&sparse.into())?;
    let array = revived
        .as_array()
        .ok_or_else(|| AuthError::internal("Revived array is absent"))?;
    assert_eq!(array.len()?, 3);
    assert_eq!(array.own_indices()?, [1]);
    assert!(array.get(1)?.is_some_and(|value| value.as_date().is_some()));

    let expected: FieldValue = FieldMap::from([("nativeResult".into(), true.into())]).into();
    let result = expected.clone();
    let original = FieldArray::new();
    let receiver = original.clone();
    original.properties().set(
        "map",
        FieldFunction::contextual(move |value, arguments| {
            assert!(value.strict_equals(&receiver.clone().into()));
            assert_eq!(arguments.len(), 1);
            let Some(FieldValue::Function(revive)) = arguments.first() else {
                return Err(AuthError::internal("Date reviver callback is absent"));
            };
            assert!(
                revive
                    .call_with(&FieldValue::Undefined, &["2030-01-02T03:04:05.000Z".into()])?
                    .as_date()
                    .is_some()
            );
            Ok(result.clone())
        })
        .into(),
    )?;
    assert!(safe_parse_field(&original.clone().into())?.strict_equals(&expected));
    let _ = original.properties().delete("map")?;
    Ok(())
}

#[test]
fn native_revival_reads_later_object_fields_after_recursive_callbacks() -> AuthResult<()> {
    let object: FieldObject = FieldMap::new().into();
    let child = FieldArray::new();
    let original = object.clone();
    child.properties().set(
        "map",
        FieldFunction::contextual(move |_, _| {
            original.set("tail", "after".into())?;
            Ok(FieldValue::Undefined)
        })
        .into(),
    )?;
    object.set("child", child.clone().into())?;
    object.set("tail", "before".into())?;
    let revived = safe_parse_field(&object.clone().into())?;
    assert_eq!(
        revived.enumerable_fields()?,
        FieldMap::from([
            ("child".into(), FieldValue::Undefined),
            ("tail".into(), "after".into()),
        ])
    );
    assert!(!revived.strict_equals(&object.clone().into()));
    let _ = child.properties().delete("map")?;
    Ok(())
}

#[tokio::test]
async fn native_revival_catches_original_callback_errors_and_logs_the_error_property()
-> AuthResult<()> {
    use crate::observability::{LogArgument, LogLevel, LogSink};
    use crate::{AuthConfig, AuthContext, store::EphemeralStore};

    type Logs = Arc<parking_lot::Mutex<Vec<(LogLevel, String, Vec<Option<FieldValue>>)>>>;
    struct Sink(Logs);
    impl LogSink for Sink {
        fn log(
            &self,
            level: LogLevel,
            message: LogArgument<'_>,
            arguments: &[LogArgument<'_>],
        ) -> crate::AuthResult<()> {
            self.0.lock().push((
                level,
                message.to_string(),
                arguments
                    .iter()
                    .map(|argument| match argument {
                        LogArgument::Native(value) => Some((*value).clone()),
                        _ => None,
                    })
                    .collect(),
            ));
            Ok(())
        }
    }
    let original: FieldValue = FieldMap::from([("original".into(), true.into())]).into();
    let thrown = original.clone();
    let input = FieldArray::new();
    input.properties().set(
        "map",
        FieldFunction::contextual(move |_, _| Err(AuthError::from_thrown(thrown.clone()))).into(),
    )?;
    let logs = Logs::default();
    let mut config = AuthConfig::default();
    {
        let crate::LoggerSource::Config(logger_options) = &mut config.logger else {
            #[allow(
                clippy::panic,
                clippy::panic_in_result_fn,
                reason = "The fixture modifies its existing authored logger options."
            )]
            {
                panic!("fixture requires authored logger options");
            }
        };
        logger_options.log = Some(Arc::new(Sink(logs.clone())));
    }
    config
        .initialize_logger()
        .expect("fixture initialization succeeds");
    let config = Arc::new(config);
    let context = AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config)))
        .expect("fixture context initializes");
    let parsed = context
        .with_endpoint_context(|_| async { safe_parse_field(&input.into()) })
        .await?;
    assert!(parsed.is_null());
    let logs = logs.lock();
    assert_eq!(logs.len(), 1);
    let (level, message, arguments) = logs
        .first()
        .ok_or_else(|| AuthError::internal("Parser log is absent"))?;
    assert_eq!(*level, LogLevel::Error);
    assert_eq!(message, "Error parsing JSON");
    assert_eq!(arguments.len(), 1);
    let argument = arguments
        .first()
        .and_then(Option::as_ref)
        .ok_or_else(|| AuthError::internal("Parser error argument is absent"))?;
    assert_eq!(
        argument.enumerable_fields()?.keys().collect::<Vec<_>>(),
        ["error"]
    );
    assert!(argument.model_property("error")?.strict_equals(&original));
    Ok(())
}
