use super::*;
use crate::FieldFunction;
use std::sync::atomic::AtomicUsize;

#[tokio::test]
async fn message_methods_receive_native_receiver_and_truthy_return_values() -> AuthResult<()> {
    for callable in [true, false] {
        let events = Events::default();
        let payload: FieldValue =
            FieldMap::from([("message".into(), "native logger message".into())]).into();
        let receiver = FieldObject::from(FieldMap::new());
        let includes = if callable {
            FieldFunction::contextual({
                let events = events.clone();
                let receiver = receiver.clone();
                move |value, arguments| {
                    assert!(value.strict_equals(&receiver.clone().into()));
                    assert_eq!(arguments, [FieldValue::from("no column")]);
                    events.lock().unwrap().push("includes:no column".into());
                    Ok(FieldMap::from([("matched".into(), true.into())]).into())
                }
            })
            .into()
        } else {
            42.0.into()
        };
        receiver.set("includes", includes)?;
        let fields: FieldObject = FieldMap::from([
            ("name".into(), "RuntimeFailure".into()),
            ("message".into(), FieldValue::Undefined),
        ])
        .into();
        let logging = Arc::new(AtomicBool::new(false));
        let cause = Probe::value(
            fields.clone(),
            {
                let logging = logging.clone();
                let fields = fields.clone();
                move |name| {
                    if name == "message" {
                        logging.store(true, Ordering::Relaxed);
                    }
                    fields.has_property(name)
                }
            },
            {
                let events = events.clone();
                let payload = payload.clone();
                let receiver = receiver.clone();
                let reads = AtomicUsize::new(0);
                let logger_reads = AtomicUsize::new(0);
                move |name| {
                    if name != "message" {
                        return fields.get(name);
                    }
                    let count = reads.fetch_add(1, Ordering::Relaxed) + 1;
                    events.lock().unwrap().push(format!("message:{count}"));
                    if !logging.load(Ordering::Relaxed) {
                        return Ok(Some("ordinary failure".into()));
                    }
                    Ok(Some(match logger_reads.fetch_add(1, Ordering::Relaxed) {
                        0 => "ordinary failure".into(),
                        1 => receiver.clone().into(),
                        _ => payload.clone(),
                    }))
                }
            },
        );
        let harness = Harness::new(cause, &events, false, false);
        let result = harness.run(false).await;
        if callable {
            assert_empty_response(result?)?;
            let logs = harness.logs.records.lock().unwrap();
            let [record] = logs.as_slice() else {
                panic!("The database branch must log one live native message");
            };
            assert_eq!(record.level, LogLevel::Error);
            assert!(record.message.strict_equals(&payload));
            assert!(record.arguments.is_empty());
            assert_eq!(
                *events.lock().unwrap(),
                [
                    "message:1",
                    "message:2",
                    "message:3",
                    "includes:no column",
                    "message:4",
                    "log",
                    "console"
                ]
            );
            assert_eq!(harness.outer_count(), 1);
        } else {
            // Bun includes the source expression in its TypeError; Rust retains its method-call diagnostic.
            assert!(matches!(
                result.unwrap_err(),
                AuthError::TypeError(message) if message == "Error message includes property is not callable"
            ));
            assert!(harness.logs.records.lock().unwrap().is_empty());
            assert_eq!(
                *events.lock().unwrap(),
                ["message:1", "message:2", "message:3"]
            );
            assert_eq!(harness.outer_count(), 0);
        }
        let _ = receiver.delete("includes")?;
    }
    Ok(())
}

#[tokio::test]
async fn native_logger_messages_convert_before_the_sink_and_preserve_conversion_failures()
-> AuthResult<()> {
    for field in ["name", "message"] {
        for failure in [false, true] {
            let events = Events::default();
            let replacement = replacement();
            let payload = FieldObject::from(FieldMap::from([("kind".into(), field.into())]));
            let convert = FieldFunction::contextual({
                let events = events.clone();
                let replacement = replacement.clone();
                let payload = payload.clone();
                move |receiver, arguments| {
                    assert!(receiver.strict_equals(&payload.clone().into()));
                    assert!(arguments.is_empty());
                    events.lock().unwrap().push("to-string".into());
                    if failure {
                        return Err(AuthError::from_thrown(replacement.clone()));
                    }
                    Ok("rendered native message".into())
                }
            });
            payload.set("toString", convert.into())?;
            let fields = FieldObject::from(FieldMap::from([
                (
                    "name".into(),
                    if field == "name" {
                        payload.clone().into()
                    } else {
                        "RuntimeFailure".into()
                    },
                ),
                ("message".into(), FieldValue::Undefined),
            ]));
            let logging = Arc::new(AtomicBool::new(false));
            let cause = Probe::value(
                fields.clone(),
                {
                    let logging = logging.clone();
                    let fields = fields.clone();
                    move |name| {
                        if name == "message" {
                            logging.store(true, Ordering::Relaxed);
                        }
                        fields.has_property(name)
                    }
                },
                {
                    let events = events.clone();
                    let payload = payload.clone();
                    let reads = AtomicUsize::new(0);
                    let logger_reads = AtomicUsize::new(0);
                    move |name| {
                        if name != "message" {
                            return fields.get(name);
                        }
                        let count = reads.fetch_add(1, Ordering::Relaxed) + 1;
                        events.lock().unwrap().push(format!("message:{count}"));
                        Ok(Some(
                            if field == "name" || !logging.load(Ordering::Relaxed) {
                                "ordinary failure".into()
                            } else if logger_reads.fetch_add(1, Ordering::Relaxed) < 2 {
                                "diagnostic: no column".into()
                            } else {
                                payload.clone().into()
                            },
                        ))
                    }
                },
            );
            let harness = Harness::new(cause.clone(), &events, false, false);
            let result = harness.run(false).await;
            let count = if field == "name" { 7 } else { 4 };
            let mut expected: Vec<String> = (1..=count)
                .map(|index| format!("message:{index}"))
                .collect();
            expected.push("to-string".into());
            if failure {
                assert!(
                    result
                        .unwrap_err()
                        .raw_value()
                        .unwrap()
                        .strict_equals(&replacement)
                );
                assert!(harness.logs.records.lock().unwrap().is_empty());
                assert_eq!(harness.outer_count(), 0);
            } else {
                assert_empty_response(result?)?;
                let logs = harness.logs.records.lock().unwrap();
                let [record] = logs.as_slice() else {
                    panic!("The logger must call the sink once after message conversion");
                };
                assert_eq!(record.level, LogLevel::Error);
                assert!(record.message.strict_equals(&payload.clone().into()));
                if field == "name" {
                    let [argument] = record.arguments.as_slice() else {
                        panic!("Ordinary error logging must retain the original error argument");
                    };
                    assert!(argument.strict_equals(&cause));
                } else {
                    assert!(record.arguments.is_empty());
                }
                assert_eq!(harness.outer_count(), 1);
                expected.extend(["log", "console"].map(Into::into));
            }
            assert_eq!(*events.lock().unwrap(), expected, "{field}/{failure}");
            let _ = payload.delete("toString")?;
        }
    }
    Ok(())
}
