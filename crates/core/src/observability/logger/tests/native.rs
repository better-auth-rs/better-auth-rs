use super::*;
use crate::{
    FieldFunction, FieldMap,
    field_value::{FieldObjectSource, FieldPropertyDescriptor},
};
use std::sync::atomic::{AtomicUsize, Ordering};

type Getter = dyn Fn(&str, &FieldValue) -> AuthResult<Option<FieldValue>> + Send + Sync;

#[test]
fn borrowed_thrown_messages_preserve_conversion_failure_before_the_sink() -> AuthResult<()> {
    let conversions = Arc::new(AtomicUsize::new(0));
    let replacement: FieldValue = FieldMap::new().into();
    let cause = replacement.clone();
    let observed = conversions.clone();
    let raw: FieldValue = FieldMap::from([(
        "toString".into(),
        FieldFunction::contextual(move |_, _| {
            observed.fetch_add(1, Ordering::SeqCst);
            Err(AuthError::from_thrown(cause.clone()))
        })
        .into(),
    )])
    .into();
    let sink = Arc::new(Capture::default());
    let logger = Logger::new(LoggerConfig {
        log: Some(sink.clone()),
        ..Default::default()
    })?;
    let borrowed = AuthError::from_thrown(raw.clone());
    for message in [LogArgument::Native(&raw), LogArgument::Error(&borrowed)] {
        let error = logger
            .log(LogLevel::Error, message, &[])
            .expect_err("message conversion throws");
        assert!(
            error
                .raw_value()
                .expect("raw replacement is retained")
                .strict_equals(&replacement)
        );
    }
    assert_eq!(conversions.load(Ordering::SeqCst), 2);
    assert!(sink.0.lock().expect("capture remains readable").is_empty());
    Ok(())
}

struct Probe {
    fields: FieldObject,
    read: Box<Getter>,
}

impl Probe {
    fn object(
        read: impl Fn(&str, &FieldValue) -> AuthResult<Option<FieldValue>> + Send + Sync + 'static,
    ) -> FieldObject {
        FieldObject::from_source(Arc::new(Self {
            fields: FieldMap::new().into(),
            read: Box::new(read),
        }))
    }
}

impl FieldObjectSource for Probe {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        self.fields.own_keys()
    }

    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        self.fields.own_property_descriptor(name)
    }

    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        (self.read)(name, receiver)
    }

    fn set_with_receiver(
        &self,
        name: String,
        value: FieldValue,
        receiver: &FieldValue,
    ) -> AuthResult<bool> {
        self.fields.set_with_receiver(&name, value, receiver)
    }

    fn delete(&self, name: &str) -> AuthResult<bool> {
        self.fields.delete(name)
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        self.fields.snapshot_fields()
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }

    fn define_own_property(
        &self,
        name: String,
        definition: crate::FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        self.fields.define_own_property(name, definition)
    }
}

#[test]
fn native_getters_keep_source_order_and_use_the_second_callback_with_its_owner() -> AuthResult<()> {
    let events = Arc::new(Mutex::new(Vec::<String>::new()));
    let log_reads = Arc::new(AtomicUsize::new(0));
    let color_reads = Arc::new(AtomicUsize::new(0));
    let invocation = Arc::new(Mutex::new(None));
    let callback: FieldValue = FieldFunction::contextual({
        let events = events.clone();
        let invocation = invocation.clone();
        move |receiver, arguments| {
            events
                .lock()
                .expect("events are readable")
                .push("call".into());
            *invocation.lock().expect("invocation is writable") =
                Some((receiver.clone(), arguments.to_vec()));
            Ok(FieldValue::Undefined)
        }
    })
    .into();
    let wrong_callback: FieldValue =
        FieldFunction::contextual(|_, _| panic!("the function read by typeof must not be cached"))
            .into();
    let options = Probe::object({
        let events = events.clone();
        let log_reads = log_reads.clone();
        let color_reads = color_reads.clone();
        move |name, _| {
            events
                .lock()
                .expect("events are writable")
                .push(name.into());
            Ok(Some(match name {
                "disabled" => "truthy but not true".into(),
                "level" => "unrecognized".into(),
                "disableColors" => {
                    if color_reads.fetch_add(1, Ordering::SeqCst) == 0 {
                        true.into()
                    } else {
                        FieldValue::Null
                    }
                }
                "log" => {
                    if log_reads.fetch_add(1, Ordering::SeqCst) == 0 {
                        wrong_callback.clone()
                    } else {
                        callback.clone()
                    }
                }
                _ => FieldValue::Undefined,
            }))
        }
    });
    let logger = Logger::new(options.clone())?;
    assert!(logger.level().strict_equals(&"unrecognized".into()));
    assert!(logger.0.policy.colors_enabled);
    let message: FieldValue = FieldMap::from([(
        "toString".into(),
        FieldFunction::contextual({
            let events = events.clone();
            move |_, _| {
                events
                    .lock()
                    .expect("events are writable")
                    .push("message".into());
                Ok("converted".into())
            }
        })
        .into(),
    )])
    .into();
    let argument: FieldValue = FieldMap::from([("retained".into(), true.into())]).into();
    logger.log(
        LogLevel::Success,
        LogArgument::Native(&message),
        &[LogArgument::Native(&argument)],
    )?;
    assert_eq!(
        events.lock().expect("events are readable").as_slice(),
        [
            "disabled",
            "level",
            "disableColors",
            "disableColors",
            "message",
            "log",
            "log",
            "call",
        ]
    );
    let (receiver, arguments) = invocation
        .lock()
        .expect("invocation is readable")
        .take()
        .expect("callback ran");
    assert!(receiver.strict_equals(&options.into()));
    assert_eq!(arguments.len(), 3);
    assert!(arguments[0].strict_equals(&"info".into()));
    assert!(arguments[1].strict_equals(&message));
    assert!(arguments[2].strict_equals(&argument));
    Ok(())
}

#[test]
fn original_native_owner_remains_live_after_replacement_and_a_throwing_callback() -> AuthResult<()>
{
    let records = Arc::new(Mutex::new(Vec::new()));
    let sink = |name: &'static str| {
        let records = records.clone();
        FieldFunction::contextual(move |receiver, arguments| {
            records.lock().expect("records are writable").push((
                name,
                receiver.clone(),
                arguments.to_vec(),
            ));
            Ok(FieldValue::Undefined)
        })
    };
    let original: FieldObject = FieldMap::from([
        ("level".into(), "error".into()),
        ("disableColors".into(), true.into()),
        ("log".into(), sink("first").into()),
    ])
    .into();
    let replacement: FieldObject =
        FieldMap::from([("log".into(), sink("replacement").into())]).into();
    let mut source = LoggerSource::from(original.clone());
    let logger = Logger::new(source.clone())?;
    logger.error("before", &[])?;
    source = replacement.clone().into();
    logger.error("after replacement", &[])?;
    let failure: FieldValue = FieldMap::from([("failure".into(), true.into())]).into();
    original.set(
        "log",
        FieldFunction::contextual({
            let failure = failure.clone();
            move |_, _| Err(AuthError::from_thrown(failure.clone()))
        })
        .into(),
    )?;
    let error = logger.error("throwing", &[]).expect_err("sink fails");
    assert!(
        error
            .raw_value()
            .expect("native failure retained")
            .strict_equals(&failure)
    );
    original.set("log", sink("second").into())?;
    logger.error("after failure", &[])?;
    Logger::new(source)?.error("new instance", &[])?;
    original.delete("log")?;
    logger.error("default sink after deletion", &[])?;
    let records = std::mem::take(&mut *records.lock().expect("records are readable"));
    assert_eq!(
        records.iter().map(|(name, _, _)| *name).collect::<Vec<_>>(),
        ["first", "first", "second", "replacement"]
    );
    for (_, owner, _) in &records[..3] {
        assert!(owner.strict_equals(&original.clone().into()));
    }
    assert!(records[3].1.strict_equals(&replacement.into()));
    assert_eq!(
        records
            .iter()
            .map(|(_, _, args)| args[1].clone())
            .collect::<Vec<_>>(),
        [
            "before".into(),
            "after replacement".into(),
            "after failure".into(),
            "new instance".into(),
        ]
    );
    Ok(())
}

#[test]
fn native_policy_is_frozen_but_new_binding_uses_current_properties() -> AuthResult<()> {
    let records = Arc::new(AtomicUsize::new(0));
    let sink: FieldValue = FieldFunction::contextual({
        let records = records.clone();
        move |_, _| {
            records.fetch_add(1, Ordering::SeqCst);
            Ok(FieldValue::Undefined)
        }
    })
    .into();
    let options: FieldObject = FieldMap::from([
        ("disabled".into(), true.into()),
        ("level".into(), "error".into()),
        ("disableColors".into(), false.into()),
        ("log".into(), sink),
    ])
    .into();
    let disabled = Logger::new(options.clone())?;
    options.set("disabled", false.into())?;
    let error_level = Logger::new(options.clone())?;
    options.set("level", "warn".into())?;
    options.set("disableColors", true.into())?;
    disabled.error("still disabled", &[])?;
    error_level.warn("still filtered", &[])?;
    error_level.error("existing", &[])?;
    let updated = Logger::new(options.clone())?;
    updated.warn("new", &[])?;
    assert_eq!(records.load(Ordering::SeqCst), 2);
    assert!(error_level.level().strict_equals(&"error".into()));
    assert!(updated.level().strict_equals(&"warn".into()));
    assert!(error_level.prefix(LogLevel::Error).contains('\u{1b}'));
    assert!(!updated.prefix(LogLevel::Error).contains('\u{1b}'));
    for value in [FieldValue::Null, FieldValue::Undefined] {
        options.set("level", value)?;
        assert!(
            Logger::new(options.clone())?
                .level()
                .strict_equals(&"warn".into())
        );
    }
    Ok(())
}

#[test]
fn filtered_emission_skips_message_conversion_and_callback_property_access() -> AuthResult<()> {
    let options = Probe::object(|name, _| match name {
        "level" => Ok(Some("error".into())),
        "log" => panic!("filtered events must not read the callback"),
        _ => Ok(None),
    });
    let message: FieldValue = FieldMap::from([(
        "toString".into(),
        FieldFunction::contextual(|_, _| panic!("filtered events must not format the message"))
            .into(),
    )])
    .into();
    Logger::new(options)?.log(LogLevel::Warn, LogArgument::Native(&message), &[])
}

#[test]
fn second_callback_getter_error_preserves_its_native_identity() -> AuthResult<()> {
    let failure: FieldValue = FieldMap::new().into();
    let reads = Arc::new(AtomicUsize::new(0));
    let options = Probe::object({
        let failure = failure.clone();
        let reads = reads.clone();
        move |name, _| {
            if name != "log" {
                return Ok(None);
            }
            if reads.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(Some(
                    FieldFunction::contextual(|_, _| panic!("first callback is not invoked"))
                        .into(),
                ))
            } else {
                Err(AuthError::from_thrown(failure.clone()))
            }
        }
    });
    let error = Logger::new(options)?
        .error("message", &[])
        .expect_err("second getter fails");
    assert!(
        error
            .raw_value()
            .expect("getter failure retained")
            .strict_equals(&failure)
    );
    assert_eq!(reads.load(Ordering::SeqCst), 2);
    Ok(())
}

#[test]
fn telemetry_reads_raw_values_in_order_and_treats_nonfunction_log_as_truthy() -> AuthResult<()> {
    let reads = Arc::new(Mutex::new(Vec::new()));
    let options = Probe::object({
        let reads = reads.clone();
        move |name, _| {
            reads
                .lock()
                .expect("reads are writable")
                .push(name.to_owned());
            Ok(Some(match name {
                "disabled" => FieldValue::Null,
                "level" => "unknown".into(),
                "log" => FieldMap::new().into(),
                _ => FieldValue::Undefined,
            }))
        }
    });
    let source = LoggerSource::from(options);
    assert_eq!(
        source.telemetry_options()?,
        FieldMap::from([
            ("disabled".into(), FieldValue::Null),
            ("level".into(), "unknown".into()),
            ("log".into(), true.into()),
        ])
    );
    assert_eq!(
        reads.lock().expect("reads are readable").as_slice(),
        ["disabled", "level", "log"]
    );
    let logger = Logger::new(source)?;
    logger.debug("truthy nonfunction falls back to default", &[])?;
    assert!(logger.enabled(LogLevel::Debug));
    Ok(())
}
