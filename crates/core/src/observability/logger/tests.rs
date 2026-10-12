#![expect(
    clippy::indexing_slicing,
    clippy::panic,
    reason = "Fixture indexing must fail when an expected record or property is missing. Unexpected fixture variants and deliberate callback panics must fail or exercise the recorded unwind path."
)]

use super::*;
use std::sync::Mutex;

mod native;
mod recovery;

#[derive(Default)]
struct Capture(Mutex<Vec<(LogLevel, String, Vec<Value>)>>);
impl LogSink for Capture {
    fn log(
        &self,
        level: LogLevel,
        message: LogArgument<'_>,
        arguments: &[LogArgument<'_>],
    ) -> AuthResult<()> {
        let arguments = arguments
            .iter()
            .map(|value| match value {
                LogArgument::Text(value) => Value::String((*value).into()),
                LogArgument::Value(value) => (*value).clone(),
                LogArgument::Native(value) => value
                    .json()
                    .expect("contract logger argument must serialize")
                    .expect("contract logger argument must be JSON-defined"),
                LogArgument::Error(error) => Value::String(error.to_string()),
            })
            .collect();
        self.0.lock().expect("capture mutex is not poisoned").push((
            level,
            message.to_string(),
            arguments,
        ));
        Ok(())
    }
}

#[tokio::test]
async fn instance_snapshot_survives_option_replacement_and_reinitializes_for_new_auth()
-> crate::AuthResult<()> {
    struct ReplaceOptions(crate::AuthConfig);
    #[async_trait::async_trait]
    impl crate::AuthPlugin<crate::store::StatelessSchema> for ReplaceOptions {
        fn name(&self) -> &'static str {
            "replace-logger-options"
        }
        fn routes(&self) -> Vec<crate::AuthRoute> {
            Vec::new()
        }
        async fn on_request(
            &self,
            _: &crate::AuthRequest,
            _: &crate::AuthContext<crate::store::StatelessSchema>,
        ) -> crate::AuthResult<Option<crate::AuthResponse>> {
            Ok(None)
        }
        async fn on_init(
            &self,
            context: &mut crate::AuthInitContext<crate::store::StatelessSchema>,
        ) -> crate::AuthResult<()> {
            context.config = Arc::new(self.0.clone());
            context.logger().error("during initialization", &[])
        }
    }

    for disable_colors in [None, Some(true), Some(false)] {
        let original = Arc::new(Capture::default());
        let replacement = Arc::new(Capture::default());
        let mut options = crate::AuthConfig {
            logger: LoggerConfig {
                disable_colors,
                log: Some(original.clone()),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        };
        options.initialize_logger()?;
        let snapshot = Some(!options.logger()?.0.policy.colors_enabled);
        assert!(snapshot.is_some());
        assert_eq!(
            options.logger.raw_disable_colors()?,
            disable_colors.map_or(FieldValue::Undefined, Into::into),
        );
        let mut next_options = options.clone();
        next_options.logger = LoggerConfig {
            disable_colors: snapshot.map(|value| !value),
            log: Some(replacement.clone()),
            ..Default::default()
        }
        .into();
        let database = Arc::new(crate::store::EphemeralStore::default());
        let mut init = crate::AuthInitContext::new(Arc::new(options), database.clone())?;
        init.initialize_plugin(&ReplaceOptions(next_options))
            .await?;
        assert_eq!(Some(!init.logger().0.policy.colors_enabled), snapshot);
        assert_eq!(
            Some(!init.config.logger()?.0.policy.colors_enabled),
            snapshot
        );
        assert_eq!(
            init.config.logger.raw_disable_colors()?,
            snapshot.map_or(FieldValue::Undefined, |value| (!value).into()),
        );
        let context = crate::AuthContext::new(init.config.clone(), database)?;
        let derived = context.clone();
        derived.logger().error("after initialization", &[])?;
        assert_eq!(Some(!derived.logger().0.policy.colors_enabled), snapshot);
        assert_eq!(
            original
                .0
                .lock()
                .expect("capture mutex is not poisoned")
                .as_slice(),
            [
                (
                    LogLevel::Error,
                    "during initialization".to_owned(),
                    Vec::new()
                ),
                (
                    LogLevel::Error,
                    "after initialization".to_owned(),
                    Vec::new()
                ),
            ]
        );
        assert!(
            replacement
                .0
                .lock()
                .expect("capture mutex is not poisoned")
                .is_empty()
        );
        let mut reused_options = (*init.config).clone();
        reused_options.initialize_logger()?;
        assert_eq!(
            Some(!reused_options.logger()?.0.policy.colors_enabled),
            snapshot.map(|value| !value)
        );
        reused_options.logger()?.error("new instance", &[])?;
        assert_eq!(
            replacement
                .0
                .lock()
                .expect("capture mutex is not poisoned")
                .as_slice(),
            [(LogLevel::Error, "new instance".to_owned(), Vec::new())]
        );
    }
    Ok(())
}

#[test]
fn thresholds_keep_success_order_and_custom_arguments_unformatted() -> crate::AuthResult<()> {
    let levels = [
        LogLevel::Debug,
        LogLevel::Info,
        LogLevel::Success,
        LogLevel::Warn,
        LogLevel::Error,
    ];
    let structured = serde_json::json!({"value": 1});
    let tail = Value::String("tail".into());
    for configured_level in [None].into_iter().chain(levels.map(Some)) {
        let level = configured_level.unwrap_or_default();
        for disabled in [None, Some(false), Some(true)] {
            let sink = Arc::new(Capture::default());
            let logger = Logger::new(LoggerConfig {
                level: configured_level,
                disabled,
                log: Some(sink.clone()),
                disable_colors: Some(false),
            })?;
            for event in levels {
                logger.log(
                    event,
                    "literal %s",
                    &[LogArgument::Value(&structured), LogArgument::Value(&tail)],
                )?;
            }
            let expected: Vec<_> = levels
                .into_iter()
                .filter(|event| !disabled.unwrap_or(false) && *event >= level)
                .map(|event| {
                    (
                        if event == LogLevel::Success {
                            LogLevel::Info
                        } else {
                            event
                        },
                        "literal %s".to_owned(),
                        vec![structured.clone(), tail.clone()],
                    )
                })
                .collect();
            assert_eq!(
                *sink.0.lock().expect("capture mutex is not poisoned"),
                expected
            );
        }
    }
    Ok(())
}

#[test]
fn native_arguments_reach_custom_sink_without_coercion_or_identity_loss() -> crate::AuthResult<()> {
    #[derive(Default)]
    struct NativeCapture(Mutex<Option<crate::FieldValue>>);
    impl LogSink for NativeCapture {
        fn log(
            &self,
            _: LogLevel,
            message: LogArgument<'_>,
            arguments: &[LogArgument<'_>],
        ) -> AuthResult<()> {
            let (LogArgument::Text("native fields"), [LogArgument::Native(argument)]) =
                (message, arguments)
            else {
                panic!("native arguments must retain their representation");
            };
            *self.0.lock().expect("capture mutex is not poisoned") = Some((*argument).clone());
            Ok(())
        }
    }
    let message: crate::FieldValue = crate::Utf16String::from_units(vec![0xd800]).into();
    let argument: crate::FieldValue = crate::FieldMap::from([
        ("missing".into(), crate::FieldValue::Undefined),
        ("message".into(), message.clone()),
    ])
    .into();
    let sink = Arc::new(NativeCapture::default());
    let logger = Logger::new(LoggerConfig {
        log: Some(sink.clone()),
        ..Default::default()
    })?;
    logger.log(
        LogLevel::Error,
        "native fields",
        &[LogArgument::Native(&argument)],
    )?;
    let observed = sink.0.lock().expect("capture mutex is not poisoned");
    let observed_argument = observed.as_ref().expect("logger was called");
    assert!(observed_argument.strict_equals(&argument));
    assert!(
        observed_argument
            .model_property("message")
            .expect("native object is readable")
            .strict_equals(&message)
    );
    assert!(
        observed_argument
            .model_property("missing")
            .expect("native object is readable")
            .is_undefined()
    );
    assert_eq!(LogArgument::Native(&message).to_string(), "\u{fffd}");
    Logger::new(LoggerConfig::default())?.log(
        LogLevel::Error,
        LogArgument::Native(&message),
        &[],
    )?;
    Ok(())
}

#[test]
fn live_typed_options_replace_callbacks_without_rebinding_policy() -> AuthResult<()> {
    let first = Arc::new(Capture::default());
    let second = Arc::new(Capture::default());
    let options = LoggerOptions::new(LoggerConfig {
        level: Some(LogLevel::Error),
        disable_colors: Some(false),
        log: Some(first.clone()),
        ..Default::default()
    });
    let logger = Logger::new(options.clone())?;
    logger.error("first", &[])?;
    let mut updated = options.snapshot();
    updated.level = Some(LogLevel::Warn);
    updated.disable_colors = Some(true);
    updated.log = Some(second.clone());
    drop(options.replace(updated));
    logger.warn("filtered", &[])?;
    logger.error("second", &[])?;
    let fresh = Logger::new(options.clone())?;
    fresh.warn("new policy", &[])?;
    assert!(logger.level().strict_equals(&"error".into()));
    assert!(fresh.level().strict_equals(&"warn".into()));
    assert!(logger.0.policy.colors_enabled);
    assert!(!fresh.0.policy.colors_enabled);
    assert_eq!(
        first.0.lock().expect("first sink is readable").as_slice(),
        [(LogLevel::Error, "first".into(), Vec::new()),]
    );
    assert_eq!(
        second.0.lock().expect("second sink is readable").as_slice(),
        [
            (LogLevel::Error, "second".into(), Vec::new()),
            (LogLevel::Warn, "new policy".into(), Vec::new()),
        ]
    );
    options.set_log(None);
    logger.error("default sink", &[])?;
    assert_eq!(second.0.lock().expect("second sink is readable").len(), 2);
    Ok(())
}

#[test]
fn native_sink_receives_original_error_handle_and_typed_sink_can_downcast() -> AuthResult<()> {
    struct InspectError;
    impl LogSink for InspectError {
        fn log(
            &self,
            _: LogLevel,
            _: LogArgument<'_>,
            arguments: &[LogArgument<'_>],
        ) -> AuthResult<()> {
            let [LogArgument::Error(error)] = arguments else {
                panic!("typed sink receives a borrowed error");
            };
            assert_eq!(
                error
                    .downcast_ref::<std::io::Error>()
                    .expect("original error type")
                    .kind(),
                std::io::ErrorKind::TimedOut
            );
            Ok(())
        }
    }
    let typed = std::io::Error::new(std::io::ErrorKind::TimedOut, "elapsed");
    Logger::new(LoggerConfig {
        log: Some(Arc::new(InspectError)),
        ..Default::default()
    })?
    .error("typed", &[LogArgument::Error(&typed)])?;
    let raw: FieldValue = crate::FieldMap::new().into();
    let error = AuthError::from_thrown(raw.clone());
    let options: FieldObject = crate::FieldMap::from([(
        "log".into(),
        crate::FieldFunction::contextual(move |_, arguments| {
            assert_eq!(arguments.len(), 3);
            assert!(arguments[2].strict_equals(&raw));
            Ok(FieldValue::Undefined)
        })
        .into(),
    )])
    .into();
    Logger::new(options)?.error("native", &[LogArgument::Error(&error)])
}
