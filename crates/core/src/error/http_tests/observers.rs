#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
use super::*;
use std::sync::atomic::AtomicUsize;

use crate::{
    AuthContext, AuthResponse,
    api_error::handle_http_error,
    field_value::{FieldObjectSource, FieldPropertyDescriptor},
    observability::{LogArgument, LogSink, with_span},
    store::EphemeralStore,
};
use tracing::{
    Event, Metadata, Subscriber,
    field::{Field, Visit},
    instrument::WithSubscriber,
    span::{Attributes, Id, Record},
};

pub(super) type S = crate::store::StatelessSchema;
pub(super) type Events = Arc<Mutex<Vec<String>>>;
type Presence = dyn Fn(&str) -> AuthResult<bool> + Send + Sync;
type Getter = dyn Fn(&str) -> AuthResult<Option<FieldValue>> + Send + Sync;

pub(super) struct Probe {
    fields: FieldObject,
    has: Box<Presence>,
    read: Box<Getter>,
}

impl Probe {
    pub(super) fn value(
        fields: FieldObject,
        has: impl Fn(&str) -> AuthResult<bool> + Send + Sync + 'static,
        read: impl Fn(&str) -> AuthResult<Option<FieldValue>> + Send + Sync + 'static,
    ) -> FieldValue {
        FieldObject::from_source(Arc::new(Self {
            fields,
            has: Box::new(has),
            read: Box::new(read),
        }))
        .into()
    }
}

impl FieldObjectSource for Probe {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        self.fields.own_keys()
    }

    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        self.fields.own_property_descriptor(name)
    }

    fn has_property(&self, name: &str) -> AuthResult<bool> {
        (self.has)(name)
    }

    fn get_with_receiver(
        &self,
        name: &str,
        _receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        (self.read)(name)
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
        self.own_keys()?
            .into_iter()
            .map(|name| {
                Ok((
                    name.clone(),
                    self.get_with_receiver(&name, &FieldValue::Undefined)?
                        .unwrap(),
                ))
            })
            .collect()
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

pub(super) struct LogRecord {
    pub(super) level: LogLevel,
    pub(super) message: FieldValue,
    pub(super) arguments: Vec<FieldValue>,
}

pub(super) struct InstanceCapture {
    events: Events,
    pub(super) records: Mutex<Vec<LogRecord>>,
}

impl LogSink for InstanceCapture {
    fn log(
        &self,
        level: LogLevel,
        message: LogArgument<'_>,
        arguments: &[LogArgument<'_>],
    ) -> crate::AuthResult<()> {
        let LogArgument::Native(message) = message else {
            panic!("Raw errors must preserve the native logger message");
        };
        let arguments = arguments
            .iter()
            .map(|argument| match argument {
                LogArgument::Native(value) => (*value).clone(),
                _ => panic!("Raw errors must preserve native logger arguments"),
            })
            .collect();
        self.events.lock().unwrap().push("log".into());
        self.records.lock().unwrap().push(LogRecord {
            level,
            message: message.clone(),
            arguments,
        });
        Ok(())
    }
}

#[derive(Default)]
struct TraceFields(Vec<(String, String)>);

impl Visit for TraceFields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.push((field.name().into(), value.into()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.push((field.name().into(), format!("{value:?}")));
    }
}

struct OuterCapture {
    events: Events,
    count: Arc<AtomicUsize>,
    arguments: String,
}

impl Subscriber for OuterCapture {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target() == "better-auth"
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        if event.metadata().name() == "exception" {
            return;
        }
        assert_eq!(event.metadata().level(), &tracing::Level::ERROR);
        let mut fields = TraceFields::default();
        event.record(&mut fields);
        let [message, arguments] = fields.0.as_slice() else {
            panic!("The outer logger must retain message and argument fields");
        };
        assert_eq!(message.0, "message");
        assert!(message.1.ends_with("Authentication request failed"));
        assert_eq!(arguments, &("arguments".into(), self.arguments.clone()));
        // The default tracing sink corresponds to the upstream router's console.error call.
        self.events.lock().unwrap().push("console".into());
        let _ = self.count.fetch_add(1, Ordering::Relaxed);
    }
}

pub(super) struct Harness {
    pub(super) context: AuthContext<S>,
    pub(super) logs: Arc<InstanceCapture>,
    events: Events,
    cause: FieldValue,
    outer: Arc<AtomicUsize>,
}

impl Harness {
    pub(super) fn new(cause: FieldValue, events: &Events, disabled: bool, throws: bool) -> Self {
        let logs = Arc::new(InstanceCapture {
            events: events.clone(),
            records: Mutex::default(),
        });
        let mut config = (*crate::test_store::test_config()).clone();
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
            logger_options.disabled = Some(disabled);
            logger_options.log = Some(logs.clone());
        }
        config.api_error.throw_errors = Some(throws);
        let config = Arc::new(config);
        Self {
            context: AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config)))
                .expect("fixture context initializes"),
            logs,
            events: events.clone(),
            cause,
            outer: Arc::default(),
        }
    }

    pub(super) async fn run(&self, observe_middleware: bool) -> AuthResult<AuthResponse> {
        let raw = AuthError::from_thrown(self.cause.clone());
        let capture = OuterCapture {
            events: self.events.clone(),
            count: self.outer.clone(),
            arguments: format!("{:?}", [LogArgument::Error(&raw)]),
        };
        self.context
            .with_endpoint_context(|context| async move {
                let error = with_span(
                    &context.config.experimental.instrumentation,
                    "middleware /logging-failure http-error-logging",
                    Default::default(),
                    async {
                        if observe_middleware {
                            self.events.lock().unwrap().push("middleware".into());
                        }
                        Err::<(), _>(raw)
                    },
                )
                .await
                .unwrap_err();
                handle_http_error(error, &context).await
            })
            .with_subscriber(capture)
            .await
    }

    pub(super) fn outer_count(&self) -> usize {
        self.outer.load(Ordering::Relaxed)
    }
}

pub(super) fn assert_empty_response(response: AuthResponse) -> AuthResult<()> {
    assert_eq!(response.status, 500);
    assert_eq!(response.status_text, "Internal Server Error".into());
    assert!(response.headers.is_empty());
    assert_eq!(response.body.bytes()?.as_ref(), b"");
    Ok(())
}
