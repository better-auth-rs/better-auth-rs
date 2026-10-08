use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{Event, Metadata, Subscriber, field::Visit, span};

#[derive(Default)]
pub(super) struct AdmissionTrace {
    pub events: Mutex<Vec<String>>,
    pub owners: Mutex<Vec<FieldValue>>,
    pub sessions: Mutex<Vec<SessionView>>,
    pub banned_users: Mutex<Vec<FieldMap>>,
    next_span: AtomicU64,
}

#[better_auth_core::database_hooks()]
impl DatabaseHooks<StatelessSchema> for AdmissionTrace {
    async fn before_create_session(
        &self,
        fields: &mut FieldMap,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.events.lock().unwrap().push("session:before".into());
        self.owners
            .lock()
            .unwrap()
            .push(fields.get("userId").cloned().unwrap_or_default());
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_create_session(
        &self,
        session: Option<&SessionView>,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        let session = session
            .ok_or_else(|| better_auth_core::AuthError::internal("Expected created fixture row"))?;
        self.events.lock().unwrap().push("session:after".into());
        self.sessions.lock().unwrap().push(session.clone());
        Ok(())
    }
}

pub(super) struct DatabaseSpans(pub Arc<AdmissionTrace>);

impl Visit for DatabaseSpans {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "otel.name"
            && matches!(
                value,
                "db findOne passkey"
                    | "db update passkey"
                    | "db findOne user"
                    | "db update user"
                    | "db create session"
            )
        {
            self.0.events.lock().unwrap().push(value.into());
        }
    }

    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
}

impl Subscriber for DatabaseSpans {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, attributes: &span::Attributes<'_>) -> span::Id {
        attributes.record(&mut Self(self.0.clone()));
        span::Id::from_u64(self.0.next_span.fetch_add(1, Ordering::Relaxed) + 1)
    }

    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
    fn event(&self, _: &Event<'_>) {}
    fn enter(&self, _: &span::Id) {}
    fn exit(&self, _: &span::Id) {}
}
