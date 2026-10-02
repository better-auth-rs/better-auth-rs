use super::SessionView;
use crate::store::schema::resolve_field_name;
use crate::{AuthResult, AuthSession, config::SessionConfig, user_fields::UserFieldConfig};
use serde_json::{Map, Value};

pub(super) struct SessionProjection<'a, T> {
    session: &'a T,
    pub(super) view: SessionView,
    core: Map<String, Value>,
    model: Value,
}

pub(super) fn rows<'a, T: AuthSession>(
    sessions: &'a [T],
    config: &SessionConfig,
) -> AuthResult<Vec<SessionProjection<'a, T>>> {
    sessions
        .iter()
        .map(|session| {
            let view = SessionView::from(session);
            // Core getters retain public names when models serialize application field names.
            let core = view.clone().into();
            Ok(SessionProjection {
                session,
                view,
                core,
                model: if config.fields().is_empty() {
                    Value::Null
                } else {
                    serde_json::to_value(session)?
                },
            })
        })
        .collect()
}

impl<T: AuthSession> SessionProjection<'_, T> {
    pub(super) async fn project(
        &mut self,
        name: &str,
        field: &UserFieldConfig,
        supports_native_json: bool,
    ) -> AuthResult<()> {
        let value = if let Some(fields) = self.session.projected_fields() {
            fields.get(name).cloned()
        } else {
            let value = self
                .model
                .get(T::serialized_field_name(resolve_field_name(
                    field.field_name.as_deref(),
                    name,
                )))
                .or_else(|| self.model.get(name))
                .or_else(|| self.core.get(name))
                .cloned();
            field.adapter_output(value, supports_native_json).await?
        };
        if let Some(mut value) = value {
            if !field.references_id() {
                field.normalize_date(&mut value)?;
            }
            let _ = self.view.additional_fields.insert(name.to_owned(), value);
        }
        Ok(())
    }
}
