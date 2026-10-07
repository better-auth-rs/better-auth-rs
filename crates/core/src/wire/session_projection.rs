use super::SessionView;
use crate::FieldMap;
use crate::store::schema::resolve_field_name;
use crate::{AuthResult, AuthSession, config::SessionConfig, user_fields::UserFieldConfig};

pub(super) struct SessionProjection<'a, T> {
    session: &'a T,
    pub(super) view: SessionView,
    core: crate::FieldMap,
    model: FieldMap,
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
                    FieldMap::new()
                } else {
                    session.field_values()?
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
            fields.get(name).cloned().unwrap_or_default()
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
            field
                .adapter_output(value.unwrap_or_default(), supports_native_json)
                .await?
        };
        {
            let mut value = value;
            if !field.references_id() {
                field.normalize_date(&mut value)?;
            }
            let _ = self.view.additional_fields.insert(name.to_owned(), value);
        }
        Ok(())
    }
}
