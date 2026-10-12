use super::*;
use better_auth_core::FieldFunction;
use better_auth_core::field_value::{
    FieldObject, FieldObjectSource, FieldProperty, FieldPropertyDefinition, FieldPropertyDescriptor,
};

struct UserSource {
    fields: FieldObject,
}

impl FieldObjectSource for UserSource {
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
        self.fields.get_with_receiver(name, receiver)
    }

    fn set_with_receiver(&self, _: String, _: FieldValue, _: &FieldValue) -> AuthResult<bool> {
        Err(AuthError::internal("Injected User must not be mutated"))
    }

    fn define_own_property(&self, _: String, _: FieldPropertyDefinition) -> AuthResult<bool> {
        Err(AuthError::internal("Injected User must not be mutated"))
    }

    fn delete(&self, _: &str) -> AuthResult<bool> {
        Err(AuthError::internal("Injected User must not be mutated"))
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        self.own_keys()?
            .into_iter()
            .map(|name| {
                let value = self
                    .get_with_receiver(&name, &FieldValue::Undefined)?
                    .unwrap_or_default();
                Ok((name, value))
            })
            .collect()
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self).addr()
    }
}

pub(super) fn injected_user(
    case: &'static str,
    shared: &FieldValue,
    state: &Arc<Mutex<Observed>>,
    thrown: &FieldValue,
) -> AuthResult<FieldValue> {
    let user = snapshot_user(case, shared);
    if !case.starts_with("getter-") {
        return Ok(user);
    }
    let fields = user
        .enumerable_fields()?
        .into_iter()
        .map(|(name, value)| {
            let descriptor = if matches!(name.as_str(), "id" | "unread") {
                let state = state.clone();
                let thrown = thrown.clone();
                let unread = name == "unread";
                let event = format!("user.{name}");
                FieldPropertyDescriptor {
                    enumerable: true,
                    configurable: true,
                    property: FieldProperty::Accessor {
                        get: Some(FieldFunction::contextual(move |_, _| {
                            lock(&state)?.events.push(event.clone());
                            if unread
                                || matches!(
                                    case,
                                    "getter-error" | "getter-no-fields" | "getter-email"
                                )
                            {
                                return Err(AuthError::from_thrown(thrown.clone()));
                            }
                            Ok(value.clone())
                        })),
                        set: None,
                    },
                }
            } else {
                FieldPropertyDescriptor::data(value)
            };
            (name, descriptor)
        })
        .collect::<indexmap::IndexMap<_, _>>()
        .into();
    Ok(FieldObject::from_source(Arc::new(UserSource { fields })).into())
}
