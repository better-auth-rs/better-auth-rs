use super::*;
use crate::field_value::{FieldObjectSource, FieldPropertyDescriptor};

struct NonEnumerableObject(FieldObject, &'static str);

impl FieldObjectSource for NonEnumerableObject {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        self.0.own_keys()
    }
    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        Ok(self.0.own_property_descriptor(name)?.map(|mut descriptor| {
            descriptor.enumerable = name != self.1;
            descriptor
        }))
    }
    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        self.0.get_with_receiver(name, receiver)
    }
    fn set_with_receiver(
        &self,
        name: String,
        value: FieldValue,
        receiver: &FieldValue,
    ) -> AuthResult<bool> {
        self.0.set_with_receiver(&name, value, receiver)
    }
    fn delete(&self, name: &str) -> AuthResult<bool> {
        self.0.delete(name)
    }
    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        self.0.snapshot_fields()
    }
    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }

    fn define_own_property(
        &self,
        name: String,
        definition: crate::FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        self.0.define_own_property(name, definition)
    }
}

pub(super) fn with_hidden_property(fields: FieldMap, name: &'static str) -> FieldValue {
    FieldObject::from_source(Arc::new(NonEnumerableObject(fields.into(), name))).into()
}

#[derive(Clone)]
pub(super) struct Errors {
    pub(super) values: FieldValue,
    tokens: FieldMap,
}

impl Errors {
    pub(super) fn new() -> Self {
        let mut tokens = FieldMap::new();
        let values = ["task", "handler", "taskLogger", "handlerLogger"]
            .into_iter()
            .map(|name| {
                let token: FieldValue = FieldMap::from([("owner".into(), name.into())]).into();
                let _ = tokens.insert(name.into(), token.clone());
                let error = with_hidden_property(
                    FieldMap::from([
                        ("code".into(), format!("BACKGROUND_{name}").into()),
                        ("message".into(), format!("{name} original failure").into()),
                        ("token".into(), token),
                    ]),
                    "token",
                );
                (name.to_owned(), error)
            })
            .collect::<FieldMap>()
            .into();
        Self { values, tokens }
    }

    pub(super) fn value(&self, name: &str) -> AuthResult<FieldValue> {
        self.values.model_property(name)
    }

    pub(super) fn identity(&self, value: &FieldValue) -> AuthResult<Json> {
        ["task", "handler", "taskLogger", "handlerLogger"]
            .into_iter()
            .map(|name| {
                let expected = self.value(name)?;
                if value.strict_equals(&expected) {
                    assert!(value.model_property("token")?.strict_equals(
                        self.tokens.get(name).ok_or_else(|| {
                            AuthError::internal("The initial error token must exist")
                        })?
                    ));
                }
                Ok((name.to_owned(), value.strict_equals(&expected).into()))
            })
            .collect::<AuthResult<serde_json::Map<_, _>>>()
            .map(Into::into)
    }

    pub(super) fn rejection(&self, error: &FieldValue) -> AuthResult<Json> {
        Ok(
            json!({"status":"rejected","identity":self.identity(error)?,"error":native_shape(error)?}),
        )
    }
}

// The Rust descriptor API exposes enumerability. Source configurable/writable flags remain in the immutable fixture.
pub(super) fn native_shape(value: &FieldValue) -> AuthResult<Json> {
    let kind = match value {
        FieldValue::Array(_) => "array",
        FieldValue::Object(_) => "object",
        _ => return NativeObservation::default().observe(value),
    };
    let keys = match value {
        FieldValue::Array(array) => {
            let mut keys = array
                .own_indices()?
                .into_iter()
                .map(|index| index.to_string())
                .collect::<Vec<_>>();
            // Reflect.ownKeys includes length between indexed and named array properties.
            keys.push("length".into());
            keys.extend(array.named_property_keys()?);
            keys
        }
        _ => value.own_property_keys()?,
    };
    let properties = keys.iter().map(|name| {
        let descriptor = value.own_property_descriptor(name)?.ok_or_else(|| AuthError::internal("Observed property vanished"))?;
        Ok(json!([name, {"enumerable":descriptor.enumerable,"value":native_shape(&value.model_property(name)?)?}]))
    }).collect::<AuthResult<Vec<_>>>()?;
    Ok(json!({"type":kind,"ownKeys":keys,"properties":properties}))
}

pub(super) fn source_shape(value: &Json) -> AuthResult<Json> {
    if value.get("identity").is_none() {
        return Ok(value.clone());
    }
    let properties = value["properties"].as_array().ok_or_else(|| AuthError::internal("Source snapshot is missing properties"))?.iter().map(|entry| {
        let descriptor = &entry[1];
        if descriptor.get("value").is_none() { return Err(AuthError::internal("Background contract cannot pair an accessor snapshot")); }
        Ok(json!([entry[0], {"enumerable":descriptor["enumerable"],"value":source_shape(&descriptor["value"])?}]))
    }).collect::<AuthResult<Vec<_>>>()?;
    Ok(json!({"type":value["type"],"ownKeys":value["ownKeys"],"properties":properties}))
}
