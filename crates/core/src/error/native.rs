use super::{AuthError, AuthResult};
use crate::{
    FieldFunction, FieldMap, FieldObject, FieldPropertyDefinition, FieldPropertyDescriptor,
    FieldValue,
};
use std::{
    any::Any,
    collections::HashSet,
    sync::{Arc, LazyLock},
};

/// The constructor family used by an API error instance.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ApiErrorClass {
    BetterCall,
    #[default]
    BetterAuth,
}

/// Native constructor arguments. Undefined arguments use the upstream defaults.
#[derive(Debug, Clone, Default)]
pub struct ApiErrorInit {
    pub status: FieldValue,
    pub body: FieldValue,
    pub headers: FieldValue,
    pub status_code: FieldValue,
    pub class: ApiErrorClass,
}

/// Check an instance brand without reading the object's properties.
pub fn is_error_value(value: &FieldValue) -> bool {
    value
        .as_object()
        .and_then(|object| object.source::<ErrorObject>())
        .is_some()
}

/// Check an API error instance brand without reading the object's properties.
pub fn api_error_instance(value: &FieldValue, class: ApiErrorClass) -> bool {
    value
        .as_object()
        .and_then(|object| object.source::<ErrorObject>())
        .is_some_and(|source| {
            source
                .class
                .is_some_and(|instance| class == ApiErrorClass::BetterCall || instance == class)
        })
}

/// Apply Better Call's instance-or-name classification without caching property reads.
pub fn is_api_error_value(value: &FieldValue) -> AuthResult<bool> {
    if api_error_instance(value, ApiErrorClass::BetterCall) {
        return Ok(true);
    }
    Ok(optional_property(value, "name")?.strict_equals(&"APIError".into()))
}

pub(super) fn optional_property(value: &FieldValue, name: &str) -> AuthResult<FieldValue> {
    if value.is_null() || value.is_undefined() {
        Ok(FieldValue::Undefined)
    } else {
        value.model_property(name)
    }
}

pub(super) fn construct(mut init: ApiErrorInit) -> AuthResult<FieldValue> {
    if init.status.is_undefined() {
        init.status = "INTERNAL_SERVER_ERROR".into();
    }
    if init.headers.is_undefined() {
        init.headers = FieldMap::new().into();
    }
    if init.status_code.is_undefined() {
        init.status_code = if init.status.is_number() {
            init.status.clone()
        } else {
            let key = init.status.display_utf16()?;
            STATUS_CODES
                .iter()
                .find(|(name, _)| key.as_utf16().iter().copied().eq(name.encode_utf16()))
                .map_or(FieldValue::Undefined, |(_, code)| f64::from(*code).into())
        };
    }

    // Error receives both arguments before converting the already-read message to a string.
    let message = optional_property(&init.body, "message")?;
    let cause = optional_property(&init.body, "cause")?;
    let cause = if cause.is_truthy() {
        Some(optional_property(&init.body, "cause")?)
    } else {
        None
    };
    let mut fields = FieldMap::new();
    let mut hidden = HashSet::new();
    if !message.is_undefined() {
        let _ = fields.insert("message".into(), message.display_utf16()?.into());
        let _ = hidden.insert("message".to_owned());
    }
    if let Some(cause) = cause {
        let _ = fields.insert("cause".into(), cause);
        let _ = hidden.insert("cause".to_owned());
    }
    for (name, value) in [
        ("status", init.status),
        ("body", init.body),
        ("headers", init.headers),
        ("statusCode", init.status_code),
        ("name", "APIError".into()),
    ] {
        let _ = fields.insert(name.into(), value);
    }
    Ok(error_object(error_fields(fields, hidden), Some(init.class)))
}

pub(super) fn better_auth(message: crate::Utf16String) -> FieldValue {
    error_object(
        error_fields(
            FieldMap::from([
                ("message".into(), message.into()),
                ("stack".into(), "".into()),
                ("name".into(), "BetterAuthError".into()),
            ]),
            HashSet::from(["message".into(), "stack".into()]),
        ),
        None,
    )
}

fn error_fields(fields: FieldMap, hidden: HashSet<String>) -> FieldObject {
    fields
        .into_iter()
        .map(|(name, value)| {
            let mut descriptor = FieldPropertyDescriptor::data(value);
            descriptor.enumerable = !hidden.contains(&name);
            (name, descriptor)
        })
        .collect::<indexmap::IndexMap<_, _>>()
        .into()
}

fn error_object(fields: FieldObject, class: Option<ApiErrorClass>) -> FieldValue {
    FieldObject::from_source(Arc::new(ErrorObject {
        fields,
        class,
        inherited_name: "Error",
    }))
    .into()
}

pub(super) fn runtime_error(name: &'static str, message: FieldValue) -> FieldValue {
    FieldObject::from_source(Arc::new(ErrorObject {
        fields: error_fields(
            FieldMap::from([("message".into(), message)]),
            HashSet::from(["message".into()]),
        ),
        class: None,
        inherited_name: name,
    }))
    .into()
}

pub(super) fn database_error(properties: FieldMap) -> FieldValue {
    // The reference Error objects keep host source-location properties nonenumerable.
    error_object(
        error_fields(
            properties,
            HashSet::from([
                "message".into(),
                "stack".into(),
                "line".into(),
                "column".into(),
            ]),
        ),
        None,
    )
}

/// Attach a known native instance brand without constructing or projecting its fields.
#[cfg(test)]
pub(crate) fn brand_api_error_object(fields: FieldObject, class: ApiErrorClass) -> FieldValue {
    error_object(fields, Some(class))
}

struct ErrorObject {
    fields: FieldObject,
    class: Option<ApiErrorClass>,
    inherited_name: &'static str,
}

impl crate::field_value::FieldObjectSource for ErrorObject {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        self.fields.own_keys()
    }

    fn own_property_descriptor(
        &self,
        name: &str,
    ) -> AuthResult<Option<crate::field_value::FieldPropertyDescriptor>> {
        self.fields.own_property_descriptor(name)
    }

    fn has_property(&self, name: &str) -> AuthResult<bool> {
        Ok(self.fields.has_property(name)? || matches!(name, "name" | "message" | "toString"))
    }

    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        if let Some(value) = self.fields.get_with_receiver(name, receiver)? {
            return Ok(Some(value));
        }
        Ok(match name {
            "name" => Some(self.inherited_name.into()),
            "message" => Some("".into()),
            "toString" => Some(ERROR_TO_STRING.clone().into()),
            _ => None,
        })
    }

    fn set_with_receiver(
        &self,
        name: String,
        value: FieldValue,
        receiver: &FieldValue,
    ) -> AuthResult<bool> {
        self.fields.set_with_receiver(&name, value, receiver)
    }

    fn define_own_property(
        &self,
        name: String,
        definition: FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        self.fields.define_own_property(name, definition)
    }

    fn delete(&self, name: &str) -> AuthResult<bool> {
        self.fields.delete(name)
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        FieldValue::Object(self.fields.clone()).enumerable_fields()
    }

    fn identity(&self) -> usize {
        self as *const Self as usize
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}

static ERROR_TO_STRING: LazyLock<FieldFunction> = LazyLock::new(|| {
    FieldFunction::contextual(|receiver, _| {
        let name = receiver.model_property("name")?;
        let name = if name.is_undefined() {
            "Error".into()
        } else {
            name.display_utf16()?
        };
        let message = receiver.model_property("message")?;
        let message = if message.is_undefined() {
            "".into()
        } else {
            message.display_utf16()?
        };
        if name.as_utf16().is_empty() {
            return Ok(message.into());
        }
        if message.as_utf16().is_empty() {
            return Ok(name.into());
        }
        let mut output = name.as_utf16().to_vec();
        output.extend_from_slice(&[u16::from(b':'), u16::from(b' ')]);
        output.extend_from_slice(message.as_utf16());
        Ok(crate::Utf16String::from_units(output).into())
    })
});

const STATUS_CODES: &[(&str, u16)] = &[
    ("OK", 200),
    ("CREATED", 201),
    ("ACCEPTED", 202),
    ("NO_CONTENT", 204),
    ("MULTIPLE_CHOICES", 300),
    ("MOVED_PERMANENTLY", 301),
    ("FOUND", 302),
    ("SEE_OTHER", 303),
    ("NOT_MODIFIED", 304),
    ("TEMPORARY_REDIRECT", 307),
    ("BAD_REQUEST", 400),
    ("UNAUTHORIZED", 401),
    ("PAYMENT_REQUIRED", 402),
    ("FORBIDDEN", 403),
    ("NOT_FOUND", 404),
    ("METHOD_NOT_ALLOWED", 405),
    ("NOT_ACCEPTABLE", 406),
    ("PROXY_AUTHENTICATION_REQUIRED", 407),
    ("REQUEST_TIMEOUT", 408),
    ("CONFLICT", 409),
    ("GONE", 410),
    ("LENGTH_REQUIRED", 411),
    ("PRECONDITION_FAILED", 412),
    ("PAYLOAD_TOO_LARGE", 413),
    ("URI_TOO_LONG", 414),
    ("UNSUPPORTED_MEDIA_TYPE", 415),
    ("RANGE_NOT_SATISFIABLE", 416),
    ("EXPECTATION_FAILED", 417),
    ("I'M_A_TEAPOT", 418),
    ("MISDIRECTED_REQUEST", 421),
    ("UNPROCESSABLE_ENTITY", 422),
    ("LOCKED", 423),
    ("FAILED_DEPENDENCY", 424),
    ("TOO_EARLY", 425),
    ("UPGRADE_REQUIRED", 426),
    ("PRECONDITION_REQUIRED", 428),
    ("TOO_MANY_REQUESTS", 429),
    ("REQUEST_HEADER_FIELDS_TOO_LARGE", 431),
    ("UNAVAILABLE_FOR_LEGAL_REASONS", 451),
    ("INTERNAL_SERVER_ERROR", 500),
    ("NOT_IMPLEMENTED", 501),
    ("BAD_GATEWAY", 502),
    ("SERVICE_UNAVAILABLE", 503),
    ("GATEWAY_TIMEOUT", 504),
    ("HTTP_VERSION_NOT_SUPPORTED", 505),
    ("VARIANT_ALSO_NEGOTIATES", 506),
    ("INSUFFICIENT_STORAGE", 507),
    ("LOOP_DETECTED", 508),
    ("NOT_EXTENDED", 510),
    ("NETWORK_AUTHENTICATION_REQUIRED", 511),
];
