#![expect(
    clippy::indexing_slicing,
    reason = "Tests intentionally panic when fixture setup or adapter contract assertions fail."
)]

use better_auth_core::{
    AuthError, AuthResult, FieldDate, FieldFunction, FieldMap, FieldObject, FieldValue,
    field_value::{FieldProperty, FieldPropertyDescriptor},
};
use serde_json::{Value as Json, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

const METHODS: [&str; 8] = [
    "getTime",
    "getFullYear",
    "getMonth",
    "getDate",
    "getHours",
    "getMinutes",
    "getSeconds",
    "getMilliseconds",
];

type Events = Arc<Mutex<Vec<String>>>;

fn record(events: &Events, value: String) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Date event lock poisoned"))?
        .push(value);
    Ok(())
}

#[derive(Clone, Copy, Default)]
enum Fault {
    #[default]
    None,
    Get(&'static str),
    Call(&'static str),
    NonCallable(&'static str),
}

#[derive(Clone)]
struct Properties {
    base: FieldValue,
    events: Events,
    overrides: FieldMap,
    fault: Fault,
    thrown: FieldValue,
}

impl Properties {
    fn into_object(self) -> AuthResult<FieldObject> {
        let source = Arc::new(self);
        let object = FieldObject::from(FieldMap::new());
        for name in METHODS {
            let source = source.clone();
            FieldValue::Object(object.clone()).define_model_property(
                name,
                FieldPropertyDescriptor {
                    enumerable: false,
                    configurable: false,
                    property: FieldProperty::Accessor {
                        get: Some(FieldFunction::contextual(move |receiver, _| {
                            Ok(source.read(name, receiver)?.unwrap_or_default())
                        })),
                        set: None,
                    },
                }
                .into(),
            )?;
        }
        Ok(object)
    }

    fn read(self: &Arc<Self>, name: &str, expected: &FieldValue) -> AuthResult<Option<FieldValue>> {
        if !METHODS.contains(&name) {
            return Ok(None);
        }
        record(&self.events, format!("get:{name}"))?;
        if matches!(self.fault, Fault::Get(method) if method == name) {
            return Err(AuthError::from_thrown(self.thrown.clone()));
        }
        if matches!(self.fault, Fault::NonCallable(method) if method == name) {
            return Ok(Some(false.into()));
        }
        let source = self.clone();
        let name = name.to_owned();
        let expected = expected.clone();
        Ok(Some(
            FieldFunction::contextual(move |receiver, arguments| {
                record(
                    &source.events,
                    format!(
                        "call:{name}:{}:{}",
                        receiver.strict_equals(&expected),
                        arguments.len()
                    ),
                )?;
                if matches!(source.fault, Fault::Call(method) if method == name) {
                    return Err(AuthError::from_thrown(source.thrown.clone()));
                }
                match source.overrides.get(&name) {
                    Some(value) => Ok(value.clone()),
                    None => source.base.date_getter_method(&name, "date"),
                }
            })
            .into(),
        ))
    }
}

fn observe(name: &str, value: FieldValue, events: Events, thrown: FieldValue) -> AuthResult<Json> {
    let result = super::super::format("select ?", &[value]);
    let events = events
        .lock()
        .map_err(|_| AuthError::internal("Date event lock poisoned"))?
        .clone();
    Ok(match result {
        Ok(sql) => json!({"name": name, "units": sql.as_utf16(), "events": events}),
        Err(AuthError::TypeError(message)) => {
            json!({"name": name, "error": {"name": "TypeError", "message": message}, "events": events})
        }
        Err(error) => {
            json!({"name": name, "sameError": error.into_thrown_value()?.strict_equals(&thrown), "events": events})
        }
    })
}

fn native(name: &str, timestamp: f64, configure: impl FnOnce(&mut Properties)) -> AuthResult<Json> {
    let events = Events::default();
    let thrown: FieldValue = FieldMap::from([("marker".into(), name.into())]).into();
    let mut properties = Properties {
        base: FieldDate::from_milliseconds(timestamp).into(),
        events: events.clone(),
        overrides: FieldMap::new(),
        fault: Fault::None,
        thrown: thrown.clone(),
    };
    configure(&mut properties);
    let date = FieldDate::from_milliseconds_with_properties(timestamp, properties.into_object()?);
    observe(name, date.into(), events, thrown)
}

#[test]
#[ignore = "requires the pinned native Date observations from GitHub Actions"]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The contract compares complete captured Date outputs and callback events."
)]
fn pinned_mysql_native_dates() -> AuthResult<()> {
    let path = std::env::var("BETTER_AUTH_MYSQL_NATIVE_VALUES_FIXTURE")
        .map_err(|cause| AuthError::internal(cause.to_string()))?;
    let expected: Json = serde_json::from_slice(
        &std::fs::read(path).map_err(|cause| AuthError::internal(cause.to_string()))?,
    )
    .map_err(|cause| AuthError::internal(cause.to_string()))?;
    let mut dates = Vec::new();
    for (index, timestamp) in [
        0.0,
        -1.0,
        1_893_553_445_006.0,
        f64::NAN,
        -8_640_000_000_000_000.0,
        8_640_000_000_000_000.0,
    ]
    .into_iter()
    .enumerate()
    {
        dates.push(observe(
            &format!("date-{index}"),
            FieldDate::from_milliseconds(timestamp).into(),
            Events::default(),
            FieldValue::Undefined,
        )?);
    }
    dates.push(native("date-read-order", 0.0, |_| {})?);
    dates.push(native("date-nan-short-circuit", 0.0, |value| {
        let _ = value.overrides.insert("getTime".into(), f64::NAN.into());
    })?);
    dates.push(native("date-get-time-keeps-string", 0.0, |value| {
        let _ = value.overrides.insert("getTime".into(), "NaN".into());
    })?);
    dates.push(native("date-invalid-overridden-time", f64::NAN, |value| {
        let _ = value.overrides.insert("getTime".into(), 0.into());
    })?);
    dates.push(native("date-cross-type-components", 0.0, |value| {
        value.overrides.extend([
            ("getFullYear".into(), "2".into()),
            ("getMonth".into(), "8".into()),
            ("getDate".into(), FieldValue::Null),
            ("getHours".into(), true.into()),
            ("getMinutes".into(), f64::NAN.into()),
            ("getSeconds".into(), FieldValue::Undefined),
            ("getMilliseconds".into(), 5.into()),
        ]);
    })?);
    dates.push(native("date-padding-coercion-order", 0.0, |value| {
        let calls = Arc::new(AtomicUsize::new(0));
        let events = value.events.clone();
        let year = FieldFunction::contextual(move |_, _| {
            let count = calls.fetch_add(1, Ordering::SeqCst) + 1;
            record(&events, format!("year:valueOf:{count}"))?;
            Ok(if count == 1 { 20.into() } else { 50.into() })
        });
        let events = value.events.clone();
        let month = FieldFunction::contextual(move |_, _| {
            record(&events, "month:valueOf".into())?;
            Ok(2.into())
        });
        value.overrides.extend([
            (
                "getFullYear".into(),
                FieldMap::from([("valueOf".into(), year.into())]).into(),
            ),
            (
                "getMonth".into(),
                FieldMap::from([("valueOf".into(), month.into())]).into(),
            ),
        ]);
    })?);
    dates.push(native("date-getter-throws", 0.0, |value| {
        value.fault = Fault::Get("getMonth");
    })?);
    dates.push(native("date-method-throws", 0.0, |value| {
        value.fault = Fault::Call("getMonth");
    })?);
    dates.push(native("date-non-callable", 0.0, |value| {
        value.fault = Fault::NonCallable("getMonth");
    })?);
    assert_eq!(dates.len(), 15);
    assert_eq!(json!(dates), expected["dates"]);
    Ok(())
}
