#![expect(
    clippy::panic_in_result_fn,
    reason = "HTTP contracts assert getter order, original errors, complete bytes, and MIME behavior."
)]

use super::*;
use crate::{FieldFunction, FieldMap, FieldObject, field_value::FieldObjectSource};
use std::{collections::BTreeMap, collections::VecDeque, sync::Mutex};

type Events = Arc<Mutex<Vec<String>>>;
type Reads = BTreeMap<&'static str, VecDeque<AuthResult<Option<FieldValue>>>>;

struct Probe {
    fields: FieldMap,
    reads: Mutex<Reads>,
    events: Events,
}

impl FieldObjectSource for Probe {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        crate::FieldObject::from(self.fields.clone()).own_keys()
    }

    fn own_property_descriptor(
        &self,
        name: &str,
    ) -> AuthResult<Option<crate::field_value::FieldPropertyDescriptor>> {
        Ok(self
            .fields
            .get(name)
            .cloned()
            .map(crate::field_value::FieldPropertyDescriptor::data))
    }

    fn get_with_receiver(
        &self,
        name: &str,
        _receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        if ["buffer", "constructor", "toJSON", "toString", "valueOf"].contains(&name) {
            self.events
                .lock()
                .map_err(|_| AuthError::internal("HTTP event lock poisoned"))?
                .push(name.to_owned());
        }
        let mut reads = self
            .reads
            .lock()
            .map_err(|_| AuthError::internal("HTTP getter lock poisoned"))?;
        match reads.get_mut(name) {
            Some(reads) => reads
                .pop_front()
                .ok_or_else(|| AuthError::internal(format!("Unexpected repeated {name} read")))?,
            None => Ok(self.fields.get(name).cloned()),
        }
    }

    fn set_with_receiver(
        &self,
        _: String,
        _: FieldValue,
        _receiver: &FieldValue,
    ) -> AuthResult<bool> {
        Err(AuthError::internal("HTTP getter fixture is read-only"))
    }

    fn delete(&self, _: &str) -> AuthResult<bool> {
        Err(AuthError::internal("HTTP getter fixture is read-only"))
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Ok(self.fields.clone())
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }

    fn define_own_property(
        &self,
        _name: String,
        _definition: crate::FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        Err(AuthError::internal(
            "This contract source does not define properties",
        ))
    }
}

fn probe(fields: FieldMap, reads: Reads, events: &Events) -> ResponseBody {
    ResponseBody::Native(FieldValue::Object(FieldObject::from_source(Arc::new(
        Probe {
            fields,
            reads: Mutex::new(reads),
            events: events.clone(),
        },
    ))))
}

fn values(
    values: impl IntoIterator<Item = FieldValue>,
) -> VecDeque<AuthResult<Option<FieldValue>>> {
    values.into_iter().map(|value| Ok(Some(value))).collect()
}

fn method(events: &Events, name: &'static str, result: FieldValue) -> FieldValue {
    let events = events.clone();
    FieldFunction::contextual(move |_, arguments| {
        if name == "toJSON" {
            assert_eq!(arguments, [FieldValue::from("")]);
        } else if name == "toString" {
            assert!(arguments.is_empty());
        }
        events
            .lock()
            .map_err(|_| AuthError::internal("HTTP event lock poisoned"))?
            .push(format!("call:{name}"));
        Ok(result.clone())
    })
    .into()
}

fn sample(name: &str, events: &Events) -> AuthResult<ResponseBody> {
    let string = method(events, "toString", "opaque".into());
    let json = method(events, "toJSON", "encoded".into());
    let mut reads = Reads::from([("toJSON", values([json]))]);
    match name {
        "buffer" => {
            let _ = reads.insert("buffer", values([true.into()]));
        }
        "constructor-null" | "constructor-undefined" => {
            let _ = reads.insert(
                "constructor",
                values([if name == "constructor-null" {
                    FieldValue::Null
                } else {
                    FieldValue::Undefined
                }]),
            );
            let _ = reads.insert("toJSON", values([FieldValue::Undefined]));
        }
        "constructor-shift" => {
            let _ = reads.insert(
                "constructor",
                values(
                    ["Other", "Object"]
                        .map(|name| FieldMap::from([("name".into(), name.into())]).into()),
                ),
            );
        }
        "method-shift" => {
            let _ = reads.insert("constructor", values([FieldValue::Null]));
            let _ = reads.insert(
                "toJSON",
                values([
                    method(events, "classification", FieldValue::Null),
                    method(events, "toJSON", "encoded".into()),
                ]),
            );
        }
        "prototype" => {}
        _ => return Err(AuthError::internal("Unknown HTTP classification sample")),
    }
    Ok(probe(
        FieldMap::from([("toString".into(), string)]),
        reads,
        events,
    ))
}

#[test]
fn http_classification_preserves_getter_order_and_bodyinit_mime() -> AuthResult<()> {
    let cases: [(_, _, &[&str], _); 6] = [
        (
            "buffer",
            "opaque",
            &["buffer", "toString", "call:toString"],
            false,
        ),
        (
            "constructor-null",
            "opaque",
            &[
                "buffer",
                "constructor",
                "toJSON",
                "toString",
                "call:toString",
            ],
            false,
        ),
        (
            "constructor-undefined",
            "opaque",
            &[
                "buffer",
                "constructor",
                "toJSON",
                "toString",
                "call:toString",
            ],
            false,
        ),
        (
            "constructor-shift",
            r#""encoded""#,
            &[
                "buffer",
                "constructor",
                "constructor",
                "toJSON",
                "call:toJSON",
            ],
            true,
        ),
        (
            "method-shift",
            r#""encoded""#,
            &["buffer", "constructor", "toJSON", "toJSON", "call:toJSON"],
            true,
        ),
        (
            "prototype",
            r#""encoded""#,
            &[
                "buffer",
                "constructor",
                "constructor",
                "toJSON",
                "call:toJSON",
            ],
            true,
        ),
    ];
    for (name, expected, expected_events, json) in cases {
        for initial in [None, Some("application/custom"), Some("")] {
            let events = Events::default();
            let body = sample(name, &events)?;
            let mut headers = Headers::new();
            if let Some(initial) = initial {
                let _ = headers.insert("content-type", initial);
            }
            let encoded = body.into_http_body(&mut headers)?;
            assert_eq!(encoded.bytes()?.as_ref(), expected.as_bytes(), "{name}");
            assert_eq!(
                headers.get("content-type").map(String::as_str),
                if json {
                    Some("application/json")
                } else {
                    initial
                },
                "{name}",
            );
            assert_eq!(
                headers.iter().count(),
                usize::from(json || initial.is_some())
            );
            assert_eq!(
                *events
                    .lock()
                    .map_err(|_| AuthError::internal("HTTP event lock poisoned"))?,
                expected_events
            );
        }
        let events = Events::default();
        assert_eq!(
            sample(name, &events)?.bytes()?.as_ref(),
            expected.as_bytes()
        );
        assert_eq!(
            *events
                .lock()
                .map_err(|_| AuthError::internal("HTTP event lock poisoned"))?,
            expected_events
        );
    }
    Ok(())
}

#[test]
fn http_classification_preserves_original_getter_errors() -> AuthResult<()> {
    for stage in [
        "buffer",
        "constructor-first",
        "constructor-second",
        "constructor-name",
        "toJSON-class",
        "toJSON-encode",
        "toString",
        "valueOf",
    ] {
        for bytes in [false, true] {
            let events = Events::default();
            let message = format!("original HTTP {stage} failure");
            let pointer = message.as_ptr() as usize;
            let failure = Err(AuthError::internal(message));
            let mut reads = Reads::new();
            let expected: &[&str] = match stage {
                "buffer" => {
                    let _ = reads.insert("buffer", [failure].into());
                    &["buffer"]
                }
                "constructor-first" => {
                    let _ = reads.insert("constructor", [failure].into());
                    &["buffer", "constructor"]
                }
                "constructor-second" => {
                    let _ = reads.insert("constructor", [Ok(Some(true.into())), failure].into());
                    &["buffer", "constructor", "constructor"]
                }
                "constructor-name" => {
                    let constructor = probe(
                        FieldMap::new(),
                        Reads::from([("name", [failure].into())]),
                        &events,
                    )
                    .field_value()?;
                    let _ = reads.insert("constructor", values([true.into(), constructor]));
                    &["buffer", "constructor", "constructor"]
                }
                "toJSON-class" => {
                    let _ = reads.insert("constructor", values([FieldValue::Null]));
                    let _ = reads.insert("toJSON", [failure].into());
                    &["buffer", "constructor", "toJSON"]
                }
                "toJSON-encode" => {
                    let _ = reads.insert("toJSON", [failure].into());
                    &["buffer", "constructor", "constructor", "toJSON"]
                }
                "toString" => {
                    let _ = reads.insert("buffer", values([true.into()]));
                    let _ = reads.insert("toString", [failure].into());
                    &["buffer", "toString"]
                }
                _ => {
                    let _ = reads.insert("buffer", values([true.into()]));
                    let _ = reads.insert("toString", values([FieldValue::Null]));
                    let _ = reads.insert("valueOf", [failure].into());
                    &["buffer", "toString", "valueOf"]
                }
            };
            let body = probe(FieldMap::new(), reads, &events);
            let result = if bytes {
                body.bytes().map(|_| ())
            } else {
                body.into_http_body(&mut Headers::new()).map(|_| ())
            };
            assert!(
                matches!(result, Err(AuthError::Internal(message)) if message.as_ptr() as usize == pointer)
            );
            assert_eq!(
                *events
                    .lock()
                    .map_err(|_| AuthError::internal("HTTP event lock poisoned"))?,
                expected
            );
        }
    }
    Ok(())
}

#[test]
fn http_constructor_second_read_can_become_null_and_json_stays_strict() -> AuthResult<()> {
    let events = Events::default();
    let body = probe(
        FieldMap::new(),
        Reads::from([("constructor", values([true.into(), FieldValue::Null]))]),
        &events,
    );
    assert!(matches!(
        body.into_http_body(&mut Headers::new()),
        Err(AuthError::TypeError(_))
    ));
    assert_eq!(
        *events
            .lock()
            .map_err(|_| AuthError::internal("HTTP event lock poisoned"))?,
        ["buffer", "constructor", "constructor"]
    );

    let events = Events::default();
    let body = sample("buffer", &events)?;
    assert_eq!(body.json()?, Some(serde_json::json!("encoded")));
    assert_eq!(
        *events
            .lock()
            .map_err(|_| AuthError::internal("HTTP event lock poisoned"))?,
        ["toJSON", "call:toJSON"]
    );
    Ok(())
}
