use super::*;
use better_auth_core::FieldFunction;
use object::Root;

fn text<'a>(state: &'a State, key: &str) -> &'a str {
    state.scenario[key].as_str().unwrap_or("")
}

fn flag(state: &State, key: &str) -> bool {
    state.scenario[key].as_bool().unwrap_or(false)
}

fn keep(state: &State, root: Root) -> FieldValue {
    let value = root.value.clone();
    state.roots.lock().unwrap().push(root);
    value
}

fn method(
    root: &Root,
    name: &'static str,
    state: &Arc<State>,
    body: impl Fn(&Arc<State>, &[FieldValue]) -> AuthResult<FieldValue> + Send + Sync + 'static,
) {
    let expected = root.owner();
    let state = Arc::downgrade(state);
    let body = Arc::new(body);
    root.getter(name, false, move |receiver| {
        let state = state.upgrade().unwrap();
        let owner = expected.upgrade().unwrap();
        state.record(
            &format!("get:{name}"),
            [(
                "sameReceiver".into(),
                receiver.strict_equals(owner.get().unwrap()).into(),
            )],
        );
        if text(&state, "fail") == format!("{name}:get") {
            return state.fail(&format!("throw:{name}:get"));
        }
        let state = Arc::downgrade(&state);
        let expected = expected.clone();
        let body = body.clone();
        Ok(FieldFunction::contextual(move |receiver, arguments| {
            let state = state.upgrade().unwrap();
            let owner = expected.upgrade().unwrap();
            state.record(
                &format!("call:{name}"),
                [
                    (
                        "sameReceiver".into(),
                        receiver.strict_equals(owner.get().unwrap()).into(),
                    ),
                    (
                        "arguments".into(),
                        state.observe(&arguments.to_vec().into())?,
                    ),
                ],
            );
            if text(&state, "fail") == format!("{name}:call") {
                return state.fail(&format!("throw:{name}:call"));
            }
            body(&state, arguments)
        })
        .into())
    });
}

fn expiry(state: &Arc<State>) -> AuthResult<FieldValue> {
    Ok(match text(state, "expiry") {
        "missing" | "undefined" => FieldValue::Undefined,
        "null" => FieldValue::Null,
        "nan" => f64::NAN.into(),
        "invalid-date" => date(f64::NAN),
        "expired" => date((NOW - 1) as f64),
        "equal" => date(NOW as f64),
        "object" | "conversion-error" => {
            let root = Root::new("object");
            method(&root, "valueOf", state, |state, _| {
                if text(state, "expiry") == "conversion-error" {
                    state.fail("throw:expiry-conversion")
                } else {
                    Ok(((NOW + 60_000) as f64).into())
                }
            });
            keep(state, root)
        }
        _ => date((NOW + 60_000) as f64),
    })
}

fn attempts(state: &Arc<State>) -> FieldValue {
    if let Some(counter) = state.scenario["counterText"].as_str() {
        return counter.into();
    }
    match text(state, "attempts") {
        "string-object" | "string-error" => {
            let root = Root::new("object");
            root.data("marker", "attempts".into());
            method(&root, "toString", state, |state, _| {
                if text(state, "attempts") == "string-error" {
                    state.fail("throw:attempt-conversion")
                } else {
                    Ok("  +2tail".into())
                }
            });
            keep(state, root)
        }
        "object" | "conversion-error" => {
            let root = Root::new("object");
            root.data("marker", "attempts".into());
            method(&root, "valueOf", state, |state, _| {
                if text(state, "attempts") == "conversion-error" {
                    state.fail("throw:attempt-conversion")
                } else {
                    Ok(1.into())
                }
            });
            keep(state, root)
        }
        "false" => false.into(),
        "nan" => f64::NAN.into(),
        _ => if flag(state, "exhausted") { "3" } else { "0" }.into(),
    }
}

fn otp(state: &State) -> FieldValue {
    let bytes = || {
        [49, 50, 51, 52, 53, 54]
            .into_iter()
            .map(FieldValue::from)
            .collect::<Vec<_>>()
    };
    match text(state, "otpShape") {
        "array" => bytes().into(),
        "array-like" => bytes()
            .into_iter()
            .enumerate()
            .map(|(index, value)| (index.to_string(), value))
            .chain([("length".into(), 6.into())])
            .collect::<FieldMap>()
            .into(),
        _ => "123456".into(),
    }
}

fn value(state: &Arc<State>) -> FieldValue {
    match text(state, "value") {
        "methods" => {
            let root = Root::new("object");
            root.data("marker", "native-otp".into());
            method(&root, "lastIndexOf", state, |state, _| {
                Ok(match text(state, "index") {
                    "string" => "6".into(),
                    "object" => {
                        let index = Root::new("object");
                        index.data("marker", "index".into());
                        method(&index, "valueOf", state, |_, _| Ok(6.into()));
                        keep(state, index)
                    }
                    _ => if flag(state, "noColon") { -1 } else { 6 }.into(),
                })
            });
            method(&root, "slice", state, |state, _| {
                let count = {
                    let mut counts = state.counts.lock().unwrap();
                    counts.slice += 1;
                    counts.slice
                };
                Ok(if count % 2 == 1 {
                    otp(state)
                } else if flag(state, "exhausted") {
                    "3".into()
                } else {
                    "0".into()
                })
            });
            method(&root, "split", state, |state, _| {
                let count = {
                    let mut counts = state.counts.lock().unwrap();
                    counts.split += 1;
                    counts.split
                };
                if text(state, "fail") == "split:second" && count == 2 {
                    return state.fail("throw:split:second");
                }
                let raw = attempts(state);
                Ok(match text(state, "splitShape") {
                    "null" => FieldValue::Null,
                    "undefined" => FieldValue::Undefined,
                    "string" => "12".into(),
                    "array-like" => FieldMap::from([
                        ("0".into(), "123456".into()),
                        ("1".into(), raw),
                        ("length".into(), 2.into()),
                    ])
                    .into(),
                    _ => vec!["123456".into(), raw].into(),
                })
            });
            keep(state, root)
        }
        "undefined" => FieldValue::Undefined,
        "null" => FieldValue::Null,
        "false" => false.into(),
        "zero" => 0.into(),
        "nan" => f64::NAN.into(),
        "empty" => "".into(),
        "owner" => "owner".into(),
        "other-user" => "other-user".into(),
        "object" => FieldMap::from([
            ("ownUndefined".into(), FieldValue::Undefined),
            ("marker".into(), "native-value".into()),
        ])
        .into(),
        _ => format!("123456:{}", if flag(state, "exhausted") { 3 } else { 0 }).into(),
    }
}

pub(super) fn input(state: &Arc<State>, identifier: &str) -> AuthResult<FieldValue> {
    let value = value(state);
    let root = Root::new(if text(state, "root") == "function" {
        "function"
    } else {
        "date"
    });
    for (name, value) in [
        ("id", "verification-row".into()),
        ("identifier", identifier.into()),
        ("createdAt", date(NOW as f64)),
        ("updatedAt", date(NOW as f64)),
    ] {
        root.data(name, value);
    }
    if text(state, "expiry") != "missing" {
        let state = Arc::downgrade(state);
        let expected = root.owner();
        root.getter("expiresAt", true, move |receiver| {
            let state = state.upgrade().unwrap();
            let read = {
                let mut counts = state.counts.lock().unwrap();
                counts.expiry += 1;
                counts.expiry
            };
            if flag(&state, "unreadExpiry") {
                return state.fail("unexpected:trust-expiry");
            }
            state.record(
                "get:expiresAt",
                [
                    (
                        "sameReceiver".into(),
                        receiver
                            .strict_equals(expected.upgrade().unwrap().get().unwrap())
                            .into(),
                    ),
                    ("read".into(), read.into()),
                ],
            );
            if text(&state, "fail") == "expiry:get"
                || text(&state, "fail") == "expiry:second" && read == 2
            {
                return state.fail("throw:expiry:get");
            }
            expiry(&state)
        });
    }
    let copied_value = value;
    let expected = root.owner();
    let weak = Arc::downgrade(state);
    root.getter("value", true, move |receiver| {
        let state = weak.upgrade().unwrap();
        let read = {
            let mut counts = state.counts.lock().unwrap();
            counts.value += 1;
            counts.value
        };
        state.record(
            "get:value",
            [
                (
                    "sameReceiver".into(),
                    receiver
                        .strict_equals(expected.upgrade().unwrap().get().unwrap())
                        .into(),
                ),
                ("read".into(), read.into()),
                ("sameValue".into(), true.into()),
            ],
        );
        if text(&state, "fail") == "value:get"
            || text(&state, "fail") == "value:second" && read == 2
        {
            return state.fail("throw:value:get");
        }
        Ok(copied_value.clone())
    });
    Ok(keep(state, root))
}
