use better_auth_core::{AuthError, AuthResult, FieldArray, FieldFunction, FieldMap, FieldValue};
use serde_json::{Value as Json, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

type Events = Arc<Mutex<Vec<String>>>;

fn record(events: &Events, event: String) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Array event lock poisoned"))?
        .push(event);
    Ok(())
}

fn observe(name: &str, sql: &str, value: &FieldValue, events: &Events) -> AuthResult<Json> {
    let result = super::super::format(sql, std::slice::from_ref(value));
    let events = events
        .lock()
        .map_err(|_| AuthError::internal("Array event lock poisoned"))?
        .clone();
    match result {
        Ok(sql) => Ok(json!({"name": name, "units": sql.as_utf16(), "events": events})),
        Err(AuthError::RangeError(message)) => Ok(
            json!({"name": name, "error": {"name": "RangeError", "message": message}, "events": events}),
        ),
        Err(error) => Err(error),
    }
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The regression asserts bounded native effects and an error instead of partial SQL."
)]
fn dynamic_cycles_stop_at_the_shared_frame_limit() -> AuthResult<()> {
    for (sql, method) in [("select ?", "toSqlString"), ("select ??", "toString")] {
        let value = FieldValue::from(FieldArray::new());
        let called = Arc::new(AtomicUsize::new(0));
        let calls = called.clone();
        let callback = FieldFunction::contextual(move |_, _| {
            let _ = calls.fetch_add(1, Ordering::SeqCst);
            Ok("native-effect".into())
        });
        value.set_model_property(
            "0",
            FieldMap::from([(method.into(), callback.into())]).into(),
        )?;
        value.set_model_property("1", value.clone())?;

        let result = super::super::format(sql, std::slice::from_ref(&value));
        value.set_model_property("length", 0.into())?;

        assert!(matches!(
            result,
            Err(AuthError::RangeError(message)) if message == "Maximum call stack size exceeded."
        ));
        let calls = called.load(Ordering::SeqCst);
        assert!(calls > 1);
        assert!(calls <= super::MAX_ACTIVE_FRAMES);
    }
    Ok(())
}

#[test]
#[ignore = "requires the pinned native Array observations from GitHub Actions"]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The contract compares complete captured Array output, errors, and callback events."
)]
fn pinned_mysql_native_arrays() -> AuthResult<()> {
    let path = std::env::var("BETTER_AUTH_MYSQL_NATIVE_VALUES_FIXTURE")
        .map_err(|cause| AuthError::internal(cause.to_string()))?;
    let expected: Json = serde_json::from_slice(
        &std::fs::read(path).map_err(|cause| AuthError::internal(cause.to_string()))?,
    )
    .map_err(|cause| AuthError::internal(cause.to_string()))?;
    let mut arrays = Vec::new();
    for depth in [64, 512, 2048] {
        let mut value = 7.into();
        let mut retained = Vec::new();
        for _ in 0..depth {
            value = vec![value].into();
            retained.push(value.clone());
        }
        arrays.push(observe(
            &format!("array-depth-{depth}"),
            "select ?",
            &value,
            &Events::default(),
        )?);
        arrays.push(observe(
            &format!("identifier-depth-{depth}"),
            "select ??",
            &value,
            &Events::default(),
        )?);
        drop(value);
        // Release outer handles first; native graph destruction is a separate boundary from SQL formatting.
        while let Some(value) = retained.pop() {
            drop(value);
        }
    }
    for sql in ["select ?", "select ??"] {
        let value = FieldValue::from(FieldArray::new());
        value.set_model_property("0", value.clone())?;
        let observed = observe(
            &format!("self-cycle-{sql}"),
            sql,
            &value,
            &Events::default(),
        );
        value.set_model_property("length", 0.into())?;
        arrays.push(observed?);

        let left = FieldValue::from(FieldArray::new());
        let right: FieldValue = vec![left.clone()].into();
        left.set_model_property("0", right.clone())?;
        let observed = observe(
            &format!("mutual-cycle-{sql}"),
            sql,
            &left,
            &Events::default(),
        );
        left.set_model_property("length", 0.into())?;
        right.set_model_property("length", 0.into())?;
        arrays.push(observed?);
    }
    {
        let value = FieldValue::from(FieldArray::new());
        let events = Events::default();
        let target = value.clone();
        let called = Arc::new(AtomicUsize::new(0));
        let calls = events.clone();
        let callback = FieldFunction::contextual(move |_, _| {
            let count = called.fetch_add(1, Ordering::SeqCst) + 1;
            record(&calls, format!("call:{count}"))?;
            if count == 2 {
                target.set_model_property("1", 9.into())?;
            }
            Ok("NOW()".into())
        });
        value.set_model_property(
            "0",
            FieldMap::from([("toSqlString".into(), callback.into())]).into(),
        )?;
        value.set_model_property("1", value.clone())?;
        let observed = observe(
            "cycle-broken-on-second-callback",
            "select ?",
            &value,
            &events,
        );
        value.set_model_property("length", 0.into())?;
        arrays.push(observed?);
    }
    {
        let value: FieldValue = vec![FieldValue::Null, 2.into()].into();
        let events = Events::default();
        let target = value.clone();
        let calls = events.clone();
        let callback = FieldFunction::contextual(move |_, _| {
            record(&calls, "mutate".into())?;
            target.set_model_property("length", 1.into())?;
            target.set_model_property("2", 3.into())?;
            Ok("NOW()".into())
        });
        value.set_model_property(
            "0",
            FieldMap::from([("toSqlString".into(), callback.into())]).into(),
        )?;
        let observed = observe(
            "array-captured-length-live-indices",
            "select ?",
            &value,
            &events,
        );
        value.set_model_property("length", 0.into())?;
        arrays.push(observed?);
    }
    {
        let value = FieldValue::from(FieldArray::with_length(3));
        value.set_model_property("1", "present".into())?;
        arrays.push(observe(
            "array-holes",
            "select ?",
            &value,
            &Events::default(),
        )?);
    }
    assert_eq!(arrays.len(), 13);
    assert_eq!(json!(arrays), expected["arrays"]);
    Ok(())
}
