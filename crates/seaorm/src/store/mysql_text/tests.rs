use super::*;
use better_auth_core::{
    FieldDate, FieldFunction, FieldMap, FieldObject, FieldObjectSource, FieldPropertyDescriptor,
};
use serde_json::{Value as Json, json};
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicUsize, Ordering},
};

fn decode(value: &Json) -> AuthResult<FieldValue> {
    if let Some(values) = value.as_array() {
        return values
            .iter()
            .map(decode)
            .collect::<AuthResult<Vec<_>>>()
            .map(Into::into);
    }
    let Some(fields) = value.as_object() else {
        return FieldValue::from_json(value.clone());
    };
    match fields.get("$type").and_then(Json::as_str) {
        Some("undefined") => Ok(FieldValue::Undefined),
        Some("number") => Ok(match fields["value"].as_str() {
            Some("NaN") => f64::NAN,
            Some("Infinity") => f64::INFINITY,
            Some("-Infinity") => f64::NEG_INFINITY,
            _ => return Err(AuthError::internal("Unexpected tagged contract number")),
        }
        .into()),
        Some("date") => Ok(FieldDate::from_milliseconds(
            decode(&fields["value"])?
                .as_f64()
                .ok_or_else(|| AuthError::internal("Missing date milliseconds"))?,
        )
        .into()),
        Some("utf16") => {
            let units: Vec<u16> = serde_json::from_value(fields["value"].clone())
                .map_err(|cause| AuthError::internal(cause.to_string()))?;
            Ok(Utf16String::from_units(units).into())
        }
        Some("raw") => {
            let text = decode(&fields["value"])?;
            Ok(FieldMap::from([(
                "toSqlString".into(),
                FieldFunction::contextual(move |_, _| Ok(text.clone())).into(),
            )])
            .into())
        }
        Some(_) => Err(AuthError::internal("Unexpected tagged contract value")),
        None => fields
            .iter()
            .map(|(key, value)| Ok((key.clone(), decode(value)?)))
            .collect::<AuthResult<FieldMap>>()
            .map(Into::into),
    }
}

struct Native {
    source: Weak<Self>,
    events: Arc<Mutex<Vec<String>>>,
    reads: AtomicUsize,
    throw_on_read: usize,
    thrown: FieldValue,
}

impl Native {
    fn event(&self, text: String) -> AuthResult<()> {
        self.events
            .lock()
            .map_err(|_| AuthError::internal("Native contract event lock poisoned"))?
            .push(text);
        Ok(())
    }
}

impl FieldObjectSource for Native {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        Ok(Vec::new())
    }
    fn own_property_descriptor(&self, _: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        Ok(None)
    }
    fn has_property(&self, name: &str) -> AuthResult<bool> {
        if name == "toSqlString" {
            self.event("has".into())?;
        }
        Ok(name == "toSqlString")
    }
    fn get(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        if name != "toSqlString" {
            return Ok(None);
        }
        let reads = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
        self.event(format!("get:{reads}"))?;
        if reads == self.throw_on_read {
            return Err(AuthError::from_thrown(self.thrown.clone()));
        }
        let source = self.source.clone();
        Ok(Some(
            FieldFunction::contextual(move |receiver, arguments| {
                let source = source
                    .upgrade()
                    .ok_or_else(|| AuthError::internal("Missing native contract receiver"))?;
                let expected = FieldValue::Object(FieldObject::from_source(source.clone()));
                source.event(format!(
                    "call:{}:{}",
                    receiver.strict_equals(&expected),
                    arguments.len()
                ))?;
                Ok("CURRENT_TIMESTAMP".into())
            })
            .into(),
        ))
    }
    fn set(&self, _: String, _: FieldValue) -> AuthResult<Option<FieldValue>> {
        Err(AuthError::internal(
            "Native contract source must not be assigned",
        ))
    }
    fn delete(&self, _: &str) -> AuthResult<Option<FieldValue>> {
        Err(AuthError::internal(
            "Native contract source must not be deleted",
        ))
    }
    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Ok(FieldMap::new())
    }
    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }
}

fn native(throw_on_read: usize) -> AuthResult<Json> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let thrown = FieldValue::from(FieldMap::from([("marker".into(), "render-error".into())]));
    let source = Arc::new_cyclic(|source| Native {
        source: source.clone(),
        events: events.clone(),
        reads: AtomicUsize::new(0),
        throw_on_read,
        thrown: thrown.clone(),
    });
    let value = FieldValue::Object(FieldObject::from_source(source));
    let result = format("select ?", &[value]);
    let events = events
        .lock()
        .map_err(|_| AuthError::internal("Native contract event lock poisoned"))?
        .clone();
    Ok(match result {
        Ok(sql) => json!({"events": events, "units": sql.as_utf16()}),
        Err(error) => {
            json!({"events": events, "sameError": error.into_thrown_value()?.strict_equals(&thrown)})
        }
    })
}

#[test]
#[ignore = "requires the pinned mysql2 source observation from GitHub Actions"]
fn pinned_mysql_text_parameters_and_native_callbacks() -> AuthResult<()> {
    let fixture = std::env::var("BETTER_AUTH_MYSQL_TEXT_FIXTURE")
        .map_err(|cause| AuthError::internal(cause.to_string()))?;
    let expected: Json = serde_json::from_slice(
        &std::fs::read(fixture).map_err(|cause| AuthError::internal(cause.to_string()))?,
    )
    .map_err(|cause| AuthError::internal(cause.to_string()))?;
    let definitions = std::fs::read(format!(
        "{}/../../compat-tests/reference-server/contracts/mysql-text-cases.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .map_err(|cause| AuthError::internal(cause.to_string()))?;
    let definitions: Vec<Json> = serde_json::from_slice(&definitions)
        .map_err(|cause| AuthError::internal(cause.to_string()))?;
    let mut observations = Vec::new();
    for definition in definitions {
        let sql = definition["sql"]
            .as_str()
            .ok_or_else(|| AuthError::internal("Missing contract SQL"))?;
        let values = definition["values"]
            .as_array()
            .ok_or_else(|| AuthError::internal("Missing contract parameters"))?
            .iter()
            .map(decode)
            .collect::<AuthResult<Vec<_>>>()?;
        let output = format(sql, &values)?;
        observations.push(json!({"name": definition["name"], "units": output.as_utf16()}));
    }
    assert_eq!(observations.len(), 30);
    assert_eq!(json!(observations), expected["formats"]);
    assert_eq!(json!([native(0)?, native(2)?]), expected["native"]);
    Ok(())
}
