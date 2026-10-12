use super::*;
use better_auth_core::store::{EphemeralStore, schema::EntityRole};

pub(super) fn storage(store: &EphemeralStore) -> AuthResult<FieldValue> {
    let mut tables = FieldMap::new();
    for (name, role) in [
        ("user", EntityRole::User),
        ("session", EntityRole::Session),
        ("account", EntityRole::Account),
        ("verification", EntityRole::Verification),
    ] {
        let rows: Vec<FieldValue> = store
            .storage_rows(role)?
            .into_iter()
            .map(Into::into)
            .collect();
        tables.insert(name.into(), rows.into());
    }
    Ok(tables.into())
}

pub(super) struct Before {
    observations: Value,
    events: Vec<Value>,
}

impl Before {
    pub fn capture(state: &State, store: &EphemeralStore) -> AuthResult<Self> {
        let observations = json!({
            "raw": observe::complete(&state.raw, state, "before.raw")?,
            "mapped": observe::complete(&state.mapped, state, "before.mapped")?,
            "storage": observe::complete(&storage(store)?, state, "before.storage")?,
        });
        let events = state.log.take();
        state.tracking.lock().unwrap().run_start = chrono::Utc::now().timestamp_millis();
        state.log.phase("execute");
        Ok(Self {
            observations,
            events,
        })
    }

    pub fn finish(
        self,
        state: &State,
        store: &EphemeralStore,
        value: FieldValue,
        mut outcome: Value,
        headers: Value,
    ) -> AuthResult<Value> {
        let mut events = state.log.take();
        state.log.phase("assertion");
        assertions::execution(state, store, &outcome, &events, &value)?;
        let assertion_events = state.log.take();
        outcome
            .as_object_mut()
            .unwrap()
            .insert("headers".into(), headers);
        let admissions: FieldValue = state.tracking.lock().unwrap().admissions.clone().into();
        let mut after = json!({
            "raw": observe::complete(&state.raw, state, "after.raw")?,
            "mapped": observe::complete(&state.mapped, state, "after.mapped")?,
            "providerResponse": observe::complete(&state.info(), state, "after.provider-response")?,
            "result": if outcome["kind"] == "native" {
                observe::complete(&value, state, "after.result")?
            } else { Value::Null },
            "admissions": observe::complete(&admissions, state, "after.admissions")?,
            "storage": observe::complete(&storage(store)?, state, "after.storage")?,
        });
        if state.scenario.operation == "account-info" {
            assert_eq!(after["storage"], self.observations["storage"]);
        }
        state.log.phase("identity-observation");
        let (info, mapper, subject, admissions) = {
            let tracking = state.tracking.lock().unwrap();
            (
                tracking.info.clone(),
                tracking.mapper_input.clone(),
                tracking.subject_input.clone(),
                tracking.admissions.clone(),
            )
        };
        let identities = json!({
            "providerDataIsRaw": info.as_ref().map(|info| info.model_property("data").map(|data| data.strict_equals(&state.raw))).transpose()?,
            "customResponseIsOriginal": if state.scenario.provider == "social" { info.as_ref().map(|info| info.strict_equals(&state.social_response)) } else { None },
            "mapperIsRaw": mapper.as_ref().map(|value| value.strict_equals(&state.raw)),
            "subjectIsRaw": subject.as_ref().map(|value| value.strict_equals(&state.raw)),
            "admissionProfilesAreRaw": admissions.iter().map(|data| Ok(data.model_property("source")?.model_property("oauth")?.model_property("profile")?.strict_equals(&state.raw))).collect::<AuthResult<Vec<_>>>()?,
        });
        let tracking = state.tracking.lock().unwrap();
        dates::apply(
            &mut events,
            &mut after,
            &state.scenario,
            &tracking.generated_dates,
        );
        let mut sample = serde_json::to_value(&state.scenario)?;
        sample.as_object_mut().unwrap().extend(
            json!({
                "backend": "memory", "before": self.observations, "outcome": outcome,
                "executionEvents": events,
                "assertionEvents": assertion_events, "after": after,
                "observationEvents": {"before": self.events, "after": state.log.take()},
                "identities": identities,
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        Ok(observe::replace_generated(sample, &tracking.replacements))
    }
}

pub(super) fn assert_complete(actual: &Value, expected: &Value, scenario: &str) {
    const LIMIT: usize = 32;
    fn describe(value: &Value) -> String {
        let text = value.to_string();
        let mut characters = text.chars();
        let mut result: String = characters.by_ref().take(512).collect();
        if characters.next().is_some() {
            result.push('…');
        }
        result
    }
    fn differences(actual: &Value, expected: &Value, path: &str, output: &mut Vec<String>) {
        if output.len() == LIMIT || actual == expected {
            return;
        }
        match (actual, expected) {
            (Value::Object(actual), Value::Object(expected)) => {
                for (key, expected) in expected {
                    if output.len() == LIMIT {
                        return;
                    }
                    let path = format!("{path}.{key}");
                    if let Some(actual) = actual.get(key) {
                        differences(actual, expected, &path, output);
                    } else {
                        output.push(format!(
                            "{path}: missing actual key; expected {}",
                            describe(expected)
                        ));
                    }
                }
                for (key, actual) in actual {
                    if output.len() == LIMIT {
                        return;
                    }
                    if !expected.contains_key(key) {
                        output.push(format!(
                            "{path}.{key}: unexpected actual key with {}",
                            describe(actual)
                        ));
                    }
                }
            }
            (Value::Array(actual), Value::Array(expected)) => {
                if actual.len() != expected.len() {
                    output.push(format!(
                        "{path}: array length {} != {}",
                        actual.len(),
                        expected.len()
                    ));
                }
                for (index, (actual, expected)) in actual.iter().zip(expected).enumerate() {
                    if output.len() == LIMIT {
                        return;
                    }
                    differences(actual, expected, &format!("{path}[{index}]"), output);
                }
            }
            _ => output.push(format!(
                "{path}: actual {}, expected {}",
                describe(actual),
                describe(expected)
            )),
        }
    }
    if actual != expected {
        let mut output = Vec::new();
        differences(actual, expected, scenario, &mut output);
        panic!(
            "{scenario}: complete case differs (at most {LIMIT} paths shown)\n{}",
            output.join("\n")
        );
    }
}
