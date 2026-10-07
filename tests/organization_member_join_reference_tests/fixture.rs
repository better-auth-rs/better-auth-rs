use super::*;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Scenario {
    #[serde(default)]
    pub(super) name: String,
    #[serde(default)]
    pub(super) member_fields: serde_json::Map<String, Value>,
    #[serde(default)]
    pub(super) user_fields: serde_json::Map<String, Value>,
    pub(super) error: Option<String>,
    #[serde(rename = "selected")]
    _selected: Option<String>,
    #[serde(default)]
    pub(super) missing_child: bool,
    #[serde(default)]
    pub(super) many: bool,
    pub(super) limit: Option<Value>,
    pub(super) failure: Option<String>,
    pub(super) storage_fields: Option<Box<Scenario>>,
    #[serde(default)]
    pub(super) member_seed: serde_json::Map<String, Value>,
    #[serde(default)]
    pub(super) user_seeds: serde_json::Map<String, Value>,
    pub(super) backends: Option<Vec<String>>,
    #[serde(rename = "on")]
    _on: Option<Value>,
    #[serde(rename = "selectedFallback")]
    _selected_fallback: Option<String>,
    #[serde(rename = "childCounts")]
    _child_counts: Option<Value>,
}

impl Scenario {
    pub(super) fn storage(&self) -> Self {
        self.storage_fields.as_deref().cloned().unwrap_or_default()
    }

    pub(super) fn limit(&self) -> AuthResult<Option<f64>> {
        self.limit
            .as_ref()
            .map(|value| match values::revive(value)? {
                FieldValue::Number(number) => Ok(number),
                _ => Err(AuthError::internal("Expected a numeric member join limit")),
            })
            .transpose()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Operation {
    pub(super) surface: String,
    pub(super) path: String,
    pub(super) events: Vec<Value>,
    pub(super) returned: bool,
    pub(super) result: Option<Value>,
    pub(super) json: Option<Value>,
    pub(super) key_order: Option<Vec<Value>>,
    pub(super) error: Option<Value>,
    pub(super) storage_unchanged: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Case {
    pub(super) backend: String,
    pub(super) scenario: String,
    pub(super) joins: bool,
    pub(super) populated: bool,
    pub(super) before: Value,
    pub(super) operations: Vec<Operation>,
    pub(super) after: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Fixture {
    version: String,
    pub(super) scenarios: Vec<Scenario>,
    boundaries: Vec<Value>,
    pub(super) cases: Vec<Case>,
}

impl Fixture {
    pub(super) fn read() -> AuthResult<Self> {
        let fixture: Self = serde_json::from_str(include_str!(
            "../fixtures/organization-member-join-reference-1.7.6.json"
        ))?;
        assert_eq!(fixture.version, "1.7.6");
        assert_eq!(fixture.scenarios.len(), 22);
        assert_eq!(fixture.boundaries.len(), 44);
        assert_eq!(fixture.cases.len(), 164);
        for scenario in &fixture.scenarios {
            for backend in ["memory", "sqlite"] {
                let enabled = scenario
                    .backends
                    .as_ref()
                    .is_none_or(|backends| backends.iter().any(|value| value == backend));
                for joins in [false, true] {
                    for populated in [false, true] {
                        let matching = fixture
                            .cases
                            .iter()
                            .filter(|case| {
                                case.scenario == scenario.name
                                    && case.backend == backend
                                    && case.joins == joins
                                    && case.populated == populated
                            })
                            .collect::<Vec<_>>();
                        assert_eq!(
                            matching.len(),
                            usize::from(enabled),
                            "{} / {backend} / {joins} / {populated}",
                            scenario.name
                        );
                    }
                }
            }
        }
        for case in &fixture.cases {
            assert_eq!(case.before, case.after, "{case:?}");
            assert_eq!(case.operations.len(), 4, "{case:?}");
            let scenario = fixture.scenario(&case.scenario)?;
            if let Some(message) = &scenario.error {
                for operation in &case.operations {
                    assert!(!operation.returned);
                    assert_eq!(
                        operation
                            .error
                            .as_ref()
                            .and_then(|error| error.get("message"))
                            .and_then(Value::as_str),
                        Some(message.as_str())
                    );
                    assert!(operation.events.is_empty());
                }
            }
        }
        Ok(fixture)
    }

    pub(super) fn scenario(&self, name: &str) -> AuthResult<&Scenario> {
        self.scenarios
            .iter()
            .find(|scenario| scenario.name == name)
            .ok_or_else(|| AuthError::internal(format!("Missing member join scenario: {name}")))
    }
}
