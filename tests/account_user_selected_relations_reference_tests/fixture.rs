use super::*;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Scenario {
    pub(super) name: String,
    pub(super) populations: Option<Vec<bool>>,
    #[serde(default)]
    pub(super) account_fields: serde_json::Map<String, Value>,
    #[serde(default)]
    pub(super) user_fields: serde_json::Map<String, Value>,
    #[serde(default)]
    pub(super) replacements: serde_json::Map<String, Value>,
    pub(super) limit: Option<f64>,
    #[serde(default)]
    pub(super) reverse: bool,
    #[serde(default)]
    pub(super) reverse_unique: bool,
    #[serde(default)]
    pub(super) missing_child: bool,
    #[serde(default)]
    pub(super) image_reference: bool,
    #[serde(default)]
    pub(super) duplicate_identity: bool,
    #[serde(rename = "ownerIds")]
    _owner_ids: Option<Vec<String>>,
    #[serde(rename = "accountIds")]
    _account_ids: Option<Vec<String>>,
    #[serde(rename = "fallbackOwnerIds")]
    _fallback_owner_ids: Option<Vec<String>>,
    #[serde(rename = "fallbackAccountIds")]
    _fallback_account_ids: Option<Vec<String>>,
    #[serde(rename = "ownerMany")]
    _owner_many: Option<bool>,
    #[serde(rename = "accountsOne")]
    _accounts_one: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Operation {
    pub(super) surface: String,
    pub(super) operation: String,
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
    before: Value,
    pub(super) operations: Vec<Operation>,
    after: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Fixture {
    version: String,
    scenarios: Vec<Scenario>,
    pub(super) cases: Vec<Case>,
}

impl Fixture {
    #[expect(
        clippy::panic_in_result_fn,
        reason = "The fixture loader propagates decoding errors and rejects incomplete contract coverage."
    )]
    pub(super) fn read() -> AuthResult<Self> {
        let fixture: Self = serde_json::from_str(include_str!(
            "../fixtures/account-user-selected-relations-1.7.6.json"
        ))?;
        assert_eq!(fixture.version, "1.7.6");
        assert_eq!(fixture.scenarios.len(), 10);
        assert_eq!(fixture.cases.len(), 44);
        for scenario in &fixture.scenarios {
            for backend in ["memory", "sqlite"] {
                for joins in [false, true] {
                    for &populated in scenario.populations.as_deref().unwrap_or(&[true]) {
                        assert_eq!(
                            fixture
                                .cases
                                .iter()
                                .filter(|case| case.scenario == scenario.name
                                    && case.backend == backend
                                    && case.joins == joins
                                    && case.populated == populated)
                                .count(),
                            1,
                            "{scenario:?}/{backend}/{joins}/{populated}"
                        );
                    }
                }
            }
        }
        let mut internal_reads = 0;
        for case in &fixture.cases {
            assert_eq!(case.before, case.after, "{case:?}");
            assert_eq!(case.operations.len(), 4, "{case:?}");
            for operation in ["owner", "accounts"] {
                for surface in ["adapter", "internal"] {
                    assert_eq!(
                        case.operations
                            .iter()
                            .filter(|item| item.surface == surface && item.operation == operation)
                            .count(),
                        1,
                        "{case:?}"
                    );
                }
            }
            internal_reads += case
                .operations
                .iter()
                .filter(|operation| operation.surface == "internal")
                .count();
        }
        assert_eq!(internal_reads, 88);
        Ok(fixture)
    }

    pub(super) fn scenario(&self, name: &str) -> AuthResult<&Scenario> {
        self.scenarios
            .iter()
            .find(|scenario| scenario.name == name)
            .ok_or_else(|| AuthError::internal(format!("Missing Account/User scenario: {name}")))
    }
}
