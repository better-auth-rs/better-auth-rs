use super::*;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Scenario {
    pub(super) name: String,
    pub(super) route: String,
    pub(super) relation: String,
    #[serde(default)]
    pub(super) many: bool,
    #[serde(default)]
    pub(super) accounts_one: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub(super) url: String,
    pub(super) method: String,
    pub(super) headers: Vec<[String; 2]>,
    pub(super) body: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Response {
    pub(super) status: u16,
    #[serde(rename = "statusText")]
    _status_text: String,
    pub(super) headers: Vec<[String; 2]>,
    pub(super) cookies: Vec<String>,
    pub(super) body: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Case {
    pub(super) backend: String,
    pub(super) scenario: String,
    pub(super) joins: bool,
    pub(super) request: Request,
    pub(super) before: Value,
    pub(super) events: Vec<Value>,
    pub(super) response: Response,
    pub(super) after: Value,
    pub(super) checked: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Fixture {
    version: String,
    scenarios: Vec<Scenario>,
    pub(super) cases: Vec<Case>,
}

impl Fixture {
    pub(super) fn read() -> AuthResult<Self> {
        let fixture: Self = serde_json::from_str(include_str!(
            "../fixtures/account-user-auth-boundary-1.7.6.json"
        ))?;
        assert_eq!(fixture.version, "1.7.6");
        assert_eq!(fixture.scenarios.len(), 4);
        assert_eq!(fixture.cases.len(), 16);
        for scenario in &fixture.scenarios {
            for backend in ["memory", "sqlite"] {
                for joins in [false, true] {
                    assert_eq!(
                        fixture
                            .cases
                            .iter()
                            .filter(|case| {
                                case.scenario == scenario.name
                                    && case.backend == backend
                                    && case.joins == joins
                            })
                            .count(),
                        1,
                        "{scenario:?}/{backend}/{joins}"
                    );
                }
            }
        }
        Ok(fixture)
    }

    pub(super) fn scenario(&self, name: &str) -> AuthResult<&Scenario> {
        self.scenarios
            .iter()
            .find(|scenario| scenario.name == name)
            .ok_or_else(|| {
                AuthError::internal(format!("Missing Account/User HTTP scenario: {name}"))
            })
    }
}
