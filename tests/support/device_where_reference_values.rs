use super::{Case, references};
use better_auth_core::{AuthError, AuthResult, user_fields::UserFieldType};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ReferenceType {
    Json,
    Date,
}

impl ReferenceType {
    pub(crate) fn field_type(self) -> UserFieldType {
        match self {
            Self::Json => UserFieldType::Json,
            Self::Date => UserFieldType::Date,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Date => "date",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    version: String,
    backend: String,
    groups: Vec<Group>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Group {
    pub(crate) owner_ref_type: ReferenceType,
    pub(crate) serial: bool,
    pub(crate) cases: Vec<Case>,
}

fn inventory(field_type: ReferenceType) -> AuthResult<Vec<(String, Value)>> {
    let date = json!({"type": "date", "value": "1970-01-01T00:00:00.001Z"});
    let mut inputs = vec![
        ("eq-number", "eq", false, json!(1)),
        ("eq-date", "eq", true, date.clone()),
        ("ne-date", "ne", false, date.clone()),
    ];
    inputs.extend(match field_type {
        ReferenceType::Json => [
            ("eq-object", "eq", true, json!({"value": 1})),
            ("in-string-null", "in", false, json!(["1", null])),
        ],
        ReferenceType::Date => [
            ("in-date", "in", true, json!([date])),
            (
                "eq-invalid-date",
                "eq",
                false,
                json!({"type": "date", "value": "Invalid Date"}),
            ),
        ],
    });
    let condition = |operator: &str, physical: bool, value: Value| {
        json!([
            {"field": "id", "value": "<device-id>"},
            {
                "field": if physical { "stored_ownerRef" } else { "ownerRef" },
                "operator": operator,
                "value": value,
            },
            {"field": "deviceCode", "value": "ordinary-device"},
            {"field": "clientId", "value": "ordinary-client"},
            {"field": "userId", "value": "1"},
            {"field": "status", "value": "approved"},
        ])
    };
    let prefix = format!("serial-{}-reference", field_type.name());
    let mut cases = inputs
        .into_iter()
        .map(|(suffix, operator, physical, value)| {
            (
                format!("{prefix}-{suffix}"),
                condition(operator, physical, value),
            )
        })
        .collect::<Vec<_>>();
    for (index, field) in ["id", "deviceCode", "clientId", "userId", "status"]
        .into_iter()
        .enumerate()
    {
        let mut query = condition("eq", index % 2 == 1, json!(1));
        let position = if index == 0 { 0 } else { index + 1 };
        let value = query
            .get_mut(position)
            .and_then(|condition| condition.get_mut("value"))
            .ok_or_else(|| AuthError::internal("The native guard must contain its value"))?;
        *value = json!(if matches!(field, "id" | "userId") {
            "2".into()
        } else {
            format!("{field}-mismatch")
        });
        cases.push((format!("{prefix}-{field}-mismatch"), query));
    }
    cases.extend([
        (
            format!("{prefix}-transaction-commit"),
            condition("eq", false, json!(1)),
        ),
        (
            format!("{prefix}-transaction-rollback"),
            condition("eq", true, json!(1)),
        ),
    ]);
    Ok(cases)
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "The paired fixture must retain both complete configurations, operands, native guards, and storage observations"
)]
pub(crate) fn load_reference_values(
    backend: &str,
) -> Result<Vec<Group>, Box<dyn std::error::Error + Send + Sync>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "tests/fixtures/device-reference-values-{backend}-1.7.6.json"
    ));
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(path)?)?;
    assert_eq!(fixture.version, "1.7.6");
    assert_eq!(fixture.backend, backend);
    assert_eq!(
        fixture
            .groups
            .iter()
            .map(|group| group.owner_ref_type)
            .collect::<Vec<_>>(),
        [ReferenceType::Json, ReferenceType::Date]
    );
    for group in &fixture.groups {
        assert!(group.serial);
        assert_eq!(group.cases.len(), 12);
        let expected = inventory(group.owner_ref_type)?;
        assert_eq!(expected.len(), group.cases.len());
        for (case, (name, condition)) in group.cases.iter().zip(expected) {
            assert_eq!(case.name, name);
            assert_eq!(json!(case.condition), condition);
            references::validate_storage(case)?;
            assert_eq!(case.seeded.get("ownerRef"), Some(&json!("1")));
            assert_eq!(case.before.len(), 1);
            assert_eq!(
                case.before
                    .first()
                    .and_then(|row| row.get("stored_ownerRef")),
                Some(&json!(1))
            );
            assert_eq!(
                case.seed_events
                    .iter()
                    .filter(|event| event.get("field") == Some(&json!("ownerRef")))
                    .collect::<Vec<_>>(),
                [
                    &json!({"phase": "input", "field": "ownerRef", "value": 1}),
                    &json!({"phase": "output", "field": "ownerRef", "value": 1}),
                ]
            );
        }
    }
    Ok(fixture.groups)
}
