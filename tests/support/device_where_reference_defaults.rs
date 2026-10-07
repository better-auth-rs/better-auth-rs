use super::{Case, reference_values::ReferenceType, references};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Fixture {
    version: String,
    backend: String,
    id_generation: String,
    groups: Vec<Group>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Group {
    pub(crate) owner_ref_type: ReferenceType,
    serial: bool,
    pub(crate) owner_id: String,
    pub(crate) cases: Vec<Case>,
}

fn inventory(field_type: ReferenceType, owner_id: &str) -> Vec<(String, Value)> {
    let date = json!({"type": "date", "value": "1970-01-01T00:00:00.001Z"});
    let (kind, inputs) = match field_type {
        ReferenceType::Json => (
            "json",
            vec![
                ("eq-owner", "eq", false, json!(owner_id)),
                ("eq-object", "eq", true, json!({"value": 1})),
                ("in-owner-null", "in", false, json!([owner_id, null])),
                ("in-non-array", "in", true, json!(owner_id)),
            ],
        ),
        ReferenceType::Date => (
            "date",
            vec![
                ("eq-number", "eq", false, json!(1)),
                ("eq-date", "eq", true, date.clone()),
                ("in-date", "in", false, json!([date])),
                (
                    "eq-invalid-date",
                    "eq",
                    true,
                    json!({"type": "date", "value": "Invalid Date"}),
                ),
                ("in-non-array", "in", false, json!(1)),
            ],
        ),
    };
    inputs
        .into_iter()
        .map(|(suffix, operator, physical, value)| {
            (
                format!("default-{kind}-reference-{suffix}"),
                json!([
                    {"field": "id", "value": "<device-id>"},
                    {
                        "field": if physical { "stored_ownerRef" } else { "ownerRef" },
                        "operator": operator,
                        "value": value,
                    },
                    {"field": "deviceCode", "value": "ordinary-device"},
                    {"field": "clientId", "value": "ordinary-client"},
                    {"field": "userId", "value": owner_id},
                    {"field": "status", "value": "approved"},
                ]),
            )
        })
        .collect()
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "The paired fixture must retain both default-ID configurations, operands, callbacks, and storage observations"
)]
pub(crate) fn load_reference_defaults(
    backend: &str,
) -> Result<Vec<Group>, Box<dyn std::error::Error + Send + Sync>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "tests/fixtures/device-reference-defaults-{backend}-1.7.6.json"
    ));
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(path)?)?;
    assert_eq!(fixture.version, "1.7.6");
    assert_eq!(fixture.backend, backend);
    assert_eq!(fixture.id_generation, "default");
    assert_eq!(
        fixture
            .groups
            .iter()
            .map(|group| group.owner_ref_type)
            .collect::<Vec<_>>(),
        [ReferenceType::Json, ReferenceType::Date]
    );
    for group in &fixture.groups {
        assert!(!group.serial);
        let (owner_id, seed) = match group.owner_ref_type {
            ReferenceType::Json => ("ordinary-owner", json!("ordinary-owner")),
            ReferenceType::Date => ("1", json!(1)),
        };
        assert_eq!(group.owner_id, owner_id);
        let stored = if backend == "memory" {
            seed.clone()
        } else {
            json!(owner_id)
        };
        let expected = inventory(group.owner_ref_type, owner_id);
        assert_eq!(group.cases.len(), expected.len());
        for (case, (name, condition)) in group.cases.iter().zip(expected) {
            assert_eq!(case.name, name);
            assert_eq!(json!(case.condition), condition);
            references::validate_storage(case)?;
            assert!(!case.transaction);
            assert!(case.rollback.is_none());
            assert_eq!(case.seeded.get("ownerRef"), Some(&json!(owner_id)));
            assert_eq!(case.before.len(), 1);
            assert_eq!(
                case.before
                    .first()
                    .and_then(|row| row.get("stored_ownerRef")),
                Some(&stored)
            );
            assert_eq!(
                case.seed_events
                    .iter()
                    .filter(|event| event.get("field") == Some(&json!("ownerRef")))
                    .collect::<Vec<_>>(),
                [
                    &json!({"phase": "input", "field": "ownerRef", "value": seed}),
                    &json!({"phase": "output", "field": "ownerRef", "value": stored}),
                ]
            );
        }
    }
    Ok(fixture.groups)
}
