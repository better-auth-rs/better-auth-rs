use super::contract::{Case, Fixture};
use std::collections::{BTreeMap, BTreeSet};

fn inventory() -> BTreeMap<String, Option<&'static str>> {
    let mut cases = BTreeMap::new();
    let mut add = |name: String, reason| {
        assert!(cases.insert(name, reason).is_none());
    };
    for operator in ["eq", "ne", "lt", "lte", "gt", "gte"] {
        for value in [1, 2, 3] {
            add(format!("number-{operator}-{value}"), None);
        }
    }
    for operator in ["contains", "starts_with", "ends_with"] {
        for suffix in ["match", "miss", "insensitive", "wildcard"] {
            add(format!("text-{operator}-{suffix}"), None);
        }
        add(format!("null-{operator}"), None);
        add(format!("null-{operator}-insensitive"), None);
    }
    for operator in ["eq", "ne", "in", "not_in"] {
        add(format!("text-{operator}-insensitive"), None);
        add(format!("null-{operator}"), None);
        add(format!("missing-{operator}"), None);
        for source in ["same-object", "new-object"] {
            add(
                format!("date-{operator}-{source}"),
                Some("Device ownership guards reject Date fields"),
            );
        }
    }
    for name in [
        "number-numeric-string",
        "number-mixed-candidates",
        "number-string-candidates",
        "text-utf16-order",
        "text-lowercase-expansion",
        "text-underscore-pattern",
        "text-backslash-pattern",
        "text-numeric-coercion",
        "text-insensitive-range",
        "text-mixed-insensitive-candidates",
        "null-range",
        "missing-range",
        "null-range-value",
        "boolean-string-true",
        "boolean-string-false",
        "boolean-candidates",
        "array-contains",
        "array-insensitive-contains",
        "json-eq-same-object",
        "json-eq-new-object",
        "mapped-physical-name",
        "transaction-text",
        "transaction-range-miss",
        "transaction-pattern-error",
    ] {
        add(name.into(), None);
    }
    for name in ["number-nan", "number-infinity"] {
        add(
            name.into(),
            Some("Device ownership guards reject non-finite numbers"),
        );
    }
    for name in ["date-range", "date-iso-string", "date-invalid-query"] {
        add(
            name.into(),
            Some("Device ownership guards reject Date fields"),
        );
    }
    for name in ["array-eq-same-object", "array-eq-new-object"] {
        add(
            name.into(),
            Some("Device ownership guards reject native array equality"),
        );
    }
    for name in [
        "serial-reference-string",
        "serial-reference-null",
        "serial-reference-candidates",
    ] {
        add(name.into(), None);
    }
    cases
}

pub(crate) fn paired<'a>(fixture: &'a Fixture, backend: &str) -> Vec<(bool, Vec<&'a Case>)> {
    assert_eq!(fixture.version, "1.7.6");
    assert_eq!(fixture.backend, backend);
    assert_eq!(
        fixture
            .groups
            .iter()
            .map(|group| group.serial)
            .collect::<Vec<_>>(),
        [false, true]
    );
    let inventory = inventory();
    let captured = fixture
        .groups
        .iter()
        .flat_map(|group| &group.cases)
        .collect::<Vec<_>>();
    assert_eq!(captured.len(), 90);
    assert_eq!(
        captured
            .iter()
            .map(|case| case.name.as_str())
            .collect::<BTreeSet<_>>(),
        inventory.keys().map(String::as_str).collect()
    );
    let unpaired = inventory
        .iter()
        .filter_map(|(name, reason)| reason.map(|reason| (name, reason)))
        .collect::<Vec<_>>();
    assert_eq!(unpaired.len(), 15);
    eprintln!("Device Where cases that remain unpaired: {unpaired:?}");
    eprintln!(
        "JavaScript Error.name and Rust AuthError identity remain unpaired. Database wrappers retain their Rust diagnostics."
    );
    let paired = fixture
        .groups
        .iter()
        .map(|group| {
            (
                group.serial,
                group
                    .cases
                    .iter()
                    .filter(|case| inventory.get(&case.name) == Some(&None))
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        paired.iter().map(|(_, cases)| cases.len()).sum::<usize>(),
        75
    );
    assert_eq!(
        paired
            .iter()
            .map(|(_, cases)| cases.len())
            .collect::<Vec<_>>(),
        [72, 3]
    );
    paired
}

pub(crate) fn paired_transactions<'a>(fixture: &'a Fixture, backend: &str) -> Vec<&'a Case> {
    assert_eq!(fixture.version, "1.7.6");
    assert_eq!(fixture.backend, backend);
    assert_eq!(
        fixture
            .groups
            .iter()
            .map(|group| group.serial)
            .collect::<Vec<_>>(),
        [false]
    );
    let mut inventory = inventory()
        .into_iter()
        .filter(|(name, _)| {
            name.starts_with("date-")
                || name.starts_with("array-eq-")
                || name.starts_with("json-eq-")
                || matches!(name.as_str(), "number-nan" | "number-infinity")
        })
        .map(|(name, reason)| (format!("transaction-existing-{name}"), reason))
        .collect::<BTreeMap<_, _>>();
    for (name, reason) in [
        (
            "date-eq-same-object",
            Some("Device ownership guards reject Date fields"),
        ),
        (
            "date-ne-same-object",
            Some("Device ownership guards reject Date fields"),
        ),
        (
            "date-in-same-object",
            Some("Device ownership guards reject Date fields"),
        ),
        (
            "date-not_in-same-object",
            Some("Device ownership guards reject Date fields"),
        ),
        (
            "array-eq-same-object",
            Some("Device ownership guards reject native array equality"),
        ),
        ("json-eq-same-object", None),
    ] {
        assert!(
            inventory
                .insert(format!("transaction-selected-{name}"), reason)
                .is_none()
        );
    }
    let captured = fixture
        .groups
        .iter()
        .flat_map(|group| &group.cases)
        .collect::<Vec<_>>();
    assert_eq!(captured.len(), 23);
    assert_eq!(
        captured
            .iter()
            .map(|case| case.name.as_str())
            .collect::<BTreeSet<_>>(),
        inventory.keys().map(String::as_str).collect()
    );
    let unpaired = inventory
        .iter()
        .filter_map(|(name, reason)| reason.map(|reason| (name, reason)))
        .collect::<Vec<_>>();
    assert_eq!(unpaired.len(), 20);
    eprintln!("Device transaction Where cases that remain unpaired: {unpaired:?}");
    let paired = captured
        .into_iter()
        .filter(|case| inventory.get(&case.name) == Some(&None))
        .collect::<Vec<_>>();
    assert_eq!(paired.len(), 3);
    paired
}
