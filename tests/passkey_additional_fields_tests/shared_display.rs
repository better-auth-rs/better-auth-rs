use super::{contract, display_fixture};
use better_auth::{
    __private_core::{
        AuthError,
        store::EphemeralStore,
        user_fields::{UserConfig, UserFieldConfig},
    },
    BetterAuth,
};
use serde_json::{Value, json};
use std::sync::Arc;

#[path = "../support/passkey_shared_display_model.rs"]
mod fixture;
#[path = "../support/passkey_shared_display_contract.rs"]
mod shared;
use shared::{TestResult, Trace, config, policies, run, take};

async fn paired(backend: &str) -> TestResult {
    let fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/passkey-shared-display-1.7.6.json"
    ))?;
    assert_eq!(fixture.get("version").ok_or("Captured version")?, "1.7.6");
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("Captured shared display cases")?;
    assert_eq!(cases.len(), 4);
    let mut selected = Vec::new();
    for case in cases {
        if case.get("backend").ok_or("Captured backend")? == backend {
            selected.push(case);
        }
    }
    assert_eq!(
        selected
            .iter()
            .map(|case| case
                .get("declarationOrder")
                .ok_or("Captured declaration order"))
            .collect::<Result<Vec<_>, _>>()?,
        [&json!(["name", "aaguid"]), &json!(["aaguid", "name"])]
    );
    for case in selected {
        assert_eq!(
            case.get("table").ok_or("Captured table")?,
            "shared_display_passkey"
        );
        assert_eq!(case.get("column").ok_or("Captured column")?, "display");
        if backend == "memory" {
            run(
                Arc::new(EphemeralStore::new(Arc::new(config()))),
                None,
                case,
            )
            .await?;
        } else {
            let (store, database) =
                display_fixture::sqlite::<fixture::model::Model>(config()).await;
            run(Arc::new(store), Some(&database), case).await?;
            database.close().await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn memory_shared_passkey_display_matches_pinned_operations() -> TestResult {
    paired("memory").await
}

#[tokio::test]
async fn sqlite_shared_passkey_display_matches_pinned_operations() -> TestResult {
    paired("sqlite").await
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The configuration contract asserts exact initialization results while propagating database cleanup errors"
)]
async fn missing_passkey_display_requires_explicit_shared_storage() -> TestResult {
    let incomplete = UserConfig {
        additional_fields: Some(
            [(
                "name".into(),
                UserFieldConfig {
                    field_name: Some("display".into()),
                    ..Default::default()
                },
            )]
            .into(),
        ),
    };
    let mut missing_column = policies(false, None);
    for field in missing_column.fields_mut().values_mut() {
        field.field_name = Some("missing_display".into());
    }
    for (declaration, expected_error) in [
        (
            UserConfig::default(),
            Some("Unknown plugin model column: aaguid"),
        ),
        (incomplete, Some("Unknown plugin model column: aaguid")),
        (
            missing_column,
            Some("Unknown plugin model column: missing_display"),
        ),
        (policies(false, None), None),
    ] {
        let (store, database) = display_fixture::sqlite::<fixture::model::Model>(config()).await;
        let result = BetterAuth::new(config())
            .store(store)
            .plugin(contract::Fields(declaration))
            .build()
            .await;
        if let Some(expected) = expected_error {
            assert!(
                matches!(result, Err(AuthError::Config(ref error)) if error == expected),
                "Expected {expected}: {:?}",
                result.err()
            );
        } else {
            assert!(result.is_ok(), "Valid shared display: {:?}", result.err());
        }
        database.close().await?;
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The security contract asserts exact rejection and zero callbacks while propagating database cleanup errors"
)]
async fn shared_passkey_display_cannot_replace_protected_physical_columns() -> TestResult {
    for column in ["stored_owner", "stored_credential", "stored_counter"] {
        let events = Trace::default();
        let mut declaration = policies(false, Some(&events));
        for field in declaration.fields_mut().values_mut() {
            field.field_name = Some(column.into());
        }
        let (store, database) =
            display_fixture::sqlite::<fixture::protected::Model>(config()).await;
        let result = BetterAuth::new(config())
            .store(store)
            .plugin(contract::Fields(declaration))
            .build()
            .await;
        assert!(
            matches!(result, Err(AuthError::Config(ref message)) if message == "Passkey shared display fields cannot replace an identity or credential column"),
            "Protected shared column {column}: {:?}",
            result.err()
        );
        assert!(take(&events).is_empty(), "Rejected shared column {column}");
        database.close().await?;
    }
    Ok(())
}
