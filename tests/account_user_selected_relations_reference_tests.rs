#![cfg(feature = "seaorm2")]

use better_auth::store::{AccountOwner, EphemeralStore, JoinValue, UserAccounts};
use better_auth_core::{
    AuthConfig, AuthError, AuthRecordFields, AuthResult, AuthSchema, AuthStore, CreateAccount,
    CreateUser, FieldDate, FieldMap, FieldValue, ListUsersParams,
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldReference, UserFieldTransform,
    },
    wire::{AccountView, UserView},
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, EntityTrait, QueryOrder, Schema},
    store::{__private_test_support::bundled_schema::BundledSchema, entities},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::prelude::*;

#[path = "account_user_selected_relations_reference_tests/fixture.rs"]
mod fixture;
#[path = "account_user_selected_relations_reference_tests/observe.rs"]
mod observe;
#[path = "account_user_selected_relations_reference_tests/policies.rs"]
mod policies;
#[path = "account_user_selected_relations_reference_tests/storage.rs"]
mod storage;
#[path = "support/device_where_values.rs"]
mod values;

use fixture::{Case, Fixture, Scenario};
use policies::Events;

async fn contract<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    database: Option<&DatabaseConnection>,
    scenario: &Scenario,
    case: &Case,
) -> AuthResult<()> {
    if case.populated {
        storage::seed(raw.as_ref(), scenario).await?;
    }
    let before = storage::snapshot(raw.as_ref(), database).await?;
    for operation in case
        .operations
        .iter()
        .filter(|operation| operation.surface == "internal")
    {
        let events = Events::default();
        let store = raw.with_runtime(
            Arc::new(policies::config(scenario, case.joins, Some(&events))?),
            Vec::new(),
            Default::default(),
        )?;
        let result = async {
            match operation.operation.as_str() {
                "owner" => observe::owner(
                    store
                        .get_account_owner("provider", "external-owner")
                        .await?,
                ),
                "accounts" => observe::accounts(
                    store
                        .get_user_with_accounts("a@account-user-selected-relations.test")
                        .await?,
                ),
                operation => Err(AuthError::internal(format!(
                    "Unknown Account/User operation: {operation}"
                ))),
            }
        }
        .with_subscriber(tracing_subscriber::registry().with(events.clone()))
        .await;
        assert_eq!(
            events.take(),
            operation.events,
            "{case:?}: {}",
            operation.operation
        );
        observe::assert_result(result, operation, case)?;
        assert!(operation.storage_unchanged, "{case:?}");
        assert_eq!(
            storage::snapshot(raw.as_ref(), database).await?,
            before,
            "{case:?}: {}",
            operation.operation
        );
    }
    Ok(())
}

#[tokio::test]
async fn memory_account_user_selected_relations_match_upstream_internal_reads() -> AuthResult<()> {
    let fixture = Fixture::read()?;
    for case in fixture.cases.iter().filter(|case| case.backend == "memory") {
        let raw = Arc::new(EphemeralStore::new(Arc::new(policies::config(
            &Scenario::default(),
            case.joins,
            None,
        )?)));
        contract(raw, None, fixture.scenario(&case.scenario)?, case).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_account_user_selected_relations_match_upstream_internal_reads() -> AuthResult<()> {
    let fixture = Fixture::read()?;
    for case in fixture.cases.iter().filter(|case| case.backend == "sqlite") {
        let database = storage::sqlite().await?;
        let raw = Arc::new(SeaOrmStore::<BundledSchema>::new(
            policies::config(&Scenario::default(), case.joins, None)?,
            database.clone(),
        ));
        contract(
            raw,
            Some(&database),
            fixture.scenario(&case.scenario)?,
            case,
        )
        .await?;
    }
    Ok(())
}
