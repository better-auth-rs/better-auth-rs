#![cfg(feature = "seaorm2")]

use better_auth_core::{
    AuthConfig, AuthError, AuthRecordFields, AuthResponse, AuthResult, AuthSchema, AuthStore,
    CreateUser, FieldMap, FieldValue, ListUsersParams, Member, Organization,
    organization_fields::OrganizationFields,
    store::{EphemeralStore, MemberUser},
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldReference, UserFieldTransform,
    },
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, EntityTrait, QueryOrder, Schema},
    store::entities,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::prelude::*;

#[path = "organization_member_join_reference_tests/fixture.rs"]
mod fixture;
#[path = "organization_member_join_reference_tests/models.rs"]
mod models;
#[path = "organization_member_join_reference_tests/observe.rs"]
mod observe;
#[path = "organization_member_join_reference_tests/policies.rs"]
mod policies;
#[path = "organization_member_join_reference_tests/singular_existing.rs"]
mod singular_existing;
#[path = "organization_member_join_reference_tests/storage.rs"]
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
    raw.configure_organization_fields(policies::organization_fields(&scenario.storage(), None)?)?;
    if case.populated {
        storage::seed(raw.as_ref(), scenario).await?;
    }
    let before = storage::snapshot(raw.as_ref(), database).await?;
    let expected_operations = case
        .operations
        .iter()
        .filter(|operation| operation.surface == "organization")
        .collect::<Vec<_>>();
    assert_eq!(expected_operations.len(), 2, "{case:?}");
    for operation in expected_operations {
        let events = Events::default();
        let store = raw.with_runtime(
            Arc::new(policies::config(scenario, case.joins, Some(&events))?),
            Vec::new(),
            Default::default(),
        )?;
        store.configure_organization_fields(policies::organization_fields(
            scenario,
            Some(&events),
        )?)?;
        let result = async {
            match operation.path.as_str() {
                "by-org" => store.get_member_with_user("organization-a", "user-a").await,
                "by-id" => store.get_member_by_id_with_user("member-a").await,
                path => Err(AuthError::internal(format!(
                    "Unknown member join fixture path: {path}"
                ))),
            }
        }
        .with_subscriber(tracing_subscriber::registry().with(events.clone()))
        .await;
        assert_eq!(
            events.take(),
            operation.events,
            "{case:?}: {}",
            operation.path
        );
        observe::assert_result(result, operation, case)?;
        assert!(operation.storage_unchanged, "{case:?}");
        assert_eq!(
            storage::snapshot(raw.as_ref(), database).await?,
            before,
            "{case:?}: {}",
            operation.path
        );
    }
    Ok(())
}

#[tokio::test]
async fn memory_member_user_references_match_upstream_organization_contract() -> AuthResult<()> {
    let fixture = Fixture::read()?;
    for case in fixture.cases.iter().filter(|case| case.backend == "memory") {
        let scenario = fixture.scenario(&case.scenario)?;
        let raw = Arc::new(EphemeralStore::new(Arc::new(policies::config(
            &scenario.storage(),
            case.joins,
            None,
        )?)));
        contract(raw, None, scenario, case).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_member_user_references_match_upstream_organization_contract() -> AuthResult<()> {
    let fixture = Fixture::read()?;
    for case in fixture.cases.iter().filter(|case| case.backend == "sqlite") {
        let database = storage::sqlite().await?;
        let scenario = fixture.scenario(&case.scenario)?;
        let raw = Arc::new(
            SeaOrmStore::<models::Core>::new(
                policies::config(&scenario.storage(), case.joins, None)?,
                database.clone(),
            )
            .with_organization_schema::<models::Organizations>(),
        );
        contract(raw, Some(&database), scenario, case).await?;
    }
    Ok(())
}
