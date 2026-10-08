#![cfg(feature = "seaorm2")]

use better_auth_core::{
    AuthError, AuthResult, AuthSchema, AuthStore, Member, MemberUserView,
    store::ListOrganizationMembersParams,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;

#[path = "organization_member_json_filter_reference_tests/policies.rs"]
mod policies;
#[path = "organization_member_json_filter_reference_tests/storage.rs"]
mod storage;
#[path = "support/device_where_values.rs"]
mod values;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    version: String,
    field: Value,
    backends: Vec<Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Input {
    organization_id: &'static str,
    limit: u32,
    offset: u32,
    sort_by: &'static str,
    sort_order: &'static str,
    filter: Filter,
}

#[derive(Serialize)]
struct Filter {
    field: &'static str,
    value: Value,
    operator: &'static str,
}

impl Input {
    fn params(&self) -> AuthResult<ListOrganizationMembersParams> {
        Ok(ListOrganizationMembersParams {
            organization_id: self.organization_id.into(),
            limit: Some(f64::from(self.limit)),
            offset: Some(f64::from(self.offset)),
            sort_by: Some(self.sort_by.into()),
            sort_direction: Some(self.sort_order.into()),
            filter_field: Some(self.filter.field.into()),
            filter_value: Some(values::revive(&self.filter.value)?),
            filter_operator: Some(self.filter.operator.into()),
        })
    }
}

#[derive(Serialize)]
struct JoinedMember<'a> {
    #[serde(flatten)]
    member: &'a Member,
    user: MemberUserView,
}

async fn query<S: AuthSchema>(store: &dyn AuthStore<S>, input: &Input) -> AuthResult<Value> {
    let (members, total) = store.query_organization_members(&input.params()?).await?;
    let ids = members
        .iter()
        .map(|member| member.user_id.typed().cloned())
        .collect::<AuthResult<Vec<_>>>()?;
    let users = store.list_users_by_ids(&ids, members.len() as f64).await?;
    let joined = members
        .iter()
        .map(|member| {
            let user = users
                .iter()
                .find(|user| user.id.as_str() == member.user_id.as_str())
                .ok_or_else(|| AuthError::internal("Member JSON filter user is missing"))?;
            Ok(JoinedMember {
                member,
                user: MemberUserView::from_user(user),
            })
        })
        .collect::<AuthResult<Vec<_>>>()?;
    Ok(json!({ "members": joined, "total": total }))
}

#[tokio::test]
async fn sqlite_member_json_filters_match_upstream() -> AuthResult<()> {
    let fixture: Fixture =
        serde_json::from_str(include_str!("fixtures/member-json-filter-1.7.6.json"))?;
    assert_eq!(fixture.version, "1.7.6");
    assert_eq!(
        fixture.field,
        json!({ "name": "settings", "type": "json", "fieldName": "stored_settings" })
    );
    assert_eq!(
        fixture
            .backends
            .iter()
            .filter_map(|entry| entry.get("backend").and_then(Value::as_str))
            .collect::<Vec<_>>(),
        ["memory", "sqlite"]
    );
    let expected = fixture
        .backends
        .iter()
        .find(|entry| entry.get("backend").and_then(Value::as_str) == Some("sqlite"))
        .ok_or_else(|| AuthError::internal("SQLite Member JSON filter fixture is missing"))?;
    let (reader, database) = storage::sqlite().await?;
    reader.configure_organization_fields(policies::fields(None))?;
    let store =
        reader.with_runtime(Arc::new(policies::config()), Vec::new(), Default::default())?;
    let events = policies::Events::default();
    store.configure_organization_fields(policies::fields(Some(&events)))?;
    let created = storage::seed(store.as_ref()).await?;
    let seed_events = events.take()?;
    let stored = storage::members(reader.as_ref()).await?;
    assert!(
        events.take()?.is_empty(),
        "The storage reader has no callbacks"
    );
    let before = storage::physical(&database).await?;
    let mut operations = Vec::new();
    for (name, operator, value, limit) in [
        ("array-eq", "eq", json!(["red", "blue"]), 10),
        ("array-in", "in", json!(["red", "blue"]), 10),
        ("array-not-in", "not_in", json!(["red", "blue"]), 1),
        ("object-eq", "eq", json!({ "control": true }), 10),
    ] {
        let input = Input {
            organization_id: storage::ORGANIZATION_ID,
            limit,
            offset: 0,
            sort_by: "id",
            sort_order: "asc",
            filter: Filter {
                field: "settings",
                value,
                operator,
            },
        };
        let result = query(store.as_ref(), &input).await?;
        let query_events = events.take()?;
        let persisted = storage::members(reader.as_ref()).await?;
        assert!(
            events.take()?.is_empty(),
            "{name}: the reader has no callbacks"
        );
        assert_eq!(storage::physical(&database).await?, before, "{name}");
        operations.push(json!({
            "name": name,
            "input": input,
            "result": result,
            "error": null,
            "events": query_events,
            "stored": persisted,
        }));
    }
    assert_eq!(
        json!({
            "backend": "sqlite",
            "created": created,
            "seedEvents": seed_events,
            "stored": stored,
            "operations": operations,
        }),
        *expected
    );
    Ok(())
}
