//! Replay native invitation consumers against frozen Memory and SQLite observations.

#![expect(
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Frozen captures require complete native graphs, callback order, and storage equality."
)]

use better_auth_core::{
    AuthConfig, AuthError, AuthPlugin, AuthResult, AuthSchema, FieldMap, FieldValue, HttpMethod,
    config::{FieldTransforms, UserFieldConfig, UserFieldTransform},
    store::AuthStore,
};
use serde_json::{Value as Json, json};
use std::sync::Arc;

use crate::plugins::{
    organization::{
        OrganizationConfig, OrganizationPlugin,
        hooks::{OrganizationHooks, OrganizationInvitationEvent},
    },
    test_helpers::{self, native_email_consumers as shared, native_session},
};
use shared::Trace;

mod probe;
mod sqlite;

const SELECTED_EMAIL: &str = "SELECTED@native-email-consumers.test";

struct NoMutation;

#[async_trait::async_trait]
impl OrganizationHooks for NoMutation {
    async fn before_accept_invitation(&self, _: OrganizationInvitationEvent<'_>) -> AuthResult<()> {
        Err(better_auth_core::AuthError::internal(
            "Unexpected beforeAcceptInvitation",
        ))
    }

    async fn after_accept_invitation(
        &self,
        _: &better_auth_core::Member,
        _: OrganizationInvitationEvent<'_>,
    ) -> AuthResult<()> {
        Err(better_auth_core::AuthError::internal(
            "Unexpected afterAcceptInvitation",
        ))
    }

    async fn before_reject_invitation(&self, _: OrganizationInvitationEvent<'_>) -> AuthResult<()> {
        Err(better_auth_core::AuthError::internal(
            "Unexpected beforeRejectInvitation",
        ))
    }

    async fn after_reject_invitation(&self, _: OrganizationInvitationEvent<'_>) -> AuthResult<()> {
        Err(better_auth_core::AuthError::internal(
            "Unexpected afterRejectInvitation",
        ))
    }
}

fn plugin(trace: &Arc<Trace>, replacement: Option<FieldValue>) -> OrganizationPlugin {
    let mut config = OrganizationConfig {
        require_email_verification_on_invitation: true,
        hooks: Some(Arc::new(NoMutation)),
        ..Default::default()
    };
    let input_trace = trace.clone();
    let output_trace = trace.clone();
    let _ = config.schema.invitation.fields_mut().insert(
        "email".into(),
        UserFieldConfig {
            required: Some(true),
            field_name: Some("recipient_address".into()),
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    input_trace.record(
                        "invitation.email:input",
                        FieldMap::from([("value".into(), value.clone())]),
                    )?;
                    Ok(value)
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    output_trace.record(
                        "invitation.email:output",
                        FieldMap::from([("value".into(), value.clone())]),
                    )?;
                    Ok(replacement.clone().unwrap_or(value))
                })),
            }),
            ..Default::default()
        },
    );
    OrganizationPlugin { config }
}

struct Invocation<'a> {
    trace: &'a Arc<Trace>,
    user: FieldValue,
    method: HttpMethod,
    path: &'static str,
    body: Json,
    query: Option<Json>,
    failure: &'a FieldValue,
}

async fn dispatch<S: AuthSchema>(
    config: Arc<AuthConfig>,
    store: Arc<dyn AuthStore<S>>,
    probe: &Arc<probe::State>,
    plugin: &OrganizationPlugin,
    invocation: Invocation<'_>,
) -> AuthResult<FieldValue> {
    let now = shared::clock()?;
    let store = Arc::new(probe::Store {
        inner: store,
        state: probe.clone(),
    });
    let mut context = test_helpers::initialize_test_context(config, store, &[plugin])
        .await?
        .with_clock(move || now);
    let mut request = shared::native_request(
        invocation.trace,
        &mut context,
        <OrganizationPlugin as AuthPlugin<S>>::routes(plugin),
        invocation.user,
        invocation.method,
        invocation.path,
        invocation.body,
    )?;
    request.query = invocation.query;
    invocation.trace.endpoint_outcome(
        probe
            .capture(native_session::dispatch_plugin(&request, &context, plugin))
            .await,
        invocation.failure,
    )
}

async fn invitation_case(case: &Json, index: usize) -> AuthResult<Vec<String>> {
    let skipped: &[usize] = if index == 8 { &[1, 9, 10] } else { &[1] };
    let trace = Trace::with_unpaired_events(case, format!("/cases/{index}"), skipped);
    let mode = case["scenario"]["mode"].as_str().unwrap();
    let failure = shared::throwing_value("invitation-lower");
    let left_result: FieldValue =
        FieldMap::from([("marker".into(), "comparison-result".into())]).into();
    let right_result = if mode == "distinct-objects" {
        FieldMap::from([("marker".into(), "comparison-result".into())]).into()
    } else {
        left_result.clone()
    };
    let left = shared::native_lower(
        &trace,
        "invitation.email",
        left_result.clone(),
        failure.clone(),
        (mode == "left-getter-error").then_some("get"),
    );
    let right = shared::native_lower(
        &trace,
        "user.email",
        right_result.clone(),
        failure.clone(),
        (mode == "right-call-error").then_some("call"),
    );
    let user = shared::native_user(
        &trace,
        {
            let value = right.value.clone();
            move |_| Ok(value.clone())
        },
        true.into(),
    );
    let mut values = FieldMap::from([
        ("left".into(), left.value.clone()),
        ("right".into(), right.value.clone()),
        ("leftResult".into(), left_result),
        ("rightResult".into(), right_result),
        ("user".into(), user.root.value.clone()),
        ("failure".into(), failure.clone()),
    ]);
    trace.snapshot("input", &values.clone().into())?;
    let config = Arc::new(shared::config());
    let raw = shared::memory_from_capture(case, config.clone())?;
    let probe = Arc::new(probe::State::default());
    let plugin = plugin(&trace, Some(left.value.clone()));
    let route = case["scenario"]["route"].as_str().unwrap();
    let (method, path, body, query) = match route {
        "get" => (
            HttpMethod::Get,
            "/organization/get-invitation",
            Json::Null,
            Some(json!({"id":"invitation"})),
        ),
        "accept" => (
            HttpMethod::Post,
            "/organization/accept-invitation",
            json!({"invitationId":"invitation"}),
            None,
        ),
        "reject" => (
            HttpMethod::Post,
            "/organization/reject-invitation",
            json!({"invitationId":"invitation"}),
            None,
        ),
        _ => return Err(AuthError::internal("Unknown native email invitation route")),
    };
    trace.snapshot("before", &shared::memory_snapshot(&raw)?)?;
    let response = dispatch(
        config,
        raw.clone(),
        &probe,
        &plugin,
        Invocation {
            trace: &trace,
            user: user.root.value.clone(),
            method,
            path,
            body,
            query,
            failure: &failure,
        },
    )
    .await?;
    trace.snapshot("after", &shared::memory_snapshot(&raw)?)?;
    assert_eq!(case["reads"], user.reads());
    assert_eq!(user.reads(), usize::from(mode != "left-getter-error"));
    let calls = probe.calls()?;
    let expected = if mode == "same-object" {
        vec![
            ("invitation", vec!["invitation"]),
            ("organization", vec!["organization"]),
            ("member", vec!["organization", "inviter"]),
        ]
    } else {
        vec![("invitation", vec!["invitation"])]
    };
    assert_eq!(calls.len(), expected.len());
    for (call, (operation, arguments)) in calls.iter().zip(expected) {
        assert_eq!(call.operation, operation);
        assert_eq!(
            call.arguments,
            arguments
                .into_iter()
                .map(FieldValue::from)
                .collect::<Vec<_>>()
        );
    }
    if mode == "same-object" {
        assert!(response.model_property("email")?.strict_equals(&left.value));
    }
    let _ = values.insert("response".into(), response);
    trace.snapshot("afterValues", &values.into())?;
    trace.finish()
}

async fn selector_case(case: &Json, index: usize) -> AuthResult<Vec<String>> {
    let mode = case["scenario"]["mode"].as_str().unwrap();
    let sqlite = case["scenario"]["backend"] == "sqlite";
    let trace = Trace::with_unpaired_events(
        case,
        format!("/cases/{index}"),
        if mode == "non-callable" { &[] } else { &[5] },
    );
    let failure = shared::throwing_value("selector-lower");
    let selector: FieldValue = match mode {
        "zero" => 0.into(),
        "non-callable" => 17.into(),
        "string" => SELECTED_EMAIL.into(),
        _ => return Err(AuthError::internal("Unknown native email selector mode")),
    };
    let lower = (mode != "non-callable").then(|| {
        shared::native_lower(
            &trace,
            "user.email",
            selector.clone(),
            failure.clone(),
            None,
        )
    });
    let email = lower
        .as_ref()
        .map_or_else(|| selector.clone(), |root| root.value.clone());
    let user = shared::native_user(
        &trace,
        {
            let email = email.clone();
            move |_| Ok(email.clone())
        },
        true.into(),
    );
    let mut values = FieldMap::from([
        ("email".into(), email.clone()),
        ("selector".into(), selector),
        ("user".into(), user.root.value.clone()),
        ("failure".into(), failure.clone()),
    ]);
    trace.snapshot("input", &values.clone().into())?;
    let config = Arc::new(shared::config());
    let probe = Arc::new(probe::State::default());
    let plugin = plugin(&trace, None);
    let invocation = Invocation {
        trace: &trace,
        user: user.root.value.clone(),
        method: HttpMethod::Get,
        path: "/organization/list-user-invitations",
        body: Json::Null,
        query: Some(json!({"email":"fallback@native-email-consumers.test"})),
        failure: &failure,
    };
    let response = if sqlite {
        let (store, database) = sqlite::store(case, config.clone()).await?;
        trace.snapshot("before", &sqlite::snapshot(&database).await?)?;
        let result = dispatch(config, store, &probe, &plugin, invocation).await?;
        trace.snapshot("after", &sqlite::snapshot(&database).await?)?;
        result
    } else {
        let raw = shared::memory_from_capture(case, config.clone())?;
        trace.snapshot("before", &shared::memory_snapshot(&raw)?)?;
        let result = dispatch(config, raw.clone(), &probe, &plugin, invocation).await?;
        trace.snapshot("after", &shared::memory_snapshot(&raw)?)?;
        result
    };
    assert_eq!(case["reads"], user.reads());
    assert_eq!(user.reads(), 1);
    let calls = probe.calls()?;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].operation, "list");
    assert_eq!(calls[0].arguments.len(), 1);
    assert!(
        calls[0].arguments[0].strict_equals(&email),
        "The Store receives the original selector receiver"
    );
    if let Some(lower) = lower {
        assert_eq!(lower.value.model_property("calls")?, FieldValue::from(1));
        let ids = response
            .as_array()
            .unwrap()
            .iter()?
            .map(|row| row?.model_property("id"))
            .collect::<AuthResult<Vec<_>>>()?;
        let expected = match (sqlite, mode) {
            (false, "zero") => vec![],
            (true, "zero") => vec![FieldValue::from("invitation-zero")],
            (_, "string") => vec![FieldValue::from("invitation-selected")],
            _ => return Err(AuthError::internal("Unknown native email selector result")),
        };
        assert_eq!(ids, expected);
    } else {
        assert!(response.is_undefined());
    }
    if !sqlite {
        let queries = probe.queries()?;
        let expected = match mode {
            "zero" => vec!["db findMany invitation"],
            "string" => vec!["db findMany invitation", "db findOne organization"],
            "non-callable" => vec![],
            _ => return Err(AuthError::internal("Unknown native email query order")),
        };
        assert_eq!(queries, expected);
    }
    let _ = values.insert("response".into(), response);
    trace.snapshot("afterValues", &values.into())?;
    trace.finish()
}

fn assert_coverage(mut paths: Vec<String>, group: &str) -> AuthResult<()> {
    paths.sort();
    let coverage: Json = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/native-email-organization-1.7.6.coverage.json"
    )))?;
    assert_eq!(json!(paths), coverage[group]["unpairedPaths"]);
    Ok(())
}

#[tokio::test]
async fn invitation_email_consumers_replay_native_identity_and_errors() -> AuthResult<()> {
    let fixture = shared::fixture()?;
    let mut paths = Vec::new();
    for (index, name) in [
        (8, "invitation/get/same-object"),
        (9, "invitation/get/distinct-objects"),
        (10, "invitation/accept/left-getter-error"),
        (11, "invitation/reject/right-call-error"),
    ] {
        let case = &fixture["cases"][index];
        assert_eq!(case["name"], name);
        paths.extend(invitation_case(case, index).await?);
    }
    assert_coverage(paths, "invitation")
}

#[tokio::test]
async fn invitation_selectors_replay_memory_and_sqlite_native_results() -> AuthResult<()> {
    let fixture = shared::fixture()?;
    let mut paths = Vec::new();
    for (index, name) in [
        (12, "selector/memory/zero"),
        (13, "selector/memory/string"),
        (14, "selector/sqlite/zero"),
        (15, "selector/sqlite/string"),
        (16, "selector/memory/non-callable"),
    ] {
        let case = &fixture["cases"][index];
        assert_eq!(case["name"], name);
        paths.extend(selector_case(case, index).await?);
    }
    assert_coverage(paths, "selector")
}
