use super::*;
use better_auth::server_api::EndpointInput;
use better_auth_core::{CreateMember, HttpMethod};
use std::collections::HashMap;

fn declarations(events: &Events) -> UserConfig {
    let key_input = events.clone();
    let key_output = events.clone();
    let date_input = events.clone();
    let date_output = events.clone();
    let probe_input = events.clone();
    let probe_output = events.clone();
    let stamp_input = events.clone();
    let stamp_output = events.clone();
    declaration([
        ("teamId", identity("teamId", events)),
        (
            "membershipKey",
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |value| {
                        key_input.push("membershipKey", "input", value.clone())?;
                        Ok(format!(
                            "stored:{}",
                            required(value.as_str(), "Expected a membership key")?
                        )
                        .into())
                    })),
                    output: Some(UserFieldTransform::new(move |value| {
                        key_output.push("membershipKey", "output", value.clone())?;
                        Ok(format!(
                            "visible:{}",
                            required(value.as_str(), "Expected a stored membership key")?
                        )
                        .into())
                    })),
                }),
                ..Default::default()
            },
        ),
        (
            "createdAt",
            UserFieldConfig {
                field_type: UserFieldType::Date,
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |value| {
                        date_input.service_date(value)?;
                        Ok(date(3).into())
                    })),
                    output: Some(UserFieldTransform::new(move |value| {
                        date_output.push("createdAt", "output", value)?;
                        Ok(7.into())
                    })),
                }),
                ..Default::default()
            },
        ),
        (
            "probe",
            UserFieldConfig {
                field_name: Some("membershipKey".into()),
                default_value: Some(" Default ".into()),
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |value| {
                        probe_input.push("probe", "input", value.clone())?;
                        Ok(required(value.as_str(), "Expected probe default")?
                            .trim()
                            .into())
                    })),
                    output: Some(UserFieldTransform::new(move |value| {
                        probe_output.push("probe", "output", value)?;
                        Ok(FieldValue::Undefined)
                    })),
                }),
                ..Default::default()
            },
        ),
        (
            "stamp",
            UserFieldConfig {
                field_type: UserFieldType::Date,
                field_name: Some("createdAt".into()),
                default_value: Some(date(5).into()),
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |value| {
                        stamp_input.push("stamp", "input", value.clone())?;
                        Ok(value)
                    })),
                    output: Some(UserFieldTransform::new(move |value| {
                        stamp_output.push("stamp", "output", value)?;
                        Ok(date(6).into())
                    })),
                }),
                ..Default::default()
            },
        ),
    ])
}

fn output(before: bool) -> FieldMap {
    let mut value = member(
        "member-a",
        "team-a",
        "user-a",
        if before { date(5).into() } else { 7.into() },
    );
    value.extend([
        ("probe".into(), FieldValue::Undefined),
        ("stamp".into(), date(6).into()),
    ]);
    value
}

fn output_events(storage: &Storage, before: bool) -> Vec<FieldValue> {
    let mut events = Vec::new();
    if !before {
        events.extend([
            event("teamId", "output", "team-a".into()),
            event("membershipKey", "output", "Default".into()),
            event("createdAt", "output", storage.stored_date(5)),
        ]);
    }
    events.extend([
        event("probe", "output", "Default".into()),
        event("stamp", "output", storage.stored_date(5)),
    ]);
    events
}

async fn check<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    before: bool,
) -> AuthResult<()> {
    let events = Events::default();
    let auth = reader(raw, declarations(&events), None, before, false, "member-a").await?;
    let store = auth.store();
    let expected = output(before);
    let projected = output_events(&storage, before);
    let rows = vec![physical("member-a", "team-a", "user-a", "Default", 5)];
    let started = chrono::Utc::now().timestamp_millis();
    let created = required(
        store
            .add_team_member(&"team-a".into(), "user-a", None)
            .await?,
        "Expected new membership",
    )?;
    assert_eq!(public(created)?, expected);
    events.assert_dates(
        usize::from(!before),
        started,
        chrono::Utc::now().timestamp_millis(),
    )?;
    let mut input = Vec::new();
    if !before {
        input.extend([
            event("teamId", "input", "team-a".into()),
            event("membershipKey", "input", key("team-a", "user-a")?.into()),
            event("createdAt", "input", "native-date".into()),
        ]);
    }
    input.extend([
        event("probe", "input", " Default ".into()),
        event("stamp", "input", date(5).into()),
    ]);
    input.extend(projected.clone());
    assert_eq!(events.take()?, input);
    storage.assert_rows(rows.clone(), [1, 0]).await?;
    assert_eq!(
        public(required(
            store.get_team_member("team-a", "user-a").await?,
            "Expected existing membership"
        )?)?,
        expected
    );
    assert_eq!(events.take()?, projected);
    assert_eq!(
        store
            .list_team_members("team-a")
            .await?
            .into_iter()
            .map(public)
            .collect::<AuthResult<Vec<_>>>()?,
        [expected.clone()]
    );
    assert_eq!(events.take()?, projected);
    assert_eq!(
        public(required(
            store
                .add_team_member(&"team-a".into(), "user-a", None)
                .await?,
            "Expected repeated membership"
        )?)?,
        expected
    );
    assert_eq!(events.take()?, projected);
    assert_eq!(store.count_team_members("team-a").await?, 1);
    assert!(
        store
            .add_team_member(&"team-a".into(), "user-b", Some(1))
            .await?
            .is_none()
    );
    assert_eq!(events.take()?, []);
    assert_eq!(
        public(required(
            store
                .add_team_member(&"team-a".into(), "user-a", Some(0))
                .await?,
            "Existing membership must precede capacity check"
        )?)?,
        expected
    );
    assert_eq!(events.take()?, projected);
    storage.assert_rows(rows, [1, 0]).await?;
    for _ in 0..2 {
        store.remove_team_member("team-a", "user-a").await?;
        assert_eq!(events.take()?, []);
        storage.assert_rows(vec![], [0, 0]).await?;
    }
    Ok(())
}

async fn native_api<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>, storage: Storage) -> AuthResult<()> {
    let _ = raw
        .create_member(CreateMember::new("organization", "user-a", "owner"))
        .await?;
    let events = Events::default();
    let auth = reader(raw, declarations(&events), None, false, false, "member-a").await?;
    let session = auth
        .store()
        .create_session(CreateSession {
            inherited_fields: Default::default(),
            user_id: "user-a".into(),
            expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).into(),
            active_organization_id: Some("organization".into()),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            additional_fields: Default::default(),
        })
        .await?;
    let headers = HashMap::from([(
        "cookie".into(),
        format!(
            "better-auth.session_token={}",
            better_auth_core::utils::cookie_utils::sign_cookie_value(
                session.token.typed()?,
                auth.config().signing_secret()
            ),
        ),
    )]);
    let added = auth
        .call_endpoint(
            HttpMethod::Post,
            "/organization/add-team-member",
            EndpointInput {
                body: Some(
                    json!({"organizationId":"organization","teamId":"team-a","userId":"user-a"}),
                ),
                headers: Some(headers.clone()),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(added.status, 200);
    assert_eq!(added.body.field_value()?, FieldValue::from(output(false)));
    let listed = auth
        .call_endpoint(
            HttpMethod::Get,
            "/organization/list-team-members",
            EndpointInput {
                query: Some(json!({"teamId":"team-a"})),
                headers: Some(headers),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(listed.status, 200);
    assert_eq!(
        listed.body.field_value()?,
        FieldValue::from(vec![FieldValue::from(output(false))])
    );
    storage
        .assert_rows(
            vec![physical("member-a", "team-a", "user-a", "Default", 5)],
            [1, 0],
        )
        .await
}

#[tokio::test]
async fn memory_team_member_registration_replaces_complete_fields_in_plugin_order() -> AuthResult<()>
{
    for before in [true, false] {
        let (raw, storage) = memory_fixture().await?;
        check(raw, storage, before).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_team_member_registration_replaces_complete_fields_in_plugin_order() -> AuthResult<()>
{
    for before in [true, false] {
        let (raw, storage) = sqlite_fixture().await?;
        check(raw, storage, before).await?;
    }
    Ok(())
}

#[tokio::test]
async fn memory_team_member_api_preserves_undefined_and_cross_type_native_outputs() -> AuthResult<()>
{
    let (raw, storage) = memory_fixture().await?;
    native_api(raw, storage).await
}

#[tokio::test]
async fn sqlite_team_member_api_preserves_undefined_and_cross_type_native_outputs() -> AuthResult<()>
{
    let (raw, storage) = sqlite_fixture().await?;
    native_api(raw, storage).await
}
