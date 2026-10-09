use super::*;
use better_auth::plugins::organization::{
    hooks::{
        OrganizationEndpoint, OrganizationHooks, OrganizationMemberEvent, OrganizationPolicy,
        OrganizationTeamDraft, OrganizationTeamEvent,
    },
    types::OrganizationResponse,
};
use better_auth::server_api::EndpointInput;
use better_auth_core::{FromFieldMap, HttpMethod, Team, user_fields::UserFieldFactory};

struct Callback {
    events: Events,
    team: Team,
}

fn organization_view(organization: &OrganizationResponse) -> FieldMap {
    let mut fields = organization.additional_fields.clone();
    fields.extend([
        ("id".into(), organization.id.field_value()),
        ("name".into(), organization.name.field_value()),
        ("slug".into(), organization.slug.field_value()),
        ("logo".into(), organization.logo.field_value()),
        ("metadata".into(), organization.metadata.field_value()),
        ("createdAt".into(), organization.created_at.field_value()),
    ]);
    fields
}

#[async_trait]
impl OrganizationPolicy for Callback {
    async fn create_default_team(
        &self,
        organization: &OrganizationResponse,
        _: OrganizationEndpoint<'_>,
    ) -> AuthResult<Option<Team>> {
        self.events.push(
            "customCreateDefaultTeam",
            "callback",
            organization_view(organization).into(),
        )?;
        Ok(Some(self.team.clone()))
    }
}

#[async_trait]
impl OrganizationHooks for Callback {
    async fn before_create_team(
        &self,
        data: &mut OrganizationTeamDraft,
        _: &OrganizationResponse,
        _: Option<&FieldValue>,
    ) -> AuthResult<()> {
        assert!(data.id.is_none());
        assert!(data.created_at.is_none());
        assert!(data.updated_at.is_none());
        let mut fields = data.additional_fields.clone();
        fields.extend([
            ("name".into(), data.name.field_value()),
            ("organizationId".into(), data.organization_id.field_value()),
        ]);
        self.events.push("beforeCreateTeam", "hook", fields.into())
    }

    async fn after_create_team(&self, event: OrganizationTeamEvent<'_>) -> AuthResult<()> {
        assert!(
            event
                .team
                .name
                .field_value()
                .strict_equals(&self.team.name.field_value())
        );
        assert_eq!(event.team.field_values()?, self.team.field_values()?);
        self.events
            .push("afterCreateTeam", "hook", event.team.field_values()?.into())
    }

    async fn after_create_organization(
        &self,
        event: OrganizationMemberEvent<'_>,
    ) -> AuthResult<()> {
        trace_lock(&self.events.values)?.push(
            vec![
                "afterCreateOrganization".into(),
                "hook".into(),
                organization_view(event.organization).into(),
                event.member.field_values()?.into(),
            ]
            .into(),
        );
        Ok(())
    }
}

fn fixed_created_at(model: &'static str, events: &Events) -> UserConfig {
    let events = events.clone();
    declaration([(
        "createdAt",
        UserFieldConfig {
            field_type: UserFieldType::Date,
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    let _ = required(value.as_date(), "Expected a native creation Date")?;
                    events.push(model, "input", "native-date".into())?;
                    Ok(date(0).into())
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    )])
}

fn created_organization() -> FieldMap {
    [
        ("id".into(), "organization-a".into()),
        ("name".into(), "Created Organization".into()),
        ("slug".into(), "created".into()),
        ("logo".into(), FieldValue::Null),
        ("metadata".into(), FieldMap::new().into()),
        ("createdAt".into(), date(0).into()),
    ]
    .into()
}

fn created_member() -> FieldMap {
    [
        ("id".into(), "member-a".into()),
        ("organizationId".into(), "organization-a".into()),
        ("userId".into(), "user-a".into()),
        ("role".into(), "owner".into()),
        ("createdAt".into(), date(0).into()),
    ]
    .into()
}

async fn check<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    hidden: bool,
    native: bool,
) -> AuthResult<()> {
    details::seed_member(Arc::clone(&raw), false, "member-a", "team-a", "user-a").await?;
    let events = Events::default();
    let invoked = events.clone();
    let function: UserFieldFactory = Arc::new(move || {
        trace_lock(&invoked.values)?.push(vec!["team.name".into(), "called".into()].into());
        Ok("Callback Team".into())
    });
    let mut callback_fields = team("team-a", "Callback Team", None);
    let _ = callback_fields.insert("name".into(), FieldValue::Function(function.into()));
    let callback = Arc::new(Callback {
        events: events.clone(),
        team: Team::from_field_values(callback_fields.clone())?,
    });
    let mut options = OrganizationConfig {
        policy: Some(callback.clone()),
        hooks: Some(callback),
        ..Default::default()
    };
    options.teams.enabled = true;
    options.schema.team = if hidden {
        declaration([(
            "name",
            UserFieldConfig {
                returned: Some(false),
                ..Default::default()
            },
        )])
    } else {
        UserConfig {
            additional_fields: Some(Default::default()),
        }
    };
    let mut config = config();
    config.logger.disabled = Some(true);
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(|request| {
            Ok(Some(format!("{}-a", request.model)))
        })));
    let auth = BetterAuth::new(config)
        .store_arc(Arc::clone(&raw))
        .plugin(OrganizationPlugin::with_config(options))
        .plugin(Fields(vec![
            (
                EntityRole::Organization,
                fixed_created_at("organization.createdAt", &events),
            ),
            (
                EntityRole::Member,
                fixed_created_at("member.createdAt", &events),
            ),
            (
                EntityRole::TeamMember,
                details::member_fields(&events, "id", false, false),
            ),
            (EntityRole::Team, details::parent_fields(&events, false)),
        ]))
        .build()
        .await?;
    let headers = invitation::session_headers(&auth).await?;
    let sessions_before = raw
        .get_user_sessions("user-a")
        .await?
        .iter()
        .map(AuthRecordFields::field_values)
        .collect::<AuthResult<Vec<_>>>()?;
    let original = required(
        raw.get_organization_by_id("organization").await?,
        "Missing seed organization",
    )?;
    assert!(
        raw.list_organization_members("organization")
            .await?
            .is_empty()
    );
    assert!(events.take()?.is_empty());
    let body = json!({
        "name":"Created Organization", "slug":"created", "logo":null,
        "metadata":{}, "keepCurrentActiveOrganization":true,
    });
    let response = if native {
        auth.call_endpoint(
            HttpMethod::Post,
            "/organization/create",
            EndpointInput {
                body: Some(body),
                headers: Some(headers),
                ..Default::default()
            },
        )
        .await?
    } else {
        let path = "/api/auth/organization/create";
        auth.handle_request(
            AuthRequest::from_parts(
                HttpMethod::Post,
                path.into(),
                headers,
                Some(serde_json::to_vec(&body)?),
                None,
            )
            .with_url(
                format!("http://fields.test{path}")
                    .parse()
                    .map_err(|error| AuthError::internal(format!("Invalid test URL: {error}")))?,
            ),
        )
        .await?
    };
    assert_eq!(response.status, 200);
    let mut expected = created_organization();
    let _ = expected.insert(
        "members".into(),
        vec![FieldValue::from(created_member())].into(),
    );
    if native {
        assert_eq!(response.body.field_value()?, FieldValue::from(expected));
    } else {
        assert_eq!(
            serde_json::from_slice::<Value>(&response.body.bytes()?)?,
            Value::Object(expected.json()?)
        );
    }
    let draft: FieldMap = [
        ("name".into(), "Created Organization".into()),
        ("organizationId".into(), "organization-a".into()),
    ]
    .into();
    let mut expected_events = vec![
        event("organization.createdAt", "input", "native-date".into()),
        event("member.createdAt", "input", "native-date".into()),
        event("beforeCreateTeam", "hook", draft.into()),
        event(
            "customCreateDefaultTeam",
            "callback",
            created_organization().into(),
        ),
    ];
    expected_events.extend(details::member_events(&storage, "team-a", "user-a")?);
    expected_events.push(event("afterCreateTeam", "hook", callback_fields.into()));
    expected_events.push(
        vec![
            "afterCreateOrganization".into(),
            "hook".into(),
            created_organization().into(),
            created_member().into(),
        ]
        .into(),
    );
    assert_eq!(events.take()?, expected_events);
    storage
        .assert_rows(
            vec![physical(
                "member-a",
                "team-a",
                "user-a",
                &key("team-a", "user-a")?,
                0,
            )],
            [1, 0],
        )
        .await?;
    assert!(storage.rows(EntityRole::Invitation).await?.is_empty());
    let mut stored_organization = created_organization();
    let _ = stored_organization.insert("metadata".into(), "{}".into());
    let created = required(
        raw.get_organization_by_id("organization-a").await?,
        "Missing created organization",
    )?;
    assert_eq!(created.field_values()?, stored_organization);
    assert_eq!(
        required(
            raw.get_organization_by_id("organization").await?,
            "Missing seed organization"
        )?
        .field_values()?,
        original.field_values()?,
    );
    assert_eq!(
        raw.list_organization_members("organization-a")
            .await?
            .iter()
            .map(AuthRecordFields::field_values)
            .collect::<AuthResult<Vec<_>>>()?,
        vec![created_member()],
    );
    assert!(
        raw.list_organization_members("organization")
            .await?
            .is_empty()
    );
    assert_eq!(
        raw.get_user_sessions("user-a")
            .await?
            .iter()
            .map(AuthRecordFields::field_values)
            .collect::<AuthResult<Vec<_>>>()?,
        sessions_before,
    );
    assert!(events.take()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn memory_default_team_callback_preserves_native_values_without_public_clone()
-> AuthResult<()> {
    for hidden in [false, true] {
        for native in [false, true] {
            let (raw, storage) = memory_fixture().await?;
            check(raw, storage, hidden, native).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_default_team_callback_preserves_native_values_without_public_clone()
-> AuthResult<()> {
    for hidden in [false, true] {
        for native in [false, true] {
            let (raw, storage) = sqlite_fixture().await?;
            check(raw, storage, hidden, native).await?;
        }
    }
    Ok(())
}
