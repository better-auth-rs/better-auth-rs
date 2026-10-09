use super::*;
use better_auth::server_api::EndpointInput;
use better_auth_core::user_fields::UserFieldFactory;

#[derive(Clone, Copy)]
enum Case {
    Unconfigured,
    FirstLookupClone,
    HiddenFunction,
    SingularClone,
    SingularUnconfigured,
}

impl Case {
    const ALL: [Self; 5] = [
        Self::Unconfigured,
        Self::FirstLookupClone,
        Self::HiddenFunction,
        Self::SingularClone,
        Self::SingularUnconfigured,
    ];

    fn singular(self) -> bool {
        matches!(self, Self::SingularClone | Self::SingularUnconfigured)
    }

    fn first_lookup(self) -> bool {
        matches!(self, Self::FirstLookupClone)
    }

    fn public_fields(self) -> UserConfig {
        match self {
            Self::Unconfigured | Self::SingularUnconfigured => UserConfig::default(),
            Self::FirstLookupClone | Self::SingularClone => UserConfig {
                additional_fields: Some(Default::default()),
            },
            Self::HiddenFunction => declaration([(
                "name",
                UserFieldConfig {
                    returned: Some(false),
                    ..Default::default()
                },
            )]),
        }
    }
}

fn function_fields(events: &Events, case: Case) -> UserConfig {
    let mut fields = parent_fields(events);
    let calls = AtomicUsize::new(0);
    let invoked = events.clone();
    let function: UserFieldFactory = Arc::new(move || {
        invoked.push("team.name", "call", FieldValue::Undefined)?;
        Ok("Visible Team A".into())
    });
    let function = FieldValue::Function(function.into());
    let output = events.clone();
    let _ = fields.fields_mut().insert(
        "name".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    output.push("team.name", "output", value.clone())?;
                    let call = calls.fetch_add(1, Ordering::SeqCst);
                    Ok(if case.first_lookup() || call != 0 {
                        function.clone()
                    } else {
                        value
                    })
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    fields
}

async fn function_endpoint<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    events: &Events,
    joins: bool,
    case: Case,
) -> AuthResult<BetterAuth<S>> {
    let mut config = config();
    config.logger.disabled = Some(true);
    config.advanced.database.joins = Some(joins);
    config.advanced.database.default_find_many_limit = Some(2.0);
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(|request| {
            Ok(Some(format!("{}-a", request.model)))
        })));
    let mut options = OrganizationConfig::default();
    options.teams.enabled = true;
    options.teams.maximum_members_per_team_callback = Some(Arc::new(Capacity {
        events: events.clone(),
        maximum: 3,
    }));
    options.schema.team = case.public_fields();
    BetterAuth::new(config)
        .store_arc(raw)
        .plugin(OrganizationPlugin::with_config(options))
        .plugin(Fields(vec![
            (EntityRole::Team, function_fields(events, case)),
            (
                EntityRole::TeamMember,
                details::member_fields(events, "id", case.singular(), false),
            ),
            (EntityRole::Invitation, invitation_fields()),
        ]))
        .build()
        .await
}

async fn check_function<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    joins: bool,
    native: bool,
    case: Case,
) -> AuthResult<()> {
    let second_team = if case.singular() { "team-b" } else { "team-a" };
    details::seed_member(Arc::clone(&raw), joins, "member-a", "team-a", "user-a").await?;
    details::seed_member(Arc::clone(&raw), joins, "member-b", second_team, "user-b").await?;
    let _ = raw
        .create_member(CreateMember::new("organization", "user-a", "owner"))
        .await?;
    let events = Events::default();
    let auth = function_endpoint(raw, &events, joins, case).await?;
    assert!(events.take()?.is_empty());
    let result = if native {
        auth.call_endpoint(
            HttpMethod::Post,
            "/organization/invite-member",
            EndpointInput {
                body: Some(request_body()),
                headers: Some(session_headers(&auth).await?),
                ..Default::default()
            },
        )
        .await
    } else {
        request(&auth).await
    };
    let accepted = matches!(case, Case::Unconfigured);
    if accepted {
        let response = result?;
        assert_eq!(response.status, 200);
        if native {
            assert_eq!(
                response.body.field_value()?,
                FieldValue::from(invitation(date(0).into(), date(30).into()))
            );
        } else {
            assert_eq!(
                serde_json::from_slice::<Value>(&response.body.bytes()?)?,
                json!({
                    "id":"invitation-a", "organizationId":"organization",
                    "email":"invited@team-member-fields.test", "role":"member", "status":"pending",
                    "inviterId":"user-a", "teamId":"team-a",
                    "createdAt":"2030-01-01T00:00:00.000Z", "expiresAt":"2030-01-01T00:00:30.000Z",
                }),
            );
        }
    } else if native {
        let error = result.expect_err("Native invitation must preserve the public output failure");
        if matches!(case, Case::SingularUnconfigured) {
            assert!(matches!(error, AuthError::TypeError(_)), "{error:?}");
        } else {
            assert!(matches!(error, AuthError::DataClone), "{error:?}");
            assert_eq!(error.to_string(), "The object can not be cloned.");
        }
    } else {
        let response = result?;
        assert_eq!(response.status, 500);
        assert!(response.body.bytes()?.is_empty());
    }
    let parent = vec![
        event("team.name", "output", "Team A".into()),
        event("team.organizationId", "output", "organization".into()),
    ];
    let mut expected_events = parent.clone();
    if !case.first_lookup() {
        expected_events.extend(parent);
        expected_events.extend(details::member_events(&storage, "team-a", "user-a")?);
        if !case.singular() {
            expected_events.extend(details::member_events(&storage, "team-a", "user-b")?);
        }
        if accepted {
            expected_events.push(event(
                "limit",
                "callback",
                vec!["organization".into(), "team-a".into(), "user-a".into()].into(),
            ));
        }
    }
    assert_eq!(events.take()?, expected_events);
    assert_eq!(
        storage.rows(EntityRole::Invitation).await?,
        if accepted {
            vec![invitation(storage.stored_date(0), storage.stored_date(30))]
        } else {
            Vec::new()
        },
    );
    storage
        .assert_rows(
            vec![
                physical("member-a", "team-a", "user-a", &key("team-a", "user-a")?, 0),
                physical(
                    "member-b",
                    second_team,
                    "user-b",
                    &key(second_team, "user-b")?,
                    0,
                ),
            ],
            if case.singular() { [1, 1] } else { [2, 0] },
        )
        .await
}

#[tokio::test]
async fn memory_invitation_clones_configured_team_output_before_members_map() -> AuthResult<()> {
    for joins in [false, true] {
        for native in [false, true] {
            for case in Case::ALL {
                let (raw, storage) = memory_fixture().await?;
                check_function(raw, storage, joins, native, case).await?;
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_invitation_clones_configured_team_output_before_members_map() -> AuthResult<()> {
    for joins in [false, true] {
        for native in [false, true] {
            for case in Case::ALL {
                let (raw, storage) = sqlite_fixture().await?;
                check_function(raw, storage, joins, native, case).await?;
            }
        }
    }
    Ok(())
}
