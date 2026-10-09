use super::*;
use better_auth::plugins::organization::hooks::{
    OrganizationTeamMemberLimit, TeamMemberLimitPolicy,
};
use better_auth_core::{CreateMember, HttpMethod};
use std::collections::HashMap;

#[path = "team_member_invitation_function.rs"]
mod function;

#[derive(Clone, Copy)]
enum Mode {
    NoLimit,
    LimitedPage,
    FullPage,
    ChildError,
}

impl Mode {
    fn limit(self) -> Option<f64> {
        match self {
            Self::NoLimit => None,
            Self::LimitedPage => Some(1.0),
            Self::FullPage | Self::ChildError => Some(2.0),
        }
    }

    fn success(self) -> bool {
        matches!(self, Self::NoLimit | Self::LimitedPage)
    }
}

struct Capacity {
    events: Events,
    maximum: usize,
}

#[async_trait]
impl TeamMemberLimitPolicy for Capacity {
    async fn maximum_members_per_team(
        &self,
        data: OrganizationTeamMemberLimit<'_>,
    ) -> AuthResult<usize> {
        let user = required(data.session.user.as_object(), "Expected the actor user")?;
        self.events.push(
            "limit",
            "callback",
            vec![
                data.organization_id.clone(),
                data.team_id.clone(),
                required(user.get("id"), "Expected the actor ID")?.clone(),
            ]
            .into(),
        )?;
        Ok(self.maximum)
    }
}

fn parent_fields(events: &Events) -> UserConfig {
    let mut fields = details::parent_fields(events, false);
    for (name, label, visible) in [
        (
            "organizationId",
            "team.organizationId",
            "visible-organization",
        ),
        ("id", "team.id", "visible-team"),
    ] {
        let events = events.clone();
        let _ = fields.fields_mut().insert(
            name.into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |value| {
                        events.push(label, "output", value)?;
                        Ok(visible.into())
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    }
    fields
}

fn invitation_fields() -> UserConfig {
    declaration([("createdAt", 0), ("expiresAt", 30)].map(|(name, offset)| {
        (
            name,
            UserFieldConfig {
                field_type: UserFieldType::Date,
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |value| {
                        let _ = required(value.as_date(), "Expected a native invitation Date")?;
                        Ok(date(offset).into())
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
    }))
}

async fn endpoint<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    events: &Events,
    joins: bool,
    mode: Mode,
) -> AuthResult<BetterAuth<S>> {
    let mut config = config();
    config.logger.disabled = Some(true);
    config.advanced.database.joins = Some(joins);
    config.advanced.database.default_find_many_limit = mode.limit();
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(|request| {
            Ok(Some(format!("{}-a", request.model)))
        })));
    let mut options = OrganizationConfig::default();
    options.teams.enabled = true;
    if !matches!(mode, Mode::NoLimit) {
        options.teams.maximum_members_per_team_callback = Some(Arc::new(Capacity {
            events: events.clone(),
            maximum: 2,
        }));
    }
    BetterAuth::new(config)
        .store_arc(raw)
        .plugin(OrganizationPlugin::with_config(options))
        .plugin(Fields(vec![
            (EntityRole::Team, parent_fields(events)),
            (
                EntityRole::TeamMember,
                details::member_fields(events, "id", false, matches!(mode, Mode::ChildError)),
            ),
            (EntityRole::Invitation, invitation_fields()),
        ]))
        .build()
        .await
}

fn invitation(created_at: FieldValue, expires_at: FieldValue) -> FieldMap {
    [
        ("id".into(), "invitation-a".into()),
        ("organizationId".into(), "organization".into()),
        ("email".into(), "invited@team-member-fields.test".into()),
        ("role".into(), "member".into()),
        ("status".into(), "pending".into()),
        ("inviterId".into(), "user-a".into()),
        ("teamId".into(), "team-a".into()),
        ("createdAt".into(), created_at),
        ("expiresAt".into(), expires_at),
    ]
    .into()
}

async fn session_headers<S: AuthSchema>(
    auth: &BetterAuth<S>,
) -> AuthResult<HashMap<String, String>> {
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
    let token = better_auth_core::utils::cookie_utils::sign_cookie_value(
        session.token.typed()?,
        auth.config().signing_secret(),
    );
    Ok(HashMap::from([
        ("content-type".into(), "application/json".into()),
        ("origin".into(), "http://fields.test".into()),
        (
            "cookie".into(),
            format!("better-auth.session_token={token}"),
        ),
    ]))
}

fn request_body() -> Value {
    json!({
        "organizationId":"organization", "teamId":"team-a",
        "email":"invited@team-member-fields.test", "role":"member",
    })
}

async fn request<S: AuthSchema>(auth: &BetterAuth<S>) -> AuthResult<AuthResponse> {
    let path = "/api/auth/organization/invite-member";
    auth.handle_request(
        AuthRequest::from_parts(
            HttpMethod::Post,
            path.into(),
            session_headers(auth).await?,
            Some(serde_json::to_vec(&request_body())?),
            None,
        )
        .with_url(
            format!("http://fields.test{path}")
                .parse()
                .map_err(|error| AuthError::internal(format!("Invalid invitation URL: {error}")))?,
        ),
    )
    .await
}

async fn check<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    joins: bool,
    mode: Mode,
) -> AuthResult<()> {
    details::seed_member(Arc::clone(&raw), joins, "member-a", "team-a", "user-a").await?;
    details::seed_member(Arc::clone(&raw), joins, "member-b", "team-a", "user-b").await?;
    let _ = raw
        .create_member(CreateMember::new("organization", "user-a", "owner"))
        .await?;
    let events = Events::default();
    let auth = endpoint(raw, &events, joins, mode).await?;
    assert!(events.take()?.is_empty());
    let response = request(&auth).await?;
    let bytes = response.body.bytes()?;
    let expected_rows = if mode.success() {
        assert_eq!(response.status, 200);
        let response: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(
            response,
            json!({
                "id":"invitation-a", "organizationId":"organization",
                "email":"invited@team-member-fields.test", "role":"member", "status":"pending",
                "inviterId":"user-a", "teamId":"team-a",
                "createdAt":"2030-01-01T00:00:00.000Z", "expiresAt":"2030-01-01T00:00:30.000Z",
            })
        );
        vec![invitation(storage.stored_date(0), storage.stored_date(30))]
    } else {
        if matches!(mode, Mode::FullPage) {
            assert_eq!(response.status, 403);
            assert_eq!(
                serde_json::from_slice::<Value>(&bytes)?,
                json!({
                    "code":"TEAM_MEMBER_LIMIT_REACHED", "message":"Team member limit reached",
                })
            );
        } else {
            assert_eq!(response.status, 500);
            assert!(bytes.is_empty());
        }
        Vec::new()
    };
    let parent = vec![
        event("team.name", "output", "Team A".into()),
        event("team.organizationId", "output", "organization".into()),
    ];
    let mut expected_events = parent.clone();
    if !matches!(mode, Mode::NoLimit) {
        expected_events.extend(parent);
        if matches!(mode, Mode::ChildError) {
            expected_events.extend([
                event("teamId", "output", "team-a".into()),
                event("userId", "output", "user-a".into()),
            ]);
        } else {
            expected_events.extend(details::member_events(&storage, "team-a", "user-a")?);
            if matches!(mode, Mode::FullPage) {
                expected_events.extend(details::member_events(&storage, "team-a", "user-b")?);
            }
            expected_events.push(event(
                "limit",
                "callback",
                vec!["organization".into(), "team-a".into(), "user-a".into()].into(),
            ));
        }
    }
    assert_eq!(events.take()?, expected_events);
    assert_eq!(storage.rows(EntityRole::Invitation).await?, expected_rows);
    storage
        .assert_rows(
            vec![
                physical("member-a", "team-a", "user-a", &key("team-a", "user-a")?, 0),
                physical("member-b", "team-a", "user-b", &key("team-a", "user-b")?, 0),
            ],
            [2, 0],
        )
        .await
}

#[tokio::test]
async fn memory_invitation_route_preserves_team_scope_and_member_page_order() -> AuthResult<()> {
    for joins in [false, true] {
        for mode in [
            Mode::NoLimit,
            Mode::LimitedPage,
            Mode::FullPage,
            Mode::ChildError,
        ] {
            let (raw, storage) = memory_fixture().await?;
            check(raw, storage, joins, mode).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_invitation_route_preserves_team_scope_and_member_page_order() -> AuthResult<()> {
    for joins in [false, true] {
        for mode in [
            Mode::NoLimit,
            Mode::LimitedPage,
            Mode::FullPage,
            Mode::ChildError,
        ] {
            let (raw, storage) = sqlite_fixture().await?;
            check(raw, storage, joins, mode).await?;
        }
    }
    Ok(())
}
