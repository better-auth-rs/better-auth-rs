use super::*;
use better_auth::server_api::EndpointInput;
use better_auth_core::{CreateMember, HttpMethod};
use std::collections::HashMap;

#[path = "team_route_projection_support.rs"]
mod support;
use support::endpoint;

#[derive(Clone, Copy, Debug)]
enum Route {
    Update,
    Remove,
    Active,
    Members,
    List,
    UserList,
    Create,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Mode {
    Scope,
    OwnerUnset,
    OwnerEmpty,
    Clone,
    GuardClone,
    Page,
}

#[derive(Clone, Copy, Debug)]
struct Case {
    route: Route,
    mode: Mode,
    joins: bool,
}

impl Case {
    const fn new(route: Route, mode: Mode) -> Self {
        Self {
            route,
            mode,
            joins: false,
        }
    }

    fn all() -> [Self; 16] {
        use Mode::*;
        use Route::*;
        [
            Self::new(Update, Scope),
            Self::new(Remove, Scope),
            Self::new(Active, Scope),
            Self::new(Update, OwnerUnset),
            Self::new(Update, OwnerEmpty),
            Self::new(Remove, OwnerUnset),
            Self::new(Remove, OwnerEmpty),
            Self::new(Active, Clone),
            Self::new(Members, Clone),
            Self::new(List, Clone),
            Self::new(UserList, Clone),
            Self {
                joins: true,
                ..Self::new(UserList, Clone)
            },
            Self::new(Create, GuardClone),
            Self::new(Remove, GuardClone),
            Self::new(Create, Page),
            Self::new(Remove, Page),
        ]
    }

    fn success(self) -> bool {
        self.mode == Mode::Page && matches!(self.route, Route::Create)
    }
    fn limited_page(self) -> bool {
        self.mode == Mode::Page
            || (self.mode == Mode::GuardClone && matches!(self.route, Route::Remove))
    }
    fn business_error(self) -> Option<Value> {
        if self.mode == Mode::Page && matches!(self.route, Route::Remove) {
            Some(
                json!({"code":"UNABLE_TO_REMOVE_LAST_TEAM", "message":"Unable to remove last team"}),
            )
        } else if matches!(self.mode, Mode::Scope | Mode::OwnerUnset) {
            Some(json!({"code":"TEAM_NOT_FOUND", "message":"Team not found"}))
        } else {
            None
        }
    }
    fn request(self, org: &str) -> (HttpMethod, &'static str, Option<Value>, Option<Value>) {
        match self.route {
            Route::Update => (
                HttpMethod::Post,
                "/organization/update-team",
                Some(json!({"teamId":"team-a", "data":{"name":"Updated", "organizationId":org}})),
                None,
            ),
            Route::Remove => (
                HttpMethod::Post,
                "/organization/remove-team",
                Some(json!({"teamId":"team-a", "organizationId":org})),
                None,
            ),
            Route::Active => (
                HttpMethod::Post,
                "/organization/set-active-team",
                Some(json!({"teamId":"team-a"})),
                None,
            ),
            Route::Create => (
                HttpMethod::Post,
                "/organization/create-team",
                Some(json!({"name":"Team C", "organizationId":org})),
                None,
            ),
            Route::Members => (
                HttpMethod::Get,
                "/organization/list-team-members",
                None,
                Some(json!({"teamId":"team-a"})),
            ),
            Route::List => (
                HttpMethod::Get,
                "/organization/list-teams",
                None,
                Some(json!({"organizationId":org})),
            ),
            Route::UserList => (HttpMethod::Get, "/organization/list-user-teams", None, None),
        }
    }
}

fn team_events(name: &str) -> Vec<FieldValue> {
    vec![
        event("team.name", "output", name.into()),
        event("team.organizationId", "output", "organization".into()),
    ]
}

fn expected_events(case: Case, storage: &Storage) -> AuthResult<Vec<FieldValue>> {
    let mut events = Vec::new();
    if matches!(
        case.route,
        Route::Update | Route::Remove | Route::List | Route::Create
    ) {
        events.push(event("member.role", "output", "owner".into()));
    }
    if matches!(case.route, Route::UserList) {
        events.extend(details::member_events(storage, "team-a", "user-a")?);
        events.extend(team_events("Team A"));
        return Ok(events);
    }
    if matches!(
        case.route,
        Route::Update | Route::Remove | Route::Active | Route::Members
    ) {
        if case.mode == Mode::Scope {
            return Ok(events);
        }
        events.extend(team_events("Team A"));
        if !case.limited_page() {
            return Ok(events);
        }
    }
    if case.limited_page() {
        events.extend(team_events("Team A"));
    } else {
        events.extend([
            event("team.name", "output", "Team A".into()),
            event("team.name", "output", "Team B".into()),
            event("team.organizationId", "output", "organization".into()),
            event("team.organizationId", "output", "organization".into()),
        ]);
    }
    if case.success() {
        events.extend([
            event(
                "maximumTeams",
                "callback",
                vec!["organization".into(), "user-a".into()].into(),
            ),
            event("organization.name", "output", "Organization".into()),
            event(
                "beforeCreateTeam",
                "hook",
                FieldMap::from_iter([
                    ("name".into(), "Team C".into()),
                    ("organizationId".into(), "organization".into()),
                ])
                .into(),
            ),
            event("team.organizationId", "input", "organization".into()),
            event("team.createdAt", "input", "native-date".into()),
            event("team.updatedAt", "input", "native-date".into()),
        ]);
        events.extend(team_events("Team C"));
        events.push(event(
            "afterCreateTeam",
            "hook",
            team("team-c", "Team C", None).into(),
        ));
    }
    Ok(events)
}

async fn state<S: AuthSchema>(
    raw: &dyn AuthStore<S>,
    org: &str,
    token: &str,
) -> AuthResult<Vec<FieldValue>> {
    let organization = required(
        raw.get_organization_by_id(org).await?,
        "Expected the organization snapshot",
    )?;
    let members = raw
        .list_organization_members(org)
        .await?
        .iter()
        .map(|row| row.field_values().map(FieldValue::from))
        .collect::<AuthResult<Vec<_>>>()?;
    let session = required(
        raw.get_session(token).await?,
        "Expected the session snapshot",
    )?;
    Ok(vec![
        organization.field_values()?.into(),
        members.into(),
        session.field_values()?.into(),
    ])
}

async fn check<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    case: Case,
    native: bool,
) -> AuthResult<()> {
    details::seed_member(Arc::clone(&raw), case.joins, "member-a", "team-a", "user-a").await?;
    let org = if case.mode == Mode::Scope {
        "wrong-organization"
    } else {
        "organization"
    };
    if case.mode == Mode::Scope {
        let _ = raw
            .create_organization(CreateOrganization {
                id: Some(org.into()),
                ..CreateOrganization::new("Other Organization", org)
            })
            .await?;
    }
    let _ = raw
        .create_member(CreateMember::new(org, "user-a", "owner"))
        .await?;
    let events = Events::default();
    let auth = endpoint(Arc::clone(&raw), case, &events).await?;
    let session = auth
        .store()
        .create_session(CreateSession {
            user_id: "user-a".into(),
            expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).into(),
            active_organization_id: Some(org.into()),
            inherited_fields: Default::default(),
            additional_fields: Default::default(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
        })
        .await?;
    let token = session.token.typed()?;
    let before = state(raw.as_ref(), org, token).await?;
    let signed = better_auth_core::utils::cookie_utils::sign_cookie_value(
        token,
        auth.config().signing_secret(),
    );
    let headers = HashMap::from([
        ("content-type".into(), "application/json".into()),
        ("origin".into(), "http://fields.test".into()),
        (
            "cookie".into(),
            format!("better-auth.session_token={signed}"),
        ),
    ]);
    assert!(events.take()?.is_empty());
    let (method, path, body, query) = case.request(org);
    let result = if native {
        auth.call_endpoint(
            method,
            path,
            EndpointInput {
                headers: Some(headers),
                body,
                query,
                ..Default::default()
            },
        )
        .await
    } else {
        let path = format!("/api/auth{path}");
        let mut url = format!("http://fields.test{path}")
            .parse::<url::Url>()
            .map_err(|error| AuthError::internal(error.to_string()))?;
        if let Some(Value::Object(fields)) = &query {
            for (name, value) in fields {
                url.query_pairs_mut()
                    .append_pair(name, required(value.as_str(), "Expected string query")?);
            }
        }
        auth.handle_request(
            AuthRequest::from_parts(
                method,
                path,
                headers,
                body.map(|body| serde_json::to_vec(&body)).transpose()?,
                query,
            )
            .with_url(url),
        )
        .await
    };
    if case.success() {
        let response = result?;
        assert_eq!(response.status, 200, "{case:?}");
        let expected = team("team-c", "Team C", None);
        if native {
            assert_eq!(
                response.body.field_value()?,
                FieldValue::from(expected),
                "{case:?}"
            );
        } else {
            assert_eq!(
                serde_json::from_slice::<Value>(&response.body.bytes()?)?,
                Value::Object(expected.json()?),
                "{case:?}"
            );
        }
    } else if let Some(expected) = case.business_error() {
        let response = if native {
            result
                .expect_err("Native route must reject the Team")
                .to_auth_response()
        } else {
            result?
        };
        assert_eq!(response.status, 400, "{case:?}");
        assert_eq!(
            serde_json::from_slice::<Value>(&response.body.bytes()?)?,
            expected,
            "{case:?}"
        );
    } else if native {
        let error = result.expect_err("Native route must preserve the public clone failure");
        assert!(matches!(error, AuthError::DataClone), "{case:?}: {error:?}");
        assert_eq!(error.to_string(), "The object can not be cloned.");
    } else {
        let response = result?;
        assert_eq!(response.status, 500, "{case:?}");
        assert!(response.body.bytes()?.is_empty(), "{case:?}");
    }
    assert_eq!(events.take()?, expected_events(case, &storage)?, "{case:?}");
    assert_eq!(
        storage.rows(EntityRole::TeamMember).await?,
        vec![storage.stored(physical(
            "member-a",
            "team-a",
            "user-a",
            &key("team-a", "user-a")?,
            0
        ))]
    );
    let mut teams = vec![
        storage.stored(team("team-a", "Team A", Some(1))),
        storage.stored(team("team-b", "Team B", Some(0))),
    ];
    if case.success() {
        teams.push(storage.stored(team("team-c", "Team C", Some(0))));
    }
    assert_eq!(storage.rows(EntityRole::Team).await?, teams);
    assert!(storage.rows(EntityRole::Invitation).await?.is_empty());
    assert_eq!(state(raw.as_ref(), org, token).await?, before);
    Ok(())
}

#[tokio::test]
async fn memory_team_routes_preserve_scope_public_clone_and_page_guards() -> AuthResult<()> {
    for native in [false, true] {
        for case in Case::all() {
            let (raw, storage) = memory_fixture().await?;
            check(raw, storage, case, native).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_team_routes_preserve_scope_public_clone_and_page_guards() -> AuthResult<()> {
    for native in [false, true] {
        for case in Case::all() {
            let (raw, storage) = sqlite_fixture().await?;
            check(raw, storage, case, native).await?;
        }
    }
    Ok(())
}
