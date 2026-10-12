use super::*;
use better_auth::plugins::organization::hooks::{
    OrganizationEndpoint, OrganizationHooks, OrganizationUser,
};
use better_auth_core::{
    ApiErrorClass, ApiErrorInit, CreateInvitation,
    observability::{AfterEndpointHook, EndpointHooks},
    user_fields::UserFieldFactory,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    GetId,
    GetSlug,
    ActiveId,
    ActiveSlug,
    Create,
    Update,
    CheckSlug,
    Members,
    Role,
    Delete,
    Teams,
}

impl Route {
    fn request(self) -> (&'static str, bool, Value) {
        match self {
            Self::GetId => (
                "get-organization",
                true,
                json!({"organizationId":"organization"}),
            ),
            Self::GetSlug => (
                "get-organization",
                true,
                json!({"organizationSlug":"organization"}),
            ),
            Self::ActiveId => (
                "set-active",
                false,
                json!({"organizationId":"organization"}),
            ),
            Self::ActiveSlug => (
                "set-active",
                false,
                json!({"organizationSlug":"organization"}),
            ),
            Self::Create => (
                "create",
                false,
                json!({"name":"Duplicate","slug":"organization"}),
            ),
            Self::Update => (
                "update",
                false,
                json!({"organizationId":"organization","data":{"slug":"organization"}}),
            ),
            Self::CheckSlug => ("check-slug", false, json!({"slug":"organization"})),
            Self::Members => (
                "list-members",
                true,
                json!({"organizationSlug":"organization"}),
            ),
            Self::Role => (
                "get-active-member-role",
                true,
                json!({"organizationSlug":"organization"}),
            ),
            Self::Delete => ("delete", false, json!({"organizationId":"organization"})),
            Self::Teams => ("list-teams", true, json!({"organizationId":"organization"})),
        }
    }
}

async fn call_route<S: AuthSchema>(
    auth: &BetterAuth<S>,
    token: &str,
    native: bool,
    route: Route,
) -> AuthResult<AuthResponse> {
    let (endpoint, get, input) = route.request();
    if !get {
        return call(auth, token, native, endpoint, input).await;
    }
    let path = format!("/organization/{endpoint}");
    let headers = std::collections::HashMap::from([(
        "cookie".into(),
        format!(
            "better-auth.session_token={}",
            better_auth_core::utils::cookie_utils::sign_cookie_value(
                token,
                auth.config().signing_secret()
            )
        ),
    )]);
    if native {
        auth.call_endpoint(
            HttpMethod::Get,
            &path,
            EndpointInput {
                headers: Some(headers),
                query: Some(input),
                ..Default::default()
            },
        )
        .await
    } else {
        let mut url = format!("http://fields.test/api/auth{path}")
            .parse::<url::Url>()
            .map_err(|error| AuthError::internal(error.to_string()))?;
        for (name, value) in required(input.as_object(), "Expected route query")? {
            let _ = url
                .query_pairs_mut()
                .append_pair(name, required(value.as_str(), "Expected string query")?);
        }
        auth.handle_request(
            AuthRequest::from_parts(
                HttpMethod::Get,
                format!("/api/auth{path}"),
                headers,
                None,
                Some(input),
            )
            .with_url(url),
        )
        .await
    }
}

fn output(name: &'static str, events: &Events, value: Option<FieldValue>) -> UserFieldConfig {
    UserFieldConfig {
        transform: Some(FieldTransforms {
            output: Some(UserFieldTransform::new({
                let events = events.clone();
                move |input| {
                    event(&events, [name.into(), "output".into(), input.clone()])?;
                    Ok(value.clone().unwrap_or(input))
                }
            })),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn session_field(events: &Events) -> UserFieldConfig {
    UserFieldConfig {
        field_type: UserFieldType::Date,
        on_update: Some(better_auth_core::user_fields::UserFieldFactory::new({
            let events = events.clone();
            move || {
                event(&events, ["session.updatedAt".into(), "onUpdate".into()])?;
                Ok(date().into())
            }
        })),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new({
                let events = events.clone();
                move |input| {
                    event(
                        &events,
                        ["session.updatedAt".into(), "input".into(), input.clone()],
                    )?;
                    Ok(input)
                }
            })),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn session_events() -> Vec<FieldValue> {
    vec![
        vec!["session.updatedAt".into(), "onUpdate".into()].into(),
        vec!["session.updatedAt".into(), "input".into(), date().into()].into(),
    ]
}

fn cleared_session(storage: &Storage, before: &mut Snapshot) -> AuthResult<()> {
    for row in required(before.get_mut("session"), "Expected session table")? {
        let _ = row.insert(
            if storage.memory() {
                "activeOrganizationId"
            } else {
                "active_organization_id"
            }
            .into(),
            FieldValue::Null,
        );
        let _ = row.insert(
            if storage.memory() {
                "updatedAt"
            } else {
                "updated_at"
            }
            .into(),
            if storage.memory() {
                date().into()
            } else {
                "2030-01-01T00:00:00.000Z".into()
            },
        );
    }
    Ok(())
}

async fn seed_boundary<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    route: Route,
) -> AuthResult<String> {
    let token = seed(
        raw.clone(),
        false,
        if route == Route::Create {
            "user-b"
        } else {
            "user-a"
        },
    )
    .await?;
    if route != Route::Delete {
        for (id, name) in [("team-a", "Team A"), ("team-b", "Team B")] {
            let _ = raw
                .create_team(CreateTeam {
                    id: Some(id.into()),
                    name: name.into(),
                    organization_id: "organization".into(),
                    created_at: Some(date()),
                    updated_at: Some(date()),
                    ..Default::default()
                })
                .await?;
        }
    }
    let _ = raw
        .create_invitation(CreateInvitation {
            id: Some("invitation-a".into()),
            created_at: Some(date()),
            ..CreateInvitation::new(
                "organization",
                "user-b@fields.test",
                "member",
                "user-a",
                FieldDate::from_milliseconds(1_893_456_030_000.0),
            )
        })
        .await?;
    Ok(token)
}

async fn clone_failure<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    route: Route,
    native: bool,
) -> AuthResult<()> {
    let token = seed_boundary(raw.clone(), route).await?;
    let mut before = storage.snapshot().await?;
    let events = Events::default();
    let function: UserFieldFactory =
        UserFieldFactory::new(|| Err(AuthError::internal("Hidden output function must not run")));
    let mut plugin = OrganizationConfig::default();
    plugin.schema.organization = declaration([(
        "name",
        UserFieldConfig {
            returned: Some(false),
            ..Default::default()
        },
    )]);
    let auth = BetterAuth::new(settings()?)
        .store_arc(raw)
        .plugin(OrganizationPlugin::with_config(plugin))
        .plugin(Fields(vec![
            (
                EntityRole::Organization,
                declaration([(
                    "name",
                    output(
                        "organization.name",
                        &events,
                        Some(FieldValue::Function(function.into())),
                    ),
                )]),
            ),
            (
                EntityRole::Member,
                declaration([("role", output("member.role", &events, None))]),
            ),
            (
                EntityRole::Session,
                declaration([("updatedAt", session_field(&events))]),
            ),
        ]))
        .build()
        .await?;
    let result = call_route(&auth, &token, native, route).await;
    if native {
        let error = required(result.err(), "Native route must reject the public clone")?;
        assert!(
            matches!(error, AuthError::DataClone),
            "{route:?}: {error:?}"
        );
        assert_eq!(error.to_string(), "The object can not be cloned.");
    } else {
        let response = result?;
        assert_eq!(response.status, 500, "{route:?}");
        assert!(response.body.bytes()?.is_empty(), "{route:?}");
        assert!(!response.headers.contains_key("set-cookie"), "{route:?}");
    }
    let mut expected = Vec::new();
    if matches!(route, Route::ActiveId | Route::Update | Route::Delete) {
        expected.push(vec!["member.role".into(), "output".into(), "owner".into()].into());
    }
    if route == Route::Delete {
        expected.extend(session_events());
        cleared_session(&storage, &mut before)?;
    }
    expected.push(
        vec![
            "organization.name".into(),
            "output".into(),
            "Organization".into(),
        ]
        .into(),
    );
    ordered(
        &trace_lock(&events)?.clone().into(),
        &FieldValue::from(expected),
    )?;
    assert_eq!(storage.snapshot().await?, before, "{route:?}");
    Ok(())
}

#[tokio::test]
async fn organization_lookup_projection_precedes_consumers_and_preserves_failed_storage()
-> AuthResult<()> {
    for route in [
        Route::GetId,
        Route::GetSlug,
        Route::ActiveId,
        Route::ActiveSlug,
        Route::Create,
        Route::Update,
        Route::CheckSlug,
        Route::Members,
        Route::Role,
        Route::Delete,
    ] {
        for native in [false, true] {
            let (raw, storage) = memory_fixture();
            clone_failure(raw, storage, route, native).await?;
            let (raw, storage) = sqlite_fixture().await?;
            clone_failure(raw, storage, route, native).await?;
        }
    }
    Ok(())
}

struct Replace {
    original: FieldValue,
    replacement: FieldValue,
    api_error: bool,
}

#[async_trait]
impl<S: AuthSchema> AfterEndpointHook<S> for Replace {
    async fn after(
        &self,
        _: &AuthRequest,
        response: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        assert_eq!(response.status, 200);
        ordered(&response.body.field_value()?, &self.original)?;
        if self.api_error {
            return Err(AuthError::from_thrown(self.replacement.clone()));
        }
        response.body = better_auth_core::ResponseBody::Native(self.replacement.clone());
        Ok(())
    }
}

async fn after_hook<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    route: Route,
    native: bool,
    api_error: bool,
) -> AuthResult<()> {
    let token = seed_boundary(raw.clone(), route).await?;
    let mut teams = Vec::new();
    for id in ["team-a", "team-b"] {
        teams.push(FieldValue::from(FieldMap::from([
            ("organizationId".into(), "organization".into()),
            ("createdAt".into(), date().into()),
            ("updatedAt".into(), date().into()),
            ("id".into(), id.into()),
        ])));
    }
    let original = if route == Route::Teams {
        FieldValue::from(teams)
    } else {
        FieldMap::from([
            ("slug".into(), "organization".into()),
            ("logo".into(), FieldValue::Null),
            ("createdAt".into(), date().into()),
            ("metadata".into(), "{}".into()),
            ("id".into(), "organization".into()),
        ])
        .into()
    };
    let before = storage.snapshot().await?;
    let item: FieldValue = FieldMap::from([
        ("name".into(), "after-hook".into()),
        ("memberCount".into(), 7.into()),
        ("ownUndefined".into(), FieldValue::Undefined),
    ])
    .into();
    let body: FieldValue = FieldMap::from([
        ("message".into(), "after-hook".into()),
        ("name".into(), "body-name".into()),
        ("memberCount".into(), 7.into()),
    ])
    .into();
    let error_headers: FieldValue = FieldMap::from([("x-output".into(), "1".into())]).into();
    let replacement: FieldValue = if api_error {
        required(
            AuthError::try_api_error(ApiErrorInit {
                status: "CREATED".into(),
                body: body.clone(),
                headers: error_headers.clone(),
                ..Default::default()
            })?
            .raw_value()
            .cloned(),
            "Expected native APIError",
        )?
    } else if route == Route::Teams {
        vec![item].into()
    } else {
        item
    };
    let mut plugin = OrganizationConfig::default();
    plugin.teams.enabled = true;
    plugin.schema.organization = declaration([(
        "name",
        UserFieldConfig {
            returned: Some(false),
            ..Default::default()
        },
    )]);
    plugin.schema.team = plugin.schema.organization.clone();
    let auth = BetterAuth::new(settings()?)
        .store_arc(raw)
        .plugin(OrganizationPlugin::with_config(plugin))
        .hooks(EndpointHooks {
            before: None,
            after: Some(Arc::new(Replace {
                original,
                replacement: replacement.clone(),
                api_error,
            })),
        })
        .build()
        .await?;
    let actual = call_route(&auth, &token, native, route).await;
    if native && api_error {
        let error = required(actual.err(), "Native after hook must throw APIError")?;
        assert!(error.is_api_error_instance(ApiErrorClass::BetterAuth));
        assert!(
            required(error.raw_value(), "Expected APIError value")?.strict_equals(&replacement)
        );
        assert_eq!(error.status_code()?, 201);
        ordered(&error.body_value()?, &body)?;
        ordered(&error.headers_value()?, &error_headers)?;
    } else {
        let actual = actual?;
        if native {
            assert!(
                actual.body.field_value()?.strict_equals(&replacement),
                "After hook root identity"
            );
        }
        if api_error {
            assert_eq!(
                actual.headers.get("x-output").map(String::as_str),
                Some("1")
            );
        }
        response(
            actual,
            native,
            if api_error { 201 } else { 200 },
            if api_error { &body } else { &replacement },
        )?;
    }
    assert_eq!(storage.snapshot().await?, before);
    Ok(())
}

#[tokio::test]
async fn organization_success_keeps_after_hook_object_array_identity_and_fields() -> AuthResult<()>
{
    for route in [Route::GetId, Route::Teams] {
        for native in [false, true] {
            for api_error in [false, true] {
                let (raw, storage) = memory_fixture();
                after_hook(raw, storage, route, native, api_error).await?;
                let (raw, storage) = sqlite_fixture().await?;
                after_hook(raw, storage, route, native, api_error).await?;
            }
        }
    }
    Ok(())
}

struct DeleteHooks {
    events: Events,
    metadata: Mutex<Option<FieldValue>>,
}

#[async_trait]
impl OrganizationHooks for DeleteHooks {
    async fn before_delete_organization(
        &self,
        subject: OrganizationUser<'_>,
        _: OrganizationEndpoint<'_>,
    ) -> AuthResult<()> {
        let fields = subject.organization.field_values()?;
        assert!(!fields.contains_key("name"));
        *trace_lock(&self.metadata)? = fields.get("metadata").cloned();
        event(
            &self.events,
            ["beforeDeleteOrganization".into(), fields.into()],
        )
    }
    async fn after_delete_organization(
        &self,
        subject: OrganizationUser<'_>,
        _: OrganizationEndpoint<'_>,
    ) -> AuthResult<()> {
        let fields = subject.organization.field_values()?;
        assert!(
            required(fields.get("metadata"), "Expected hook metadata")?.strict_equals(required(
                trace_lock(&self.metadata)?.as_ref(),
                "Expected before hook metadata"
            )?)
        );
        event(
            &self.events,
            ["afterDeleteOrganization".into(), fields.into()],
        )
    }
}

async fn delete_hooks<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    native: bool,
) -> AuthResult<()> {
    let token = seed_boundary(raw.clone(), Route::Delete).await?;
    let mut before = storage.snapshot().await?;
    let events = Events::default();
    let hooks = Arc::new(DeleteHooks {
        events: events.clone(),
        metadata: Mutex::new(None),
    });
    let metadata: FieldValue = FieldMap::from([(
        "nested".into(),
        FieldMap::from([("value".into(), "shared".into())]).into(),
    )])
    .into();
    let mut plugin = OrganizationConfig {
        hooks: Some(hooks.clone()),
        ..Default::default()
    };
    plugin.schema.organization = declaration([(
        "name",
        UserFieldConfig {
            returned: Some(false),
            ..Default::default()
        },
    )]);
    let auth = BetterAuth::new(settings()?)
        .store_arc(raw)
        .plugin(OrganizationPlugin::with_config(plugin))
        .plugin(Fields(vec![
            (
                EntityRole::Organization,
                declaration([(
                    "metadata",
                    output("metadata", &events, Some(metadata.clone())),
                )]),
            ),
            (
                EntityRole::Session,
                declaration([("updatedAt", session_field(&events))]),
            ),
        ]))
        .build()
        .await?;
    let actual = call_route(&auth, &token, native, Route::Delete).await?;
    let projected = required(
        trace_lock(&hooks.metadata)?.clone(),
        "Expected projected metadata",
    )?;
    assert!(
        !projected.strict_equals(&metadata),
        "Configured output must clone metadata"
    );
    if native {
        assert!(
            actual
                .body
                .field_value()?
                .model_property("metadata")?
                .strict_equals(&projected)
        );
    }
    let expected: FieldValue = FieldMap::from([
        ("slug".into(), "organization".into()),
        ("logo".into(), FieldValue::Null),
        ("createdAt".into(), date().into()),
        ("metadata".into(), projected),
        ("id".into(), "organization".into()),
    ])
    .into();
    response(actual, native, 200, &expected)?;
    let mut expected_events = session_events();
    expected_events.extend([
        vec!["metadata".into(), "output".into(), "{}".into()].into(),
        vec!["beforeDeleteOrganization".into(), expected.clone()].into(),
        vec!["afterDeleteOrganization".into(), expected].into(),
    ]);
    ordered(
        &trace_lock(&events)?.clone().into(),
        &FieldValue::from(expected_events),
    )?;
    cleared_session(&storage, &mut before)?;
    for model in ["organization", "member", "invitation"] {
        required(before.get_mut(model), "Expected deleted model")?.clear();
    }
    assert_eq!(storage.snapshot().await?, before);
    Ok(())
}

#[tokio::test]
async fn organization_delete_hooks_share_projected_fields_with_result() -> AuthResult<()> {
    for native in [false, true] {
        let (raw, storage) = memory_fixture();
        delete_hooks(raw, storage, native).await?;
        let (raw, storage) = sqlite_fixture().await?;
        delete_hooks(raw, storage, native).await?;
    }
    Ok(())
}
