use super::member_contract_support::*;
use super::*;
use better_auth::plugins::organization::{AddMemberInput, types::RoleInput};
use better_auth::server_api::EndpointInput;
use better_auth_core::id::{IdGeneration, IdGenerator};
use better_auth_core::observability::{AfterEndpointHook, EndpointHooks};
use better_auth_core::user_fields::UserFieldFactory;
use better_auth_core::{AuthRecordFields, FromFieldMap, HttpMethod, Member, MemberUserView};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Route {
    Get,
    List,
    Role,
    RemoveId,
    RemoveEmail,
    Update,
    Leave,
    Add,
}

#[derive(Clone, Copy, Debug)]
enum RoleValue {
    String,
    Undefined,
    Null,
    Object,
    Function,
}

#[derive(Clone)]
struct Values {
    function: FieldValue,
    shared: FieldValue,
    extensions: FieldMap,
}

impl Values {
    fn new() -> Self {
        let function: UserFieldFactory = UserFieldFactory::new(|| {
            Err(AuthError::internal("Member output function must not run"))
        });
        let function: FieldValue = FieldValue::Function(function.into());
        let shared: FieldValue = FieldMap::from_iter([("native".into(), true.into())]).into();
        let nested: FieldValue = FieldMap::from_iter([
            ("id".into(), "nested-id".into()),
            ("userId".into(), "nested-user".into()),
            ("token".into(), "nested-token".into()),
            ("expiresAt".into(), date().into()),
            ("activeTeamId".into(), shared.clone()),
        ])
        .into();
        let extensions = FieldMap::from_iter([
            ("ownUndefined".into(), FieldValue::Undefined),
            ("ownNull".into(), FieldValue::Null),
            ("left".into(), shared.clone()),
            ("right".into(), shared.clone()),
            ("token".into(), "member-token".into()),
            ("expiresAt".into(), date().into()),
            ("activeTeamId".into(), shared.clone()),
            ("session".into(), nested),
        ]);
        Self {
            function,
            shared,
            extensions,
        }
    }

    fn role(&self, mode: RoleValue, input: FieldValue) -> FieldValue {
        match mode {
            RoleValue::String => input,
            RoleValue::Undefined => FieldValue::Undefined,
            RoleValue::Null => FieldValue::Null,
            RoleValue::Object => self.shared.clone(),
            RoleValue::Function => self.function.clone(),
        }
    }

    fn member(&self, id: &str, role: &str, user: bool) -> FieldValue {
        let mut fields = FieldMap::from_iter([
            ("organizationId".into(), "organization".into()),
            ("userId".into(), "user-b".into()),
            ("role".into(), role.into()),
            ("createdAt".into(), self.function.clone()),
        ]);
        fields.extend(self.extensions.clone());
        let _ = fields.insert("id".into(), id.into());
        if user {
            let _ = fields.insert(
                "user".into(),
                FieldMap::from_iter([
                    ("id".into(), "user-b".into()),
                    ("name".into(), "user-b".into()),
                    ("email".into(), "user-b@fields.test".into()),
                    ("image".into(), FieldValue::Null),
                ])
                .into(),
            );
        }
        fields.into()
    }
}

type Events = Arc<Mutex<Vec<FieldValue>>>;

fn policy(name: &'static str, value: Option<FieldValue>, events: &Events) -> UserFieldConfig {
    let events = events.clone();
    UserFieldConfig {
        transform: Some(FieldTransforms {
            output: Some(UserFieldTransform::new(move |input| {
                trace_lock(&events)?.push(vec![name.into(), input.clone()].into());
                Ok(value.clone().unwrap_or(input))
            })),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "Contract assertions report mismatches while setup and callback errors propagate"
)]
fn policies(values: &Values, mode: RoleValue, events: &Events) -> AuthResult<UserConfig> {
    let role_value =
        (!matches!(mode, RoleValue::String)).then(|| values.role(mode, FieldValue::Undefined));
    let input_events = events.clone();
    let mut date_policy = policy("createdAt", Some(values.function.clone()), events);
    date_policy.field_type = UserFieldType::Date;
    required(
        date_policy.transform.as_mut(),
        "Expected output callback configuration",
    )?
    .input = Some(UserFieldTransform::new(move |value| {
        assert!(value.as_date().is_some());
        trace_lock(&input_events)?
            .push(vec!["createdAt.input".into(), "native-date".into()].into());
        Ok(date().into())
    }));
    let mut fields = UserConfig {
        additional_fields: Some(
            [
                ("role".into(), policy("role", role_value, events)),
                ("createdAt".into(), date_policy),
            ]
            .into(),
        ),
    };
    for (name, value) in &values.extensions {
        let output_events = events.clone();
        let name = name.clone();
        let output = value.clone();
        let _ = fields.fields_mut().insert(
            name.clone(),
            UserFieldConfig {
                field_name: Some("role".into()),
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |input| {
                        trace_lock(&output_events)?.push(vec![name.clone().into(), input].into());
                        Ok(output.clone())
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    }
    Ok(fields)
}

#[derive(Default)]
struct Observe(Mutex<Option<FieldValue>>);

#[async_trait]
impl<S: AuthSchema> AfterEndpointHook<S> for Observe {
    async fn after(
        &self,
        _: &AuthRequest,
        response: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        *trace_lock(&self.0)? = Some(response.body.field_value()?);
        Ok(())
    }
}

fn request(route: Route) -> (HttpMethod, &'static str, Option<Value>, Option<Value>) {
    match route {
        Route::Get => (
            HttpMethod::Get,
            "/organization/get-active-member",
            None,
            None,
        ),
        Route::List => (
            HttpMethod::Get,
            "/organization/list-members",
            None,
            Some(json!({"limit":"1","sortBy":"id","sortDirection":"asc"})),
        ),
        Route::Role => (
            HttpMethod::Get,
            "/organization/get-active-member-role",
            None,
            None,
        ),
        Route::RemoveId | Route::RemoveEmail => (
            HttpMethod::Post,
            "/organization/remove-member",
            Some(json!({
                "memberIdOrEmail": if route == Route::RemoveId { "member-b" } else { "user-b@fields.test" }, "organizationId":"organization"
            })),
            None,
        ),
        Route::Update => (
            HttpMethod::Post,
            "/organization/update-member-role",
            Some(json!({"memberId":"member-b","role":"admin","organizationId":"organization"})),
            None,
        ),
        Route::Leave => (
            HttpMethod::Post,
            "/organization/leave",
            Some(json!({"organizationId":"organization"})),
            None,
        ),
        Route::Add => (HttpMethod::Post, "", None, None),
    }
}

fn expected_events(timestamp: &FieldValue, route: Route, values: &Values) -> Vec<FieldValue> {
    let roles: &[&str] = match route {
        Route::List | Route::RemoveId | Route::RemoveEmail => &["owner", "member"],
        Route::Update => &["owner", "member", "admin"],
        _ => &["member"],
    };
    let mut events = Vec::new();
    if route == Route::Add {
        events.push(vec!["createdAt.input".into(), "native-date".into()].into());
    }
    for role in roles {
        events.push(vec!["role".into(), (*role).into()].into());
        events.push(vec!["createdAt".into(), timestamp.clone()].into());
        events.extend(
            values
                .extensions
                .keys()
                .map(|name| vec![name.clone().into(), (*role).into()].into()),
        );
    }
    events
}

async fn check<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    route: Route,
    mode: RoleValue,
    native: bool,
) -> AuthResult<()> {
    let actor = if matches!(route, Route::Get | Route::Role | Route::Leave) {
        "user-b"
    } else {
        "user-a"
    };
    let token = seed(raw.clone(), route != Route::Add, actor).await?;
    let before = storage.snapshot().await?;
    let values = Values::new();
    let events = Events::default();
    let observer = Arc::new(Observe::default());
    let plugin = OrganizationPlugin::with_config(OrganizationConfig::default());
    let mut settings = config();
    {
        let better_auth_core::LoggerSource::Config(logger_options) = &mut settings.logger else {
            return Err(AuthError::internal(
                "Fixture requires authored logger options",
            ));
        };
        logger_options.disabled = Some(true);
    }
    settings.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(|input| {
            Ok(Some(format!("{}-a", input.model)))
        })));
    let auth = BetterAuth::new(settings)
        .store_arc(raw)
        .plugin(plugin.clone())
        .plugin(Fields(vec![
            (EntityRole::Member, policies(&values, mode, &events)?),
            (
                EntityRole::Session,
                UserConfig {
                    additional_fields: Some(
                        [(
                            "updatedAt".into(),
                            UserFieldConfig {
                                field_type: UserFieldType::Date,
                                on_update: Some(
                                    better_auth_core::user_fields::UserFieldFactory::new(|| {
                                        Ok(date().into())
                                    }),
                                ),
                                ..Default::default()
                            },
                        )]
                        .into(),
                    ),
                },
            ),
        ]))
        .hooks(EndpointHooks {
            before: None,
            after: Some(observer.clone()),
        })
        .build()
        .await?;
    let signed = better_auth_core::utils::cookie_utils::sign_cookie_value(
        &token,
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
    let (method, path, body, query) = request(route);
    let expected = match route {
        Route::Role => {
            FieldMap::from_iter([("role".into(), values.role(mode, "member".into()))]).into()
        }
        Route::List => FieldMap::from_iter([
            (
                "members".into(),
                vec![values.member("member-b", "member", true)].into(),
            ),
            ("total".into(), 2.into()),
        ])
        .into(),
        Route::RemoveId | Route::RemoveEmail => FieldMap::from_iter([(
            "member".into(),
            values.member("member-b", "member", route == Route::RemoveEmail),
        )])
        .into(),
        Route::Update => values.member("member-b", "admin", false),
        Route::Add => values.member("member-a", "member", false),
        _ => values.member("member-b", "member", true),
    };
    let response = if route == Route::Add {
        let request = AuthRequest::from_parts(HttpMethod::Post, String::new(), headers, None, None);
        let member = plugin
            .add_member(
                AddMemberInput {
                    additional_fields: Default::default(),
                    user_id: "user-b".into(),
                    organization_id: "organization".into(),
                    role: RoleInput::One("member".into()).into(),
                    team_id: Default::default(),
                },
                Some(&request),
                auth.context(),
            )
            .await?;
        AuthResponse::native(None, member.field_values()?.into())
    } else if native {
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
        .await?
    } else {
        let path = format!("/api/auth{path}");
        let mut url = format!("http://fields.test{path}")
            .parse::<url::Url>()
            .map_err(|error| AuthError::internal(error.to_string()))?;
        if let Some(Value::Object(query)) = &query {
            for (key, value) in query {
                let _ = url
                    .query_pairs_mut()
                    .append_pair(key, required(value.as_str(), "Expected string query")?);
            }
        }
        auth.handle_request(
            AuthRequest::from_parts(
                method,
                path,
                headers,
                body.map(|value| serde_json::to_vec(&value)).transpose()?,
                query,
            )
            .with_url(url),
        )
        .await?
    };
    assert_eq!(response.status, 200, "{route:?} {mode:?}");
    if native {
        let actual = response.body.field_value()?;
        ordered(&actual, &expected)?;
        let observed = required(
            trace_lock(&observer.0)?.clone(),
            "Expected native global after-hook output",
        )?;
        ordered(&observed, &expected)?;
        if route != Route::Add {
            assert!(
                actual.strict_equals(&observed),
                "Global hook output root identity"
            );
        }
        let member = if route == Route::Role {
            None
        } else if route == Route::List {
            let members = required(
                required(actual.as_object(), "Expected Member page")?.get("members")?,
                "Expected Member list",
            )?;
            Some(
                required(
                    members
                        .as_array()
                        .map(|members| members.first())
                        .transpose()?
                        .flatten(),
                    "Expected first Member",
                )?
                .clone(),
            )
        } else if matches!(route, Route::RemoveId | Route::RemoveEmail) {
            actual
                .as_object()
                .map(|object| object.get("member"))
                .transpose()?
                .flatten()
        } else {
            Some(actual)
        };
        if let Some(member) = member {
            let member = required(member.as_object(), "Expected native Member object")?;
            for (name, value) in &values.extensions {
                assert!(
                    member
                        .get(name)?
                        .is_some_and(|actual| actual.strict_equals(value)),
                    "{name} identity"
                );
            }
            if route == Route::Get {
                let fields = member.snapshot_fields()?;
                let user = required(fields.get("user"), "Expected joined user summary")?;
                let user = MemberUserView::from_field_values(
                    required(user.as_object(), "Expected user summary object")?
                        .snapshot_fields()?,
                )?;
                let mut projected = Member::from_field_values(fields)?;
                let _ = projected
                    .additional_fields
                    .insert("user".into(), "shadow".into());
                let view = better_auth::plugins::organization::types::MemberResponse {
                    member: projected,
                    user,
                };
                assert_eq!(
                    serde_json::to_vec(&view)?,
                    serde_json::to_vec(&expected.json()?)?
                );
            }
        }
    } else {
        assert_eq!(
            response.body.bytes()?,
            serde_json::to_vec(&expected.json()?)?,
            "{route:?} complete HTTP JSON"
        );
    }
    let timestamp = before
        .get("member")
        .and_then(|rows| rows.first())
        .and_then(|row| {
            row.get(if storage.memory() {
                "createdAt"
            } else {
                "created_at"
            })
        })
        .ok_or_else(|| AuthError::internal("Expected physical Member timestamp"))?;
    assert_eq!(
        *trace_lock(&events)?,
        expected_events(timestamp, route, &values),
        "{route:?} {mode:?}"
    );
    let mut after = before.clone();
    let members = after
        .get_mut("member")
        .ok_or_else(|| AuthError::internal("Expected Member snapshot"))?;
    if matches!(route, Route::RemoveId | Route::RemoveEmail | Route::Leave) {
        members.retain(|row| row.get("id").and_then(FieldValue::as_str) != Some("member-b"));
    } else if route == Route::Update {
        let target = members
            .iter_mut()
            .find(|row| row.get("id").and_then(FieldValue::as_str) == Some("member-b"))
            .ok_or_else(|| AuthError::internal("Expected target Member"))?;
        let _ = target.insert("role".into(), "admin".into());
    } else if route == Route::Add {
        let mut target = members
            .first()
            .cloned()
            .ok_or_else(|| AuthError::internal("Expected owner Member"))?;
        let _ = target.insert("id".into(), "member-a".into());
        let _ = target.insert(
            if storage.memory() {
                "userId"
            } else {
                "user_id"
            }
            .into(),
            "user-b".into(),
        );
        let _ = target.insert("role".into(), "member".into());
        members.insert(0, target);
    }
    if route == Route::Leave {
        let updated = if storage.memory() {
            "updatedAt"
        } else {
            "updated_at"
        };
        let timestamp = before
            .get("user")
            .and_then(|rows| rows.first())
            .and_then(|row| row.get(updated))
            .cloned()
            .ok_or_else(|| AuthError::internal("Expected fixed physical User timestamp"))?;
        for session in after
            .get_mut("session")
            .ok_or_else(|| AuthError::internal("Expected Session snapshot"))?
        {
            let _ = session.insert(updated.into(), timestamp.clone());
            let _ = session.insert(
                if storage.memory() {
                    "activeOrganizationId"
                } else {
                    "active_organization_id"
                }
                .into(),
                FieldValue::Null,
            );
        }
    }
    assert_eq!(
        storage.snapshot().await?,
        after,
        "{route:?} complete storage"
    );
    Ok(())
}

fn cases() -> Vec<(Route, RoleValue, bool)> {
    let mut cases = Vec::new();
    for native in [true, false] {
        for route in [
            Route::Get,
            Route::List,
            Route::Role,
            Route::RemoveId,
            Route::RemoveEmail,
            Route::Update,
            Route::Leave,
        ] {
            cases.push((route, RoleValue::String, native));
        }
        for mode in [
            RoleValue::Undefined,
            RoleValue::Null,
            RoleValue::Object,
            RoleValue::Function,
        ] {
            cases.push((Route::Role, mode, native));
        }
    }
    cases.push((Route::Add, RoleValue::String, true));
    cases
}

#[tokio::test]
async fn memory_member_routes_preserve_native_values_identity_and_storage() -> AuthResult<()> {
    for (route, mode, native) in cases() {
        let (raw, storage) = memory_fixture();
        check(raw, storage, route, mode, native).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_member_routes_preserve_native_values_identity_and_storage() -> AuthResult<()> {
    for (route, mode, native) in cases() {
        let (raw, storage) = sqlite_fixture().await?;
        check(raw, storage, route, mode, native).await?;
    }
    Ok(())
}
