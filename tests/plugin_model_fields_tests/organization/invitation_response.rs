use super::*;
use better_auth::server_api::EndpointInput;
use better_auth_core::{CreateInvitation, HttpMethod, Member};

#[path = "invitation_response_fixture.rs"]
mod fixture;
#[path = "invitation_response_support.rs"]
mod support;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    Get,
    GetClone,
    List,
    UserFunction,
    UserFunctionJoin,
    UserUndefined,
    Accept,
    Reject,
    Cancel,
}

impl Case {
    const ALL: [Self; 9] = [
        Self::Get,
        Self::GetClone,
        Self::List,
        Self::UserFunction,
        Self::UserFunctionJoin,
        Self::UserUndefined,
        Self::Accept,
        Self::Reject,
        Self::Cancel,
    ];
    fn user_list(self) -> bool {
        matches!(
            self,
            Self::UserFunction | Self::UserFunctionJoin | Self::UserUndefined
        )
    }
    fn actor(self) -> &'static str {
        if matches!(self, Self::List | Self::Cancel) {
            "user-a"
        } else {
            "user-b"
        }
    }
    fn endpoint(self) -> (&'static str, HttpMethod) {
        match self {
            Self::Get | Self::GetClone => ("get-invitation", HttpMethod::Get),
            Self::List => ("list-invitations", HttpMethod::Get),
            Self::UserFunction | Self::UserFunctionJoin | Self::UserUndefined => {
                ("list-user-invitations", HttpMethod::Get)
            }
            Self::Accept => ("accept-invitation", HttpMethod::Post),
            Self::Reject => ("reject-invitation", HttpMethod::Post),
            Self::Cancel => ("cancel-invitation", HttpMethod::Post),
        }
    }
    fn status(self) -> &'static str {
        match self {
            Self::Accept => "accepted",
            Self::Reject => "rejected",
            Self::Cancel => "canceled",
            _ => "pending",
        }
    }
}

fn user(id: &str) -> FieldValue {
    FieldMap::from_iter([
        ("id".into(), id.into()),
        ("name".into(), id.into()),
        (
            "email".into(),
            format!("{id}@team-member-fields.test").into(),
        ),
        ("emailVerified".into(), true.into()),
        ("image".into(), FieldValue::Null),
        ("createdAt".into(), date(0).into()),
        ("updatedAt".into(), date(0).into()),
    ])
    .into()
}

fn visible_invitation(values: &support::Values, status: &str) -> FieldMap {
    [
        ("organizationId".into(), "organization".into()),
        ("email".into(), "user-b@team-member-fields.test".into()),
        ("role".into(), "member".into()),
        ("teamId".into(), FieldValue::Null),
        ("status".into(), status.into()),
        ("expiresAt".into(), date(30).into()),
        ("createdAt".into(), values.invitation.clone()),
        ("inviterId".into(), "user-a".into()),
        ("probeUndefined".into(), FieldValue::Undefined),
        ("probeNull".into(), FieldValue::Null),
        ("organizationName".into(), "shadow-name".into()),
        ("organizationSlug".into(), "shadow-slug".into()),
        ("inviterEmail".into(), "shadow-email".into()),
        ("id".into(), "invitation-a".into()),
    ]
    .into()
}

fn visible_member(values: &support::Values) -> FieldMap {
    [
        ("organizationId".into(), "organization".into()),
        ("userId".into(), "user-b".into()),
        ("role".into(), "member".into()),
        ("createdAt".into(), date(0).into()),
        ("probeUndefined".into(), FieldValue::Undefined),
        ("probeNull".into(), FieldValue::Null),
        ("probeFunction".into(), values.member.clone()),
        ("id".into(), "member-a".into()),
    ]
    .into()
}

fn expected_response(case: Case, values: &support::Values) -> FieldValue {
    let mut invitation = visible_invitation(values, case.status());
    match case {
        Case::Get | Case::GetClone => {
            let _ = invitation.insert("organizationName".into(), FieldValue::Undefined);
            let _ = invitation.insert("organizationSlug".into(), FieldValue::Null);
            let _ = invitation.insert(
                "inviterEmail".into(),
                "user-a@team-member-fields.test".into(),
            );
            invitation.into()
        }
        Case::List => vec![invitation.into()].into(),
        Case::UserFunction | Case::UserFunctionJoin | Case::UserUndefined => {
            let _ = invitation.insert(
                "organizationName".into(),
                if case == Case::UserUndefined {
                    FieldValue::Undefined
                } else {
                    values.organization.clone()
                },
            );
            vec![invitation.into()].into()
        }
        Case::Accept | Case::Reject => FieldMap::from_iter([
            ("invitation".into(), invitation.into()),
            (
                "member".into(),
                if case == Case::Accept {
                    visible_member(values).into()
                } else {
                    FieldValue::Null
                },
            ),
        ])
        .into(),
        Case::Cancel => invitation.into(),
    }
}

fn output_events(storage: &Storage, model: &str, role: &str) -> Vec<FieldValue> {
    let mut events = vec![event(
        &format!("{model}.createdAt"),
        "output",
        storage.stored_date(0),
    )];
    let extras: &[&str] = if model == "invitation" {
        &[
            "probeUndefined",
            "probeNull",
            "organizationName",
            "organizationSlug",
            "inviterEmail",
        ]
    } else {
        &["probeUndefined", "probeNull", "probeFunction"]
    };
    events.extend(
        extras
            .iter()
            .map(|name| event(&format!("{model}.{name}"), "output", role.into())),
    );
    events
}

fn expected_hook(case: Case, values: &support::Values, status: &str, after: bool) -> FieldValue {
    let organization = FieldMap::from_iter([
        ("slug".into(), "organization".into()),
        ("logo".into(), FieldValue::Null),
        ("createdAt".into(), date(0).into()),
        ("metadata".into(), "{}".into()),
        ("id".into(), "organization".into()),
    ]);
    let mut fields: FieldMap = [
        (
            "invitation".into(),
            visible_invitation(values, status).into(),
        ),
        (
            if case == Case::Cancel {
                "cancelledBy"
            } else {
                "user"
            }
            .into(),
            user(case.actor()),
        ),
        ("organization".into(), organization.into()),
    ]
    .into();
    if case == Case::Accept && after {
        let _ = fields.insert("member".into(), visible_member(values).into());
    }
    fields.into()
}

fn expected_events(storage: &Storage, case: Case, values: &support::Values) -> Vec<FieldValue> {
    let invitation = output_events(storage, "invitation", "member");
    let organization = event("organization.name", "output", "Organization".into());
    let member = output_events(storage, "member", "owner");
    if case == Case::List {
        return member.into_iter().chain(invitation).collect();
    }
    let mut events = invitation.clone();
    if case == Case::Cancel {
        events.extend(member.clone());
    }
    events.push(organization);
    if matches!(case, Case::Get | Case::GetClone) {
        events.push(event("organization.slug", "output", "organization".into()));
        if case == Case::Get {
            events.extend(member);
        }
    } else if !case.user_list() {
        let action = match case {
            Case::Accept => "Accept",
            Case::Reject => "Reject",
            Case::Cancel => "Cancel",
            _ => unreachable!(),
        };
        events.push(event(
            &format!("before{action}Invitation"),
            "hook",
            expected_hook(case, values, "pending", false),
        ));
        events.extend(invitation);
        if case == Case::Accept {
            events.push(event("member.createdAt", "input", "native-date".into()));
            events.extend(output_events(storage, "member", "member"));
            events.push(event("session.updatedAt", "input", "native-date".into()));
        }
        events.push(event(
            &format!("after{action}Invitation"),
            "hook",
            expected_hook(case, values, case.status(), true),
        ));
    }
    events
}

fn assert_ordered(actual: &FieldValue, expected: &FieldValue) -> AuthResult<()> {
    assert_eq!(actual, expected);
    if let (Some(actual), Some(expected)) = (actual.as_object(), expected.as_object()) {
        let actual = actual.snapshot_fields()?;
        let expected = expected.snapshot_fields()?;
        assert_eq!(
            actual.keys().collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>()
        );
        for (name, value) in &expected {
            assert_ordered(&actual[name], value)?;
        }
    } else if let (Some(actual), Some(expected)) = (actual.as_array(), expected.as_array()) {
        for (actual, expected) in actual.iter().zip(expected) {
            assert_ordered(actual, expected)?;
        }
    }
    Ok(())
}

async fn check<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    case: Case,
    native: bool,
) -> AuthResult<()> {
    let token = fixture::seed(raw.as_ref(), case).await?;
    let mut before = fixture::snapshot(&storage).await?;
    let events = Events::default();
    let values = support::Values::new(&events);
    let auth = support::auth(raw, case, &events, &values).await?;
    assert!(events.take()?.is_empty());
    let headers = std::collections::HashMap::from([
        ("content-type".into(), "application/json".into()),
        ("origin".into(), "http://fields.test".into()),
        (
            "cookie".into(),
            format!(
                "better-auth.session_token={}",
                better_auth_core::utils::cookie_utils::sign_cookie_value(
                    &token,
                    auth.config().signing_secret()
                )
            ),
        ),
    ]);
    let (endpoint, method) = case.endpoint();
    let path = format!("/organization/{endpoint}");
    let query = match case {
        Case::Get | Case::GetClone => Some(json!({"id":"invitation-a"})),
        Case::List => Some(json!({"organizationId":"organization"})),
        _ => None,
    };
    let body = (method == HttpMethod::Post).then(|| json!({"invitationId":"invitation-a"}));
    let response = if native {
        auth.call_endpoint(
            method,
            &path,
            EndpointInput {
                headers: Some(headers),
                query,
                body,
                ..Default::default()
            },
        )
        .await
    } else {
        let query_text = match case {
            Case::Get | Case::GetClone => "?id=invitation-a",
            Case::List => "?organizationId=organization",
            _ => "",
        };
        let request = AuthRequest::from_parts(
            method,
            format!("/api/auth{path}"),
            headers,
            body.as_ref().map(serde_json::to_vec).transpose()?,
            query,
        )
        .with_url(
            format!("http://fields.test/api/auth{path}{query_text}")
                .parse()
                .map_err(|error| AuthError::internal(format!("Invalid invitation URL: {error}")))?,
        );
        auth.handle_request(request).await
    };
    if case == Case::GetClone {
        if native {
            let error =
                response.expect_err("Configured organization output must clone before filtering");
            assert!(matches!(error, AuthError::DataClone));
            assert_eq!(error.to_string(), "The object can not be cloned.");
        } else {
            let response = response?;
            assert_eq!(response.status, 500);
            assert!(response.body.bytes()?.is_empty());
        }
        assert_eq!(events.take()?, expected_events(&storage, case, &values));
        assert_eq!(fixture::snapshot(&storage).await?, before);
        return Ok(());
    }
    let response = response?;
    assert_eq!(response.status, 200, "{case:?}");
    let expected = expected_response(case, &values);
    if native {
        assert_ordered(&response.body.field_value()?, &expected)?;
    } else {
        assert_eq!(
            response.body.bytes()?,
            serde_json::to_vec(&required(expected.json()?, "Expected a JSON response")?)?
        );
    }
    assert_eq!(
        events.take()?,
        expected_events(&storage, case, &values),
        "{case:?}"
    );
    fixture::update_expected(&storage, case, &mut before)?;
    assert_eq!(fixture::snapshot(&storage).await?, before, "{case:?}");
    Ok(())
}

#[tokio::test]
async fn memory_invitation_routes_preserve_native_values_order_hooks_and_storage() -> AuthResult<()>
{
    for case in Case::ALL {
        for native in [false, true] {
            let store = EphemeralStore::new(Arc::new(config()));
            let raw: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(store.clone());
            check(raw, Storage::Memory(Box::new(store)), case, native).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_invitation_routes_preserve_native_values_order_hooks_and_storage() -> AuthResult<()>
{
    for case in Case::ALL {
        for native in [false, true] {
            let mut options = ConnectOptions::new("sqlite::memory:");
            let _ = options.max_connections(1);
            let database = Database::connect(options)
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
            migrator::run_migrations(&database)
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
            let raw: Arc<dyn AuthStore<BundledSchema>> = Arc::new(
                SeaOrmStore::<BundledSchema>::new(config(), database.clone()),
            );
            check(raw, Storage::Sqlite(database), case, native).await?;
        }
    }
    Ok(())
}
