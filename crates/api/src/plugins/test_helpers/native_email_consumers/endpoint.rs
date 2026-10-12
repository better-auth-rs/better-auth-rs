use super::*;
use crate::plugins::test_helpers::{native_session::NativeSessionHook, native_source};
use better_auth_core::{
    AuthContext, AuthRequest, AuthResponse, AuthRoute, AuthSchema, BeforeRequestAction,
    FromFieldMap, HttpMethod,
    endpoint_dispatch::EndpointDispatcher,
    observability::{BeforeEndpointHook, EndpointHooks},
    store::{EphemeralStore, schema::EntityRole},
    wire::SessionView,
};

const TABLES: [(&str, EntityRole); 7] = [
    ("user", EntityRole::User),
    ("session", EntityRole::Session),
    ("account", EntityRole::Account),
    ("verification", EntityRole::Verification),
    ("organization", EntityRole::Organization),
    ("member", EntityRole::Member),
    ("invitation", EntityRole::Invitation),
];

fn seed_value(value: &Json) -> AuthResult<FieldValue> {
    if value["type"] == "date" {
        let text = value["value"]
            .as_str()
            .ok_or_else(|| AuthError::internal("Captured storage Date is missing"))?;
        return Ok(DateTime::parse_from_rfc3339(text)
            .map_err(|error| AuthError::internal(format!("Captured storage Date: {error}")))?
            .with_timezone(&Utc)
            .into());
    }
    if value["type"] == "undefined" {
        return Ok(FieldValue::Undefined);
    }
    match value {
        Json::Object(fields) => fields
            .iter()
            .map(|(name, value)| Ok((name.clone(), seed_value(value)?)))
            .collect::<AuthResult<FieldMap>>()
            .map(Into::into),
        Json::Array(values) => values
            .iter()
            .map(seed_value)
            .collect::<AuthResult<Vec<_>>>()
            .map(Into::into),
        value => FieldValue::from_json(value.clone()),
    }
}

pub(crate) fn memory_from_capture(
    case: &Json,
    config: Arc<AuthConfig>,
) -> AuthResult<Arc<EphemeralStore>> {
    // The captured pre-operation rows are inputs; the replay still compares every original storage descriptor.
    let source = native_source::source_value(&case["before"])?;
    let tables = TABLES
        .into_iter()
        .map(|(name, _)| {
            let rows = source[name]
                .as_array()
                .ok_or_else(|| AuthError::internal(format!("Captured {name} table is missing")))?;
            Ok((
                name.into(),
                rows.iter()
                    .map(|row| seed_value(row)?.enumerable_fields())
                    .collect::<AuthResult<Vec<_>>>()?,
            ))
        })
        .collect::<AuthResult<Vec<_>>>()?;
    Ok(Arc::new(EphemeralStore::from_storage(config, tables)?))
}

pub(crate) fn memory_snapshot(store: &EphemeralStore) -> AuthResult<FieldValue> {
    TABLES
        .into_iter()
        .map(|(name, role)| {
            Ok((
                name.into(),
                store
                    .storage_rows(role)?
                    .into_iter()
                    .map(FieldValue::from)
                    .collect::<Vec<_>>()
                    .into(),
            ))
        })
        .collect::<AuthResult<FieldMap>>()
        .map(Into::into)
}

struct Before {
    trace: Arc<Trace>,
    session: NativeSessionHook,
}

#[async_trait::async_trait]
impl<S: AuthSchema> BeforeEndpointHook<S> for Before {
    async fn before(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.trace.record(
            "endpoint:before",
            FieldMap::from([("path".into(), request.path().into())]),
        )?;
        self.session.before(request, context).await
    }
}

pub(crate) fn native_request<S: AuthSchema>(
    trace: &Arc<Trace>,
    context: &mut AuthContext<S>,
    routes: Vec<AuthRoute>,
    user: FieldValue,
    method: HttpMethod,
    path: &str,
    body: Json,
) -> AuthResult<AuthRequest> {
    let hook = NativeSessionHook::install(context, routes.clone());
    let session = SessionView::from_field_values(FieldMap::from([
        ("id".into(), "injected-session".into()),
        ("userId".into(), "owner".into()),
        ("token".into(), "injected-session-token".into()),
        ("createdAt".into(), date(NOW - 60_000)),
        ("updatedAt".into(), date(NOW - 60_000)),
        ("expiresAt".into(), date(NOW + 3_600_000)),
        ("ipAddress".into(), FieldValue::Null),
        ("userAgent".into(), FieldValue::Null),
        ("activeOrganizationId".into(), FieldValue::Null),
        ("activeTeamId".into(), FieldValue::Null),
    ]))?;
    let request = hook.request(context, &session, user, method, path, body)?;
    context
        .extensions
        .insert(Arc::new(EndpointDispatcher::<S>::new(
            Arc::new(Vec::new()),
            EndpointHooks {
                before: Some(Arc::new(Before {
                    trace: trace.clone(),
                    session: hook,
                })),
                after: None,
            },
            routes,
        )));
    Ok(request)
}

impl Trace {
    pub(crate) fn endpoint_outcome(
        &self,
        result: AuthResult<Option<AuthResponse>>,
        original: &FieldValue,
    ) -> AuthResult<FieldValue> {
        let result = match result {
            Ok(response) => {
                let response = response
                    .ok_or_else(|| AuthError::internal("Native email endpoint did not match"))?;
                let headers = serde_json::to_value(response.headers.iter().collect::<Vec<_>>())?;
                let cookies = serde_json::to_value(
                    response.headers.get_all("set-cookie").collect::<Vec<_>>(),
                )?;
                assert_eq!(
                    headers, self.case["headers"],
                    "{}: complete response headers",
                    self.path
                );
                assert_eq!(
                    cookies, self.case["cookies"],
                    "{}: complete response cookies",
                    self.path
                );
                response.body.field_value()
            }
            Err(error) => {
                assert!(
                    self.case.get("headers").is_none(),
                    "{}: failed native envelope",
                    self.path
                );
                assert!(
                    self.case.get("cookies").is_none(),
                    "{}: failed native cookies",
                    self.path
                );
                Err(error)
            }
        };
        self.outcome(result, original)
    }
}
