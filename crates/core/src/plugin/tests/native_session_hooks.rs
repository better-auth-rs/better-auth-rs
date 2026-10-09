#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Session hook regressions inspect exact native identity and complete persisted fixture records"
)]

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use crate::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    BeforeRequestAction, CreateUser, FieldMap, FieldValue, HttpMethod,
    config::CookieCacheConfig,
    endpoint_dispatch::EndpointDispatcher,
    observability::{BeforeEndpointHook, EndpointHooks},
    session::{NativeSessionData, SessionRead},
    store::{EphemeralStore, StatelessSchema, StoreCapabilities},
};
use async_trait::async_trait;

#[derive(Clone)]
struct Inject {
    data: NativeSessionData,
    virtual_only: bool,
    calls: Arc<AtomicUsize>,
}

impl Inject {
    fn new(data: NativeSessionData, virtual_only: bool) -> Self {
        Self {
            data,
            virtual_only,
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn action(&self) -> BeforeRequestAction {
        let _ = self.calls.fetch_add(1, Ordering::SeqCst);
        if self.virtual_only {
            BeforeRequestAction::InjectSession {
                session: Box::new(self.data.session.clone()),
            }
        } else {
            BeforeRequestAction::InjectNativeSession {
                session: Box::new(self.data.clone()),
            }
        }
    }
}

#[async_trait]
impl BeforeEndpointHook<StatelessSchema> for Inject {
    async fn before(
        &self,
        _: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        Ok(Some(self.action()))
    }
}

#[async_trait]
impl AuthPlugin<StatelessSchema> for Inject {
    fn name(&self) -> &'static str {
        "trusted-session-fixture"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn before_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        Ok(Some(self.action()))
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

async fn fixture() -> AuthResult<(AuthContext<StatelessSchema>, NativeSessionData)> {
    let mut config = (*crate::test_store::test_config()).clone();
    config.session.disable_session_refresh = Some(true);
    config.session.cookie_cache = Some(CookieCacheConfig {
        enabled: Some(true),
        ..Default::default()
    });
    let config = Arc::new(config);
    let context = AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config)));
    let user = context
        .database
        .create_user(CreateUser::new().with_email("owner@trusted-session.test"))
        .await?;
    let session = context
        .session_manager()
        .create_session(&user, None, None)
        .await?;
    let data = NativeSessionData {
        session,
        user: FieldMap::from(context.user_view(&user).await?).into(),
    };
    Ok((context, data))
}

fn dispatcher(hook: &Inject) -> EndpointDispatcher<StatelessSchema> {
    EndpointDispatcher::new(
        Arc::new(Vec::new()),
        EndpointHooks {
            before: Some(Arc::new(hook.clone())),
            after: None,
        },
        [AuthRoute::post("/session-probe", "sessionProbe")],
    )
}

#[tokio::test]
async fn trusted_hooks_preserve_native_user_identity_for_http_and_native_consumers()
-> AuthResult<()> {
    let shared: FieldValue = FieldMap::from([("native".into(), FieldValue::Undefined)]).into();
    for (user, body) in [
        (FieldValue::Null, Some("null")),
        (FieldValue::Undefined, None),
        (false.into(), Some("false")),
        (0.0.into(), Some("0")),
        ("".into(), Some("")),
        (vec![shared.clone(), shared.clone()].into(), Some("[{},{}]")),
        (
            FieldMap::from([
                ("id".into(), 17.0.into()),
                ("shared".into(), shared.clone()),
            ])
            .into(),
            Some(r#"{"id":17,"shared":{}}"#),
        ),
    ] {
        for (http, stateful) in [(true, true), (false, true), (true, false), (false, false)] {
            let (mut context, mut data) = fixture().await?;
            context.extensions.insert(StoreCapabilities {
                database: stateful,
                secondary: false,
            });
            let stored = context
                .database
                .get_session(data.session.token.typed()?)
                .await?;
            data.user = user.clone();
            let hook = Inject::new(data.clone(), false);
            let dispatcher = dispatcher(&hook);
            let mut request = AuthRequest::new(HttpMethod::Post, "/session-probe");
            let read = if stateful {
                SessionRead::Cached
            } else {
                SessionRead::Authoritative
            };
            let handler = |request: AuthRequest| {
                let context = &context;
                let user = &user;
                async move {
                    let resolved = context.native_session(&request, read).await?.unwrap();
                    assert!(resolved.user.strict_equals(user));
                    assert!(
                        request
                            .native_session_snapshot()?
                            .unwrap()
                            .user
                            .strict_equals(user)
                    );
                    assert!(request.new_session()?.is_none());
                    if matches!(user, FieldValue::Array(_)) {
                        assert!(request.session_snapshot().is_err());
                    }
                    Ok(AuthResponse::native(200, resolved.user))
                }
            };
            let response = if http {
                dispatcher
                    .run(&mut request, true, &context, None, handler)
                    .await?
            } else {
                dispatcher
                    .native(
                        request,
                        AuthRoute::post("/session-probe", "sessionProbe"),
                        &context,
                        handler,
                    )
                    .await?
            };
            assert_eq!(response.status, 200);
            assert_eq!(response.is_native(), !http);
            if http {
                assert_eq!(
                    response.headers.get("content-type").map(String::as_str),
                    Some("application/json")
                );
                assert_eq!(
                    matches!(response.body, crate::ResponseBody::Empty),
                    body.is_none()
                );
                assert_eq!(
                    response.body.bytes()?.as_ref(),
                    body.unwrap_or_default().as_bytes()
                );
            } else {
                assert!(response.body.field_value()?.strict_equals(&user));
            }
            assert_eq!(hook.calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                context
                    .database
                    .get_session(data.session.token.typed()?)
                    .await?,
                stored
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn authoritative_server_reads_discard_injected_users_and_cannot_restore_revoked_sessions()
-> AuthResult<()> {
    for capabilities in [
        StoreCapabilities {
            database: true,
            secondary: false,
        },
        StoreCapabilities {
            database: false,
            secondary: true,
        },
    ] {
        let (mut context, persisted) = fixture().await?;
        context.extensions.insert(capabilities);
        let user_id = persisted.user_property("id")?.as_str().unwrap();
        let stored_user = context.database.get_user_by_id(user_id).await?;
        let mut injected = persisted.clone();
        injected.user = FieldMap::from([
            ("id".into(), "another-user".into()),
            ("role".into(), "admin".into()),
        ])
        .into();
        let hook = Inject::new(injected, false);
        let dispatcher = dispatcher(&hook);
        for revoked in [false, true] {
            if revoked {
                context
                    .database
                    .delete_session(persisted.session.token.typed()?)
                    .await?;
            }
            let mut request = AuthRequest::new(HttpMethod::Post, "/session-probe");
            let name = context
                .config
                .auth_cookie("session_token", Default::default())
                .name;
            let token = crate::utils::cookie_utils::sign_cookie_value(
                persisted.session.token.typed()?,
                context.config.signing_secret(),
            );
            let _ = request
                .headers
                .insert("cookie".into(), format!("{name}={token}"));
            let response = dispatcher
                .run(&mut request, true, &context, None, |request| {
                    let context = &context;
                    let expected = &persisted.user;
                    async move {
                        let result = context.require_authoritative_native_session(&request).await;
                        if revoked {
                            assert!(matches!(result, Err(AuthError::Unauthenticated)));
                            assert!(request.native_session_snapshot()?.is_none());
                            assert!(
                                context
                                    .native_session(&request, SessionRead::Cached)
                                    .await?
                                    .is_none()
                            );
                        } else {
                            assert_eq!(result?.user, *expected);
                        }
                        assert!(request.new_session()?.is_none());
                        Ok(AuthResponse::new(204))
                    }
                })
                .await?;
            assert_eq!(response.status, 204);
            assert_eq!(context.database.get_user_by_id(user_id).await?, stored_user);
            assert_eq!(
                context
                    .database
                    .get_session(persisted.session.token.typed()?)
                    .await?
                    .is_none(),
                revoked
            );
        }
        assert_eq!(hook.calls.load(Ordering::SeqCst), 2);
    }
    Ok(())
}

#[tokio::test]
async fn cookie_and_json_input_cannot_install_a_trusted_native_session() -> AuthResult<()> {
    for user in [
        FieldValue::Null,
        false.into(),
        vec![FieldValue::Null].into(),
        FieldMap::from([("id".into(), 17.0.into())]).into(),
    ] {
        let (context, mut data) = fixture().await?;
        let stored_user = context
            .database
            .get_user_by_id(data.session.user_id.typed()?)
            .await?;
        data.user = user;
        let issuance = AuthRequest::new(HttpMethod::Post, "/sign-in/email");
        context
            .session_manager()
            .set_native_session_cookie(&issuance, data.clone(), None)
            .await?;
        let cookie = issuance
            .take_response_headers()?
            .get_all("set-cookie")
            .map(|cookie| cookie.split(';').next().unwrap().to_owned())
            .collect::<Vec<_>>()
            .join("; ");
        context
            .database
            .delete_session(data.session.token.typed()?)
            .await?;
        let mut request = AuthRequest::new(HttpMethod::Post, "/session-probe");
        let _ = request.headers.insert("cookie".into(), cookie);
        request.body = Some(serde_json::to_vec(&serde_json::json!({
            "session":{"session":data.session,"user":{"id":"forged","role":"admin"}},
        }))?);
        let dispatcher = EndpointDispatcher::new(
            Arc::new(Vec::new()),
            Default::default(),
            [AuthRoute::post("/session-probe", "sessionProbe")],
        );
        let response = dispatcher
            .run(&mut request, true, &context, None, |request| {
                let context = &context;
                async move {
                    assert!(request.native_session_snapshot()?.is_none());
                    assert!(
                        context
                            .native_session(&request, SessionRead::Cached)
                            .await?
                            .is_none()
                    );
                    assert!(request.native_session_snapshot()?.is_none());
                    assert!(request.new_session()?.is_none());
                    Ok(AuthResponse::new(204))
                }
            })
            .await?;
        assert_eq!(response.status, 204);
        assert_eq!(
            context
                .database
                .get_user_by_id(data.session.user_id.typed()?)
                .await?,
            stored_user
        );
        assert!(
            context
                .database
                .get_session(data.session.token.typed()?)
                .await?
                .is_none()
        );
    }
    Ok(())
}

#[tokio::test]
async fn later_session_hooks_replace_earlier_native_or_api_key_style_injection() -> AuthResult<()> {
    for native_last in [false, true] {
        let (context, stored) = fixture().await?;
        let native = Inject::new(
            NativeSessionData {
                session: stored.session.clone(),
                user: false.into(),
            },
            false,
        );
        let mut virtual_data = stored.clone();
        virtual_data.session.token = "virtual-token".into();
        let virtual_hook = Inject::new(virtual_data, true);
        let (first, last) = if native_last {
            (&virtual_hook, &native)
        } else {
            (&native, &virtual_hook)
        };
        let plugins: Vec<Box<dyn AuthPlugin<StatelessSchema>>> = vec![Box::new(last.clone())];
        let dispatcher = EndpointDispatcher::new(
            Arc::new(plugins),
            EndpointHooks {
                before: Some(Arc::new(first.clone())),
                after: None,
            },
            [AuthRoute::post("/session-probe", "sessionProbe")],
        );
        let mut request = AuthRequest::new(HttpMethod::Post, "/session-probe");
        let _ = dispatcher
            .run(&mut request, true, &context, None, |request| {
                let context = &context;
                let stored = &stored;
                async move {
                    let selected = context.require_native_session(&request).await?;
                    if native_last {
                        assert!(selected.user.strict_equals(&FieldValue::Bool(false)));
                        assert_eq!(selected.session.token, stored.session.token);
                        assert!(request.virtual_session().is_none());
                    } else {
                        assert_eq!(selected.user, stored.user);
                        assert_eq!(selected.session.token.field_value(), "virtual-token".into());
                    }
                    Ok(AuthResponse::new(204))
                }
            })
            .await?;
        assert_eq!(first.calls.load(Ordering::SeqCst), 1);
        assert_eq!(last.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            context
                .database
                .get_user_sessions(stored.session.user_id.typed()?)
                .await?
                .len(),
            1
        );
        assert!(
            context
                .database
                .get_session("virtual-token")
                .await?
                .is_none()
        );
    }
    Ok(())
}
