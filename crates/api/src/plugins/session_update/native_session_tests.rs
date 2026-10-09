#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Native consumer regressions compare exact callback, cookie, and storage results"
)]

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, CreateDeviceCode,
    CreateSession, CreateUser, CreateVerification, FieldMap, FieldValue, HttpMethod,
    config::CookieCacheConfig,
    id::IdGeneration,
    store::{EphemeralStore, StatelessSchema, StoreCapabilities},
    user_fields::UserFieldConfig,
    wire::SessionView,
};
use chrono::{Duration, Utc};
use serde_json::{Value, json};

use crate::plugins::{
    device_authorization::DeviceAuthorizationPlugin,
    phone_number::PhoneNumberPlugin,
    test_helpers::{
        create_test_config, initialize_test_context,
        native_session::{NativeSessionHook, dispatch, dispatch_plugin},
    },
    two_factor::{BackupCodeStorage, SendTwoFactorOtp, TwoFactorConfig, TwoFactorPlugin},
};

struct Fixture {
    ctx: AuthContext<StatelessSchema>,
    session: SessionView,
    hook: NativeSessionHook,
}

impl Fixture {
    async fn new(plugins: &[&dyn AuthPlugin<StatelessSchema>], serial: bool) -> AuthResult<Self> {
        let mut config = create_test_config();
        config.session.disable_session_refresh = Some(true);
        config.session.cookie_cache = Some(CookieCacheConfig {
            enabled: Some(true),
            ..Default::default()
        });
        let _ = config
            .session
            .fields_mut()
            .insert("label".into(), UserFieldConfig::default());
        if serial {
            config.advanced.database.generate_id = Some(IdGeneration::Serial);
        }
        let config = Arc::new(config);
        let mut ctx = initialize_test_context(
            config.clone(),
            Arc::new(EphemeralStore::new(config)),
            plugins,
        )
        .await?;
        let hook = NativeSessionHook::install(
            &mut ctx,
            plugins.iter().flat_map(|plugin| plugin.routes()).chain(
                AuthPlugin::<StatelessSchema>::routes(
                    &crate::plugins::session_management::SessionManagementPlugin::new(),
                ),
            ),
        );
        let user = ctx
            .database
            .create_user(CreateUser::new().with_email("owner@native-consumer.test"))
            .await?;
        let session = ctx
            .database
            .create_session(CreateSession {
                user_id: user.id,
                expires_at: (Utc::now() + Duration::hours(1)).into(),
                inherited_fields: Default::default(),
                additional_fields: Default::default(),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await?;
        Ok(Self { ctx, session, hook })
    }

    fn request(
        &self,
        user: FieldValue,
        method: HttpMethod,
        path: &str,
        body: Value,
    ) -> AuthResult<AuthRequest> {
        self.hook
            .request(&self.ctx, &self.session, user, method, path, body)
    }

    async fn update(&self, request: &AuthRequest) -> AuthResult<AuthResponse> {
        dispatch(request, &self.ctx, |request| async move {
            super::handle(&request, &self.ctx).await
        })
        .await
    }

    async fn device(&self, owner: Option<&str>) -> AuthResult<()> {
        let _ = self
            .ctx
            .database
            .create_device_code(CreateDeviceCode {
                device_code: "native-device".into(),
                user_code: "ABCD2345".into(),
                user_id: owner.map(str::to_owned),
                expires_at: (Utc::now() + Duration::minutes(5)).into(),
                status: "pending".into(),
                last_polled_at: None,
                polling_interval: Some(5.0),
                client_id: Some("native-client".into()),
                scope: Some("private-scope".into()).into(),
                additional_fields: Default::default(),
            })
            .await?;
        Ok(())
    }
}

fn body(response: &AuthResponse) -> Value {
    serde_json::from_slice(&response.body.bytes().unwrap()).unwrap()
}

#[tokio::test]
async fn update_session_preserves_native_users_and_stateless_missing_row_fallback() -> AuthResult<()>
{
    for user in [
        FieldValue::Null,
        false.into(),
        0.0.into(),
        "".into(),
        FieldMap::from([(
            "0".into(),
            FieldMap::from([("id".into(), "related".into())]).into(),
        )])
        .into(),
    ] {
        let fixture = Fixture::new(&[], false).await?;
        let req = fixture.request(
            user.clone(),
            HttpMethod::Post,
            "/update-session",
            json!({"label":"changed"}),
        )?;
        let response = fixture.update(&req).await?;
        assert_eq!(body(&response)["session"]["label"], "changed");
        let published = req.new_session()?.unwrap();
        assert_eq!(published.user, user);
        assert_eq!(published.session.token, fixture.session.token);
        assert_eq!(
            fixture
                .ctx
                .database
                .get_session(fixture.session.token.typed()?)
                .await?
                .unwrap()
                .additional_fields["label"],
            FieldValue::from("changed")
        );
    }
    for stateful in [false, true] {
        let mut fixture = Fixture::new(&[], false).await?;
        fixture.ctx.extensions.insert(StoreCapabilities {
            database: stateful,
            secondary: false,
        });
        let req = fixture.request(
            false.into(),
            HttpMethod::Post,
            "/update-session",
            json!({"label":"fallback"}),
        )?;
        fixture
            .ctx
            .database
            .delete_session(fixture.session.token.typed()?)
            .await?;
        let result = fixture.update(&req).await;
        if stateful {
            assert_eq!(
                body(&result.unwrap_err().to_auth_response())["code"].as_str(),
                Some("FAILED_TO_GET_SESSION")
            );
            assert!(req.new_session()?.is_none());
        } else {
            assert_eq!(body(&result?)["session"]["label"], "fallback");
            let published = req.new_session()?.unwrap();
            assert_eq!(published.user, FieldValue::Bool(false));
            assert_eq!(published.session.id, fixture.session.id);
        }
        assert!(
            fixture
                .ctx
                .database
                .get_session(fixture.session.token.typed()?)
                .await?
                .is_none()
        );
    }
    Ok(())
}

#[tokio::test]
async fn update_session_rejections_keep_native_api_errors_and_http_status() -> AuthResult<()> {
    use crate::plugins::{
        admin::AdminPlugin,
        organization::{OrganizationPlugin, OrganizationTeamsConfig},
    };
    use better_auth_core::{
        AuthRoute, NativeResponseStatus, endpoint_dispatch::EndpointDispatcher,
    };
    let organization =
        OrganizationPlugin::with_config(Default::default()).teams(OrganizationTeamsConfig {
            enabled: true,
            ..Default::default()
        });
    let admin = AdminPlugin::with_config(Default::default());
    let fixture = Fixture::new(&[&organization, &admin], false).await?;
    let stored = fixture
        .ctx
        .database
        .get_session(fixture.session.token.typed()?)
        .await?;
    let dispatcher = fixture
        .ctx
        .extensions
        .get::<Arc<EndpointDispatcher<StatelessSchema>>>()
        .unwrap();
    for field in [
        None,
        Some("unknown"),
        Some("activeOrganizationId"),
        Some("activeTeamId"),
        Some("impersonatedBy"),
    ] {
        let input = field.map_or_else(|| json!({}), |field| json!({(field):"forbidden"}));
        let expected = if let Some(field) = field.filter(|field| *field != "unknown") {
            json!({"code":"FIELD_NOT_ALLOWED", "message":format!("{field} is not allowed to be set")})
        } else {
            json!({"message":"No fields to update"})
        };
        for http in [false, true] {
            let mut request = fixture.request(
                FieldMap::from([("id".into(), "owner".into())]).into(),
                HttpMethod::Post,
                "/update-session",
                input.clone(),
            )?;
            let context = &fixture.ctx;
            let handler =
                move |request: AuthRequest| async move { super::handle(&request, context).await };
            let result = if http {
                dispatcher
                    .run(&mut request, true, &fixture.ctx, None, handler)
                    .await
            } else {
                dispatcher
                    .native(
                        request.clone(),
                        AuthRoute::post("/update-session", "updateSession"),
                        &fixture.ctx,
                        handler,
                    )
                    .await
            };
            let response = if http {
                result?
            } else {
                let error = result.unwrap_err();
                assert_eq!(error.status_code(), 400);
                error.to_auth_response()
            };
            assert!(response.is_api_error());
            assert_eq!(response.api_error_status(), Some(400));
            assert_eq!(response.native_status(), NativeResponseStatus::Value(400));
            assert_eq!(response.status, 400);
            assert_eq!(body(&response), expected);
            assert!(request.new_session()?.is_none());
            assert_eq!(
                fixture
                    .ctx
                    .database
                    .get_session(fixture.session.token.typed()?)
                    .await?,
                stored
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn device_primitive_users_reach_state_guards_without_claiming_or_disclosing() -> AuthResult<()>
{
    let plugin = DeviceAuthorizationPlugin::new();
    for user in [
        FieldValue::Bool(false),
        0.0.into(),
        "".into(),
        FieldMap::new().into(),
    ] {
        let fixture = Fixture::new(&[&plugin], false).await?;
        fixture.device(None).await?;
        let mut req = fixture.request(user.clone(), HttpMethod::Get, "/device", Value::Null)?;
        req.query = Some(json!({"user_code":"ABCD2345"}));
        let response = dispatch_plugin(&req, &fixture.ctx, &plugin).await?.unwrap();
        assert_eq!(
            body(&response),
            json!({"user_code":"ABCD2345","status":"pending"})
        );
        let req = fixture.request(
            user,
            HttpMethod::Post,
            "/device/approve",
            json!({"userCode":"ABCD2345"}),
        )?;
        let response = dispatch_plugin(&req, &fixture.ctx, &plugin).await?.unwrap();
        assert_eq!(response.status, 400);
        assert_eq!(body(&response)["error"], "invalid_request");
        assert_eq!(
            body(&response)["error_description"],
            "Device code has not been claimed by a verifying session; call `GET /device` with the `user_code` while signed in before approving or denying"
        );
        let device = fixture
            .ctx
            .database
            .get_device_code_by_user_code("ABCD2345")
            .await?
            .unwrap();
        assert!(!device.user_id.field_value().is_truthy());
        assert_eq!(device.status.field_value(), FieldValue::from("pending"));
    }
    let fixture = Fixture::new(&[&plugin], false).await?;
    fixture.device(Some("owner")).await?;
    let req = fixture.request(
        false.into(),
        HttpMethod::Post,
        "/device/deny",
        json!({"userCode":"ABCD2345"}),
    )?;
    let response = dispatch_plugin(&req, &fixture.ctx, &plugin).await?.unwrap();
    assert_eq!(response.status, 403);
    assert_eq!(body(&response)["error"], "access_denied");
    assert_eq!(
        fixture
            .ctx
            .database
            .get_device_code_by_user_code("ABCD2345")
            .await?
            .unwrap()
            .status
            .field_value(),
        FieldValue::from("pending")
    );
    let fixture = Fixture::new(&[&plugin], false).await?;
    fixture.device(None).await?;
    let req = fixture.request(
        FieldValue::Null,
        HttpMethod::Post,
        "/device/approve",
        json!({"userCode":"ABCD2345"}),
    )?;
    let response = dispatch_plugin(&req, &fixture.ctx, &plugin).await?.unwrap();
    assert_eq!(response.status, 400);
    assert_eq!(
        body(&response)["error_description"],
        "Device code has not been claimed by a verifying session; call `GET /device` with the `user_code` while signed in before approving or denying"
    );
    let device = fixture
        .ctx
        .database
        .get_device_code_by_user_code("ABCD2345")
        .await?
        .unwrap();
    assert!(!device.user_id.field_value().is_truthy());
    assert_eq!(device.status.field_value(), FieldValue::from("pending"));
    Ok(())
}

#[tokio::test]
async fn phone_update_binds_native_actor_and_consumes_otp_before_user_failure() -> AuthResult<()> {
    let delivered = Arc::new(Mutex::new(Vec::new()));
    let captured = delivered.clone();
    let plugin = PhoneNumberPlugin::new().callback_on_verification(move |event, _| {
        captured.lock().unwrap().push(event.user);
        async { Ok(()) }
    });
    for actor in [FieldValue::Bool(true), FieldValue::Bool(false)] {
        let fixture = Fixture::new(&[&plugin], true).await?;
        let _ = fixture
            .ctx
            .database
            .create_verification(CreateVerification {
                identifier: "+15551234567".into(),
                value: "123456".into(),
                expires_at: (Utc::now() + Duration::minutes(5)).into(),
                ..Default::default()
            })
            .await?;
        let user = if actor.is_truthy() {
            FieldMap::from([("id".into(), actor.clone())]).into()
        } else {
            actor.clone()
        };
        let req = fixture.request(
            user,
            HttpMethod::Post,
            "/phone-number/verify",
            json!({
                "phoneNumber":"+15551234567", "code":"123456", "updatePhoneNumber":true
            }),
        )?;
        let result = dispatch_plugin(&req, &fixture.ctx, &plugin).await;
        if actor.is_truthy() {
            let response = result?.unwrap();
            assert_eq!(response.status, 200);
            assert_eq!(
                body(&response)["token"],
                fixture.session.token.typed()?.as_str()
            );
            assert_eq!(body(&response)["user"]["phoneNumber"], "+15551234567");
            assert_eq!(delivered.lock().unwrap().len(), 1);
        } else {
            assert_eq!(
                body(&result.unwrap_err().to_auth_response())["code"].as_str(),
                Some("FAILED_TO_UPDATE_USER")
            );
            assert_eq!(delivered.lock().unwrap().len(), 1);
        }
        assert!(
            fixture
                .ctx
                .database
                .get_verification_by_identifier("+15551234567")
                .await?
                .is_none()
        );
        assert!(req.new_session()?.is_none());
    }
    Ok(())
}

#[derive(Default)]
struct OtpOutbox(Mutex<Vec<(FieldValue, String)>>);

#[async_trait::async_trait]
impl SendTwoFactorOtp for OtpOutbox {
    async fn send(&self, user: &FieldValue, otp: &str) -> AuthResult<()> {
        self.0.lock().unwrap().push((user.clone(), otp.into()));
        Ok(())
    }
}

#[tokio::test]
async fn two_factor_primitive_users_preserve_sender_payload_and_branch_order() -> AuthResult<()> {
    let outbox = Arc::new(OtpOutbox::default());
    let plugin = TwoFactorPlugin::with_config(TwoFactorConfig {
        send_otp: Some(outbox.clone()),
        totp_disabled: true,
        ..Default::default()
    });
    for user in [FieldValue::Bool(false), 0.0.into(), "".into()] {
        let fixture = Fixture::new(&[&plugin], false).await?;
        let req = fixture.request(
            user.clone(),
            HttpMethod::Post,
            "/two-factor/send-otp",
            json!({}),
        )?;
        assert_eq!(
            dispatch_plugin(&req, &fixture.ctx, &plugin)
                .await?
                .unwrap()
                .status,
            200
        );
        let (observed, code) = outbox.0.lock().unwrap().last().unwrap().clone();
        assert_eq!(observed, user);
        let key = format!("2fa-otp-undefined!{}", fixture.session.id.typed()?);
        assert_eq!(
            fixture
                .ctx
                .database
                .get_verification_by_identifier(&key)
                .await?
                .unwrap()
                .value
                .field_value(),
            FieldValue::from(format!("{code}:0"))
        );
        let req = fixture.request(
            user,
            HttpMethod::Post,
            "/two-factor/generate-backup-codes",
            json!({"password":"password"}),
        )?;
        let error = dispatch_plugin(&req, &fixture.ctx, &plugin)
            .await
            .unwrap_err();
        assert_eq!(error.status_code(), 400);
        assert_eq!(
            body(&error.to_auth_response())["message"],
            "Two factor isn't enabled"
        );
    }
    let fixture = Fixture::new(&[&plugin], false).await?;
    let req = fixture.request(
        FieldValue::Null,
        HttpMethod::Post,
        "/two-factor/get-totp-uri",
        json!({"password":"password"}),
    )?;
    assert_eq!(
        body(
            &dispatch_plugin(&req, &fixture.ctx, &plugin)
                .await
                .unwrap_err()
                .to_auth_response()
        )["code"]
            .as_str(),
        Some("TOTP_NOT_CONFIGURED")
    );
    Ok(())
}

#[tokio::test]
async fn two_factor_native_actor_keeps_backup_code_cas_and_response_fields() -> AuthResult<()> {
    let mut config = TwoFactorConfig::default();
    config.backup_code_options.storage = BackupCodeStorage::Plain;
    let plugin = TwoFactorPlugin::with_config(config);
    let fixture = Fixture::new(&[&plugin], false).await?;
    let _ = fixture
        .ctx
        .database
        .create_two_factor_record(FieldMap::from([
            ("userId".into(), 17.0.into()),
            ("secret".into(), "unused".into()),
            ("backupCodes".into(), "[\"used\",\"keep\"]".into()),
            ("verified".into(), true.into()),
        ]))
        .await?;
    let user: FieldValue =
        FieldMap::from([("id".into(), 17.0.into()), ("native".into(), false.into())]).into();
    for success in [true, false] {
        let req = fixture.request(
            user.clone(),
            HttpMethod::Post,
            "/two-factor/verify-backup-code",
            json!({"code":"used","disableSession":true}),
        )?;
        let result = dispatch_plugin(&req, &fixture.ctx, &plugin).await;
        if success {
            let response = result?.unwrap();
            assert_eq!(
                body(&response),
                json!({"token":fixture.session.token.typed()?,"user":{"id":17,"native":false}})
            );
        } else {
            assert_eq!(result.unwrap_err().status_code(), 401);
        }
        let row = fixture
            .ctx
            .database
            .get_two_factor_by_user_id_value(&better_auth_core::SchemaValue::from_field(
                17.0.into(),
            ))
            .await?
            .unwrap();
        assert_eq!(
            row.backup_codes.field_value(),
            FieldValue::from("[\"keep\"]")
        );
        assert!(req.new_session()?.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn consumers_read_real_many_relationships_without_a_typed_user_gate() -> AuthResult<()> {
    use better_auth_core::user_fields::UserFieldReference;
    for joins in [false, true] {
        let factor = TwoFactorPlugin::new();
        let device = DeviceAuthorizationPlugin::new();
        let phone = PhoneNumberPlugin::new();
        let mut config = create_test_config();
        config.advanced.database.joins = Some(joins);
        config.session.disable_session_refresh = Some(true);
        let _ = config
            .session
            .fields_mut()
            .insert("label".into(), UserFieldConfig::default());
        let _ = config.user.fields_mut().insert(
            "image".into(),
            UserFieldConfig {
                references: Some(UserFieldReference {
                    model: "session".into(),
                    field: "id".into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let config = Arc::new(config);
        let ctx = initialize_test_context(
            config.clone(),
            Arc::new(EphemeralStore::new(config)),
            &[&factor, &device, &phone],
        )
        .await?;
        let session = ctx
            .database
            .create_session(CreateSession {
                user_id: "canonical-owner".into(),
                expires_at: (Utc::now() + Duration::hours(1)).into(),
                inherited_fields: Default::default(),
                additional_fields: Default::default(),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await?;
        let selected = ctx
            .database
            .create_user(CreateUser {
                email: Some("related@consumer.test".into()),
                image: Some(session.id.typed()?.clone()).into(),
                ..Default::default()
            })
            .await?;
        let request = |path: &str, input: Value| {
            AuthRequest::from_parts(
                HttpMethod::Post,
                path.into(),
                HashMap::from([
                    (
                        "authorization".into(),
                        format!("Bearer {}", session.token.typed().unwrap()),
                    ),
                    ("content-type".into(), "application/json".into()),
                ]),
                Some(serde_json::to_vec(&input).unwrap()),
                None,
            )
        };
        let req = request(
            "/two-factor/generate-backup-codes",
            json!({"password":"password"}),
        );
        assert_eq!(
            factor
                .on_request(&req, &ctx)
                .await
                .unwrap_err()
                .status_code(),
            400
        );
        let fixture = Fixture {
            ctx: ctx.clone(),
            session: session.clone(),
            hook: NativeSessionHook::default(),
        };
        fixture.device(None).await?;
        let req = request("/device/approve", json!({"userCode":"ABCD2345"}));
        let response = device.on_request(&req, &ctx).await?.unwrap();
        assert_eq!(response.status, 400);
        assert_eq!(body(&response)["error"], "invalid_request");
        let _ = ctx
            .database
            .create_verification(CreateVerification {
                identifier: "+15559876543".into(),
                value: "123456".into(),
                expires_at: (Utc::now() + Duration::minutes(5)).into(),
                ..Default::default()
            })
            .await?;
        let req = request(
            "/phone-number/verify",
            json!({"phoneNumber":"+15559876543","code":"123456","updatePhoneNumber":true}),
        );
        assert_eq!(
            phone
                .on_request(&req, &ctx)
                .await
                .unwrap_err()
                .error_payload()
                .1
                .as_deref(),
            Some("FAILED_TO_UPDATE_USER")
        );
        assert!(
            ctx.database
                .get_verification_by_identifier("+15559876543")
                .await?
                .is_none()
        );
        let req = request("/update-session", json!({"label":"related"}));
        assert_eq!(super::handle(&req, &ctx).await?.status, 200);
        let published = req.new_session()?.unwrap();
        assert!(published.user_field("id")?.is_undefined());
        assert_eq!(
            published.user.as_object().unwrap().snapshot_fields()?["0"]
                .as_object()
                .unwrap()
                .snapshot_fields()?["id"],
            selected.id.field_value()
        );
        assert_eq!(
            ctx.database.get_user_by_id(selected.id.typed()?).await?,
            Some(selected.clone())
        );
        assert_eq!(
            ctx.database
                .get_device_code_by_user_code("ABCD2345")
                .await?
                .unwrap()
                .status
                .field_value(),
            FieldValue::from("pending")
        );
    }
    Ok(())
}
