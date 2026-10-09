#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "SIWE route contracts require complete fixture snapshots and immediate failure on missing state."
)]

use super::*;
use better_auth_core::{
    AuthInitContext, AuthPlugin, HttpMethod,
    store::{
        AuthStore, EphemeralStore, StatelessSchema,
        database_hooks::{DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks},
        schema::EntityRole,
    },
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
    },
};
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

const ADDRESS: &str = "0x0000000000000000000000000000000000000001";
const NONCE: &str = "native123";

struct CancelSession;

#[better_auth_core::database_hooks()]
impl DatabaseHooks<StatelessSchema> for CancelSession {
    async fn before_create_session(
        &self,
        _data: &mut FieldMap,
        _ctx: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        Ok(DatabaseHookUpdate::Cancel)
    }
}

fn output(field_type: UserFieldType, value: FieldValue) -> UserFieldConfig {
    UserFieldConfig {
        field_type,
        transform: Some(FieldTransforms {
            input: None,
            output: Some(UserFieldTransform::new(move |_| Ok(value.clone()))),
        }),
        ..Default::default()
    }
}

async fn fixture(
    cancel: bool,
) -> AuthResult<(
    SiwePlugin,
    AuthContext<StatelessSchema>,
    Arc<AtomicUsize>,
    Arc<Mutex<Vec<f64>>>,
)> {
    let mut config = crate::plugins::test_helpers::create_test_config();
    config.advanced.database.generate_id = Some(better_auth_core::id::IdGeneration::Serial);
    let reads = Arc::new(AtomicUsize::new(0));
    let calls = reads.clone();
    let _ = config.user.fields_mut().insert(
        "name".into(),
        UserFieldConfig {
            field_type: UserFieldType::String,
            transform: Some(FieldTransforms {
                input: None,
                output: Some(UserFieldTransform::new(move |_| {
                    Ok(format!("selected-{}", calls.fetch_add(1, Ordering::SeqCst) + 1).into())
                })),
            }),
            ..Default::default()
        },
    );
    let _ = config
        .session
        .fields_mut()
        .insert("token".into(), output(UserFieldType::String, 42.0.into()));
    let config = Arc::new(config);
    let store: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(EphemeralStore::new(config.clone()));
    let mut init = AuthInitContext::new(config.clone(), store.clone());
    let verified = Arc::new(Mutex::new(Vec::new()));
    let seen = verified.clone();
    let plugin = SiwePlugin::new(
        "example.com",
        || async { Ok(NONCE.into()) },
        move |input| {
            seen.lock().unwrap().push(input.chain_id);
            async { Ok(true) }
        },
    );
    plugin.on_init(&mut init).await?;
    init.register_model_fields(
        EntityRole::WalletAddress,
        UserConfig {
            additional_fields: Some(
                [
                    ("userId".into(), output(UserFieldType::Number, 1.0.into())),
                    (
                        "address".into(),
                        output(UserFieldType::String, FieldMap::new().into()),
                    ),
                    (
                        "chainId".into(),
                        output(UserFieldType::Number, FieldValue::Null),
                    ),
                    (
                        "isPrimary".into(),
                        output(UserFieldType::Boolean, FieldValue::Undefined),
                    ),
                    (
                        "createdAt".into(),
                        output(UserFieldType::Date, false.into()),
                    ),
                ]
                .into(),
            ),
        },
    )?;
    if cancel {
        init.register_database_hook(Arc::new(CancelSession));
    }
    let parts = init.into_parts();
    let store = store.with_runtime(config.clone(), parts.database_hooks, parts.plugin_fields)?;
    let mut context = AuthContext::new(config, store);
    context.extensions = parts.extensions;
    Ok((plugin, context, reads, verified))
}

async fn request(ctx: &AuthContext<StatelessSchema>, chain: &str) -> AuthResult<AuthRequest> {
    let _ = ctx
        .database
        .create_verification(CreateVerification {
            identifier: format!("siwe:{NONCE}").into(),
            value: NONCE.into(),
            expires_at: (Utc::now() + Duration::minutes(5)).into(),
            ..Default::default()
        })
        .await?;
    let mut request = AuthRequest::new(HttpMethod::Post, "/siwe/verify");
    request.body = Some(serde_json::to_vec(
        &json!({"message":format!("example.com wants you to sign in with your Ethereum account:\n{ADDRESS}\n\nChain ID: {chain}\nNonce: {NONCE}"),"signature":"verified-by-application"}),
    )?);
    Ok(request)
}

#[tokio::test]
async fn wallet_native_owner_lookup_reuses_selected_user_and_ignores_other_wallet_projections()
-> AuthResult<()> {
    let (plugin, ctx, reads, verified) = fixture(false).await?;
    let _ = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("native@siwe.test")
                .with_name("Stored name"),
        )
        .await?;
    let _ = ctx
        .database
        .create_wallet_address_record(FieldMap::from([
            ("userId".into(), 1.0.into()),
            ("address".into(), ADDRESS.into()),
            ("chainId".into(), 1.0.into()),
            ("isPrimary".into(), true.into()),
            (
                "createdAt".into(),
                better_auth_core::FieldDate::from(Utc::now()).into(),
            ),
        ]))
        .await?;
    reads.store(0, Ordering::SeqCst);
    let request = request(&ctx, "0x1").await?;
    let response = plugin.verify(&request, &ctx).await?;
    assert_eq!(response.status, 200);
    let body: Value = serde_json::from_slice(&response.body.bytes()?)?;
    assert_eq!(
        body,
        json!({"token":42,"success":true,"user":{"id":"1","walletAddress":ADDRESS,"chainId":1}})
    );
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert_eq!(
        request.new_session()?.unwrap().user_field("name"),
        &FieldValue::from("selected-1")
    );
    assert_eq!(*verified.lock().unwrap(), [1.0]);
    assert!(
        ctx.database
            .get_verification_by_identifier(&format!("siwe:{NONCE}"))
            .await?
            .is_none()
    );
    assert!(
        request
            .take_response_headers()?
            .get_all("set-cookie")
            .any(|cookie| cookie.starts_with("better-auth.session_token=42."))
    );
    Ok(())
}

#[tokio::test]
async fn large_chain_numbers_persist_before_cancelled_session_without_consuming_wallet_output()
-> AuthResult<()> {
    let (plugin, ctx, reads, verified) = fixture(true).await?;
    let chain = 1e30;
    let request = request(&ctx, "1e30").await?;
    let error = plugin.verify(&request, &ctx).await.unwrap_err();
    assert!(error.is_api_error());
    assert_eq!(error.status_code(), 500);
    let response = error.to_auth_response();
    assert_eq!(response.status, 500);
    let body: Value = serde_json::from_slice(&response.body.bytes()?)?;
    assert_eq!(
        body,
        json!({"message":"Internal Server Error","status":500})
    );
    assert_eq!(*verified.lock().unwrap(), [chain]);
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert!(
        ctx.database
            .get_wallet_address_value(&ADDRESS.into(), Some(&chain.into()))
            .await?
            .is_some()
    );
    let accounts = ctx.database.get_user_accounts("1").await?;
    assert_eq!(accounts.len(), 1);
    assert_eq!(
        accounts[0].account_id.field_value(),
        format!("{ADDRESS}:1e+30").into()
    );
    assert!(request.new_session()?.is_none());
    assert!(request.take_response_headers()?.is_empty());
    assert!(
        ctx.database
            .get_verification_by_identifier(&format!("siwe:{NONCE}"))
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn native_and_http_siwe_errors_preserve_api_errors_and_nonce_consumption() -> AuthResult<()> {
    use better_auth_core::endpoint_dispatch::EndpointDispatcher;
    for mode in [
        "invalid-nonce",
        "missing-nonce",
        "invalid-signature",
        "api-error",
        "runtime-error",
    ] {
        for http in [false, true] {
            let (mut plugin, ctx, reads, verified) = fixture(false).await?;
            let calls = verified.clone();
            plugin.get_nonce = Arc::new(|| Box::pin(async { Ok("short".into()) }));
            plugin.verify_message = Arc::new(move |input| {
                calls.lock().unwrap().push(input.chain_id);
                Box::pin(async move {
                    match mode {
                        "api-error" => Err(AuthResponse::json(
                            403,
                            &json!({"code":"VERIFIER_REJECTED", "message":"verifier rejected"}),
                        )?
                        .into()),
                        "runtime-error" => Err(AuthError::internal("verifier failed")),
                        _ => Ok(false),
                    }
                })
            });
            let mut req = if mode == "invalid-nonce" {
                AuthRequest::new(HttpMethod::Post, "/siwe/nonce")
            } else {
                let req = request(&ctx, "1").await?;
                if mode == "missing-nonce" {
                    ctx.database
                        .delete_verification_by_identifier(&format!("siwe:{NONCE}"))
                        .await?;
                }
                req.clone().with_original_request(req)
            };
            let (status, expected) = match mode {
                "invalid-nonce" => (
                    500,
                    json!({"message":"SIWE getNonce must return an ERC-4361 nonce: 8-250 alphanumeric characters.","status":500,"code":"SIWE_INVALID_NONCE"}),
                ),
                "missing-nonce" => (
                    401,
                    json!({"message":"Unauthorized: Invalid or expired nonce","status":401,"code":"UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE"}),
                ),
                "invalid-signature" => (
                    401,
                    json!({"message":"Unauthorized: Invalid SIWE signature","status":401}),
                ),
                "api-error" => (
                    403,
                    json!({"code":"VERIFIER_REJECTED","message":"verifier rejected"}),
                ),
                _ => (
                    401,
                    json!({"message":"Something went wrong. Please try again later.","error":"verifier failed","status":401}),
                ),
            };
            let routes = AuthPlugin::<StatelessSchema>::routes(&plugin);
            let route = routes
                .iter()
                .find(|route| route.path == req.path())
                .unwrap()
                .clone();
            let dispatcher =
                EndpointDispatcher::new(Arc::new(Vec::new()), Default::default(), routes);
            let handler = |req: AuthRequest| {
                let plugin = &plugin;
                let ctx = &ctx;
                async move {
                    plugin
                        .on_request(&req, ctx)
                        .await?
                        .ok_or_else(|| AuthError::not_found("SIWE endpoint"))
                }
            };
            let response = if http {
                dispatcher
                    .run(&mut req, true, &ctx, None, handler)
                    .await?
                    .into_http_response()?
            } else {
                let error = dispatcher
                    .native(req.clone(), route, &ctx, handler)
                    .await
                    .unwrap_err();
                assert!(error.is_api_error(), "{mode}");
                assert_eq!(error.status_code(), status, "{mode}");
                error.to_auth_response()
            };
            assert_eq!(response.status, status, "{mode} HTTP={http}");
            assert_eq!(response.body.json()?, Some(expected), "{mode} HTTP={http}");
            assert_eq!(
                response.headers.get("content-type").map(String::as_str),
                http.then_some("application/json")
            );
            assert_eq!(response.headers.iter().count(), usize::from(http));
            assert_eq!(
                *verified.lock().unwrap(),
                if matches!(mode, "invalid-nonce" | "missing-nonce") {
                    vec![]
                } else {
                    vec![1.0]
                }
            );
            assert_eq!(reads.load(Ordering::SeqCst), 0);
            assert!(req.new_session()?.is_none());
            assert!(req.take_response_headers()?.is_empty());
            assert!(
                ctx.database
                    .get_verification_by_identifier(&format!("siwe:{NONCE}"))
                    .await?
                    .is_none()
            );
            assert!(ctx.database.get_user_by_id("1").await?.is_none());
            assert!(ctx.database.get_user_accounts("1").await?.is_empty());
            assert!(ctx.database.get_user_sessions("1").await?.is_empty());
            assert!(
                ctx.database
                    .get_wallet_address_value(&ADDRESS.into(), Some(&1.0.into()))
                    .await?
                    .is_none()
            );
        }
    }
    Ok(())
}
