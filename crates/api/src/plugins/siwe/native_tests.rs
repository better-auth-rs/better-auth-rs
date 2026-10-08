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
        json!({"token":42.0,"success":true,"user":{"id":"1","walletAddress":ADDRESS,"chainId":1.0}})
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
    let response = plugin.verify(&request, &ctx).await?;
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
