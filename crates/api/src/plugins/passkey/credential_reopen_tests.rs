use super::{Authenticator, CREDENTIAL_ID, ORIGIN, RP_ID, STANDARD, TRANSPORTS, TestResult};
use crate::plugins::{passkey::PasskeyPlugin, test_helpers};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, CreateUser, HttpMethod, Passkey,
    PasskeyStorage,
};
use better_auth_seaorm::{
    Database, DatabaseConnection, SeaOrmStore,
    sea_orm::{ConnectionTrait, Schema},
    store::{
        __private_test_support::{bundled_schema::BundledSchema, migrator},
        entities::{api_key, device_code},
    },
};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc};

mod native {
    use better_auth_seaorm::{
        AuthEntity,
        sea_orm::{self, entity::prelude::*},
        store::entities::user,
    };

    #[derive(Clone, Debug, DeriveEntityModel, AuthEntity)]
    #[auth(role = "passkey", native_passkey)]
    #[sea_orm(table_name = "native_passkey_reopen")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: Option<String>,
        #[sea_orm(column_name = "publicKey")]
        pub public_key: String,
        #[sea_orm(column_name = "userId")]
        pub user_id: String,
        #[sea_orm(column_name = "credentialID")]
        pub credential_id: String,
        pub counter: i64,
        #[sea_orm(column_name = "deviceType")]
        pub device_type: String,
        #[sea_orm(column_name = "backedUp")]
        pub backed_up: bool,
        pub transports: Option<String>,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: Option<DateTimeUtc>,
        pub aaguid: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "user::Entity",
            from = "Column::UserId",
            to = "user::Column::Id",
            on_delete = "Cascade"
        )]
        User,
    }

    impl ActiveModelBehavior for ActiveModel {}
}

type Models = better_auth_seaorm::PluginModels<api_key::Model, device_code::Model, native::Model>;

struct Fixture {
    ctx: AuthContext<BundledSchema>,
    database: DatabaseConnection,
}

impl Fixture {
    async fn open(path: &Path) -> TestResult<Self> {
        let database = Database::connect(format!("sqlite://{}?mode=rw", path.display())).await?;
        let mut config = test_helpers::create_test_config().base_url(ORIGIN);
        config.telemetry.enabled = false;
        let config = Arc::new(config);
        let store = SeaOrmStore::<BundledSchema>::new(config.clone(), database.clone())
            .with_plugin_schema::<Models>();
        let ctx = AuthContext::new(config, Arc::new(store));
        assert_eq!(ctx.database.passkey_storage(), PasskeyStorage::Native);
        Ok(Self { ctx, database })
    }

    async fn create(path: &Path) -> TestResult<Self> {
        let fixture = Self::open(path).await?;
        migrator::run_migrations(&fixture.database).await?;
        fixture
            .database
            .execute_unprepared("DROP TABLE passkeys")
            .await?;
        fixture
            .database
            .execute(
                &Schema::new(fixture.database.get_database_backend())
                    .create_table_from_entity(native::Entity),
            )
            .await?;
        Ok(fixture)
    }

    async fn close(self) -> TestResult {
        let Self { ctx, database } = self;
        drop(ctx);
        database.close().await?;
        Ok(())
    }

    async fn route(&self, request: &AuthRequest) -> AuthResult<AuthResponse> {
        let ctx = self.ctx.initialize_request_context().await?;
        let plugin = PasskeyPlugin::new()
            .rp_id(RP_ID)
            .rp_name("Passkey reopen")
            .origin(ORIGIN);
        let response = match request.path.as_str() {
            "/passkey/generate-register-options" => {
                plugin
                    .handle_generate_register_options(request, &ctx)
                    .await?
            }
            "/passkey/verify-registration" => {
                plugin.handle_verify_registration(request, &ctx).await?
            }
            "/passkey/generate-authenticate-options" => {
                plugin
                    .handle_generate_authenticate_options(request, &ctx)
                    .await?
            }
            "/passkey/verify-authentication" => {
                plugin.handle_verify_authentication(request, &ctx).await?
            }
            "/passkey/update-passkey" => plugin.handle_update_passkey(request, &ctx).await?,
            "/passkey/delete-passkey" => plugin.handle_delete_passkey(request, &ctx).await?,
            _ => return Err(AuthError::internal("Unknown Passkey fixture route")),
        };
        Ok(test_helpers::finalize_response(&ctx, request, response))
    }

    async fn stored(&self) -> TestResult<Passkey> {
        Ok(self
            .ctx
            .database
            .get_passkey_by_credential_id(&URL_SAFE_NO_PAD.encode(CREDENTIAL_ID))
            .await?
            .ok_or("Persisted Native credential is missing")?)
    }
}

fn request(
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
    cookie: Option<&str>,
) -> AuthRequest {
    let method = if body.is_some() {
        HttpMethod::Post
    } else {
        HttpMethod::Get
    };
    let mut request = test_helpers::create_auth_json_request_no_query(method, path, token, body);
    let _ = request.headers.insert("origin".into(), ORIGIN.into());
    if let Some(cookie) = cookie {
        let _ = request.headers.insert("cookie".into(), cookie.into());
    }
    request
}

fn options(response: AuthResponse) -> TestResult<(Value, String)> {
    assert_eq!(response.status, 200);
    let cookie = response
        .headers
        .get("Set-Cookie")
        .and_then(|header| header.split(';').next())
        .ok_or("Passkey options must set the challenge cookie")?
        .to_owned();
    Ok((serde_json::from_slice(&response.body.bytes()?)?, cookie))
}

fn challenge(options: &Value) -> TestResult<Vec<u8>> {
    Ok(URL_SAFE_NO_PAD.decode(
        options
            .get("challenge")
            .and_then(Value::as_str)
            .ok_or("Missing challenge")?,
    )?)
}

fn assert_error(response: AuthResponse, code: &str) -> TestResult {
    assert_eq!(response.status, 400);
    let body: Value = serde_json::from_slice(&response.body.bytes()?)?;
    assert_eq!(body.get("code").and_then(Value::as_str), Some(code));
    Ok(())
}

fn assert_login(response: AuthResponse, owner: &str) -> TestResult {
    assert_eq!(response.status, 200);
    let body: Value = serde_json::from_slice(&response.body.bytes()?)?;
    assert_eq!(body["user"]["id"], owner);
    assert_eq!(body["session"]["userId"], owner);
    Ok(())
}

#[tokio::test]
async fn native_sqlite_credential_authenticates_after_reopen() -> TestResult {
    let path = std::env::temp_dir().join(format!(
        "better-auth-passkey-reopen-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    drop(std::fs::File::create_new(&path)?);
    let fixture = Fixture::create(&path).await?;
    let (owner, session) = test_helpers::create_user_and_session(
        &fixture.ctx,
        CreateUser::new()
            .with_name("Owner")
            .with_email("owner@passkey.example"),
        chrono::Duration::hours(1),
    )
    .await;
    let (_, other_session) = test_helpers::create_user_and_session(
        &fixture.ctx,
        CreateUser::new()
            .with_name("Other")
            .with_email("other@passkey.example"),
        chrono::Duration::hours(1),
    )
    .await;
    let authenticator = Authenticator::new()?;
    let (registration, cookie) = options(
        fixture
            .route(&request(
                "/passkey/generate-register-options",
                Some(&session.token),
                None,
                None,
            ))
            .await?,
    )?;
    let user_handle = URL_SAFE_NO_PAD.decode(
        registration["user"]["id"]
            .as_str()
            .ok_or("Missing registration user handle")?,
    )?;
    let response = authenticator.register(&challenge(&registration)?, Some(TRANSPORTS))?;
    let registered = fixture
        .route(&request(
            "/passkey/verify-registration",
            Some(&session.token),
            Some(json!({"response":response,"name":"Persisted authenticator"})),
            Some(&cookie),
        ))
        .await?;
    assert_eq!(registered.status, 200);
    let initial = fixture.stored().await?;
    assert_eq!(initial.user_id, *owner.id.typed()?);
    assert_eq!(initial.counter, 0);
    assert_eq!(STANDARD.decode(&initial.public_key)?, authenticator.cose);
    assert!(initial.credential.is_undefined());
    assert!(initial.updated_at.is_undefined());

    let (pending, cookie) = options(
        fixture
            .route(&request(
                "/passkey/generate-authenticate-options",
                None,
                None,
                None,
            ))
            .await?,
    )?;
    fixture.close().await?;

    let fixture = Fixture::open(&path).await?;
    assert_eq!(fixture.stored().await?, initial);
    let signed = authenticator.authenticate(&challenge(&pending)?, 1, &user_handle)?;
    let signed_body = json!({"response":signed});
    assert_login(
        fixture
            .route(&request(
                "/passkey/verify-authentication",
                None,
                Some(signed_body.clone()),
                Some(&cookie),
            ))
            .await?,
        owner.id.typed()?,
    )?;
    let mut advanced = initial;
    advanced.counter = 1;
    assert_eq!(fixture.stored().await?, advanced);
    for (path, body, message) in [
        (
            "/passkey/update-passkey",
            json!({"id":advanced.id,"name":"Hijacked"}),
            "You are not allowed to register this passkey",
        ),
        (
            "/passkey/delete-passkey",
            json!({"id":advanced.id}),
            "Unauthorized",
        ),
    ] {
        let result = fixture
            .route(&request(path, Some(&other_session.token), Some(body), None))
            .await;
        let error = match result {
            Err(error) => error,
            Ok(_) => return Err("A different owner changed the persisted credential".into()),
        };
        assert_eq!(error.status_code(), 403);
        assert_eq!(error.to_string(), message);
        assert_eq!(fixture.stored().await?, advanced);
    }
    fixture.close().await?;

    let fixture = Fixture::open(&path).await?;
    assert_eq!(fixture.stored().await?, advanced);
    assert_error(
        fixture
            .route(&request(
                "/passkey/verify-authentication",
                None,
                Some(signed_body),
                Some(&cookie),
            ))
            .await?,
        "CHALLENGE_NOT_FOUND",
    )?;
    for counter in [1, 2] {
        let (options, cookie) = options(
            fixture
                .route(&request(
                    "/passkey/generate-authenticate-options",
                    None,
                    None,
                    None,
                ))
                .await?,
        )?;
        let response = authenticator.authenticate(&challenge(&options)?, counter, &user_handle)?;
        let login = fixture
            .route(&request(
                "/passkey/verify-authentication",
                None,
                Some(json!({"response":response})),
                Some(&cookie),
            ))
            .await?;
        if counter == 1 {
            assert_error(login, "AUTHENTICATION_FAILED")?;
        } else {
            assert_login(login, owner.id.typed()?)?;
            advanced.counter = 2;
        }
        assert_eq!(fixture.stored().await?, advanced);
    }
    fixture.close().await?;

    let fixture = Fixture::open(&path).await?;
    assert_eq!(fixture.stored().await?, advanced);
    fixture.close().await?;
    std::fs::remove_file(path)?;
    Ok(())
}
