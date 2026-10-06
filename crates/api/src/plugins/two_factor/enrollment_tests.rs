use super::*;
use crate::plugins::test_helpers;
use better_auth_core::HttpMethod;
use better_auth_core::wire::SessionView;
use better_auth_seaorm::sea_orm::{ActiveModelTrait, ConnectionTrait, Schema, Set};
use better_auth_seaorm::store::__private_test_support::{bundled_schema::BundledSchema, migrator};
use better_auth_seaorm::{Database, SeaOrmStore};
use serde_json::json;

mod factor {
    use better_auth_seaorm::AuthEntity;
    use better_auth_seaorm::sea_orm;
    use better_auth_seaorm::sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, DeriveEntityModel, AuthEntity)]
    #[auth(role = "two_factor", native_two_factor)]
    #[sea_orm(table_name = "native_two_factor")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub secret: String,
        pub backup_codes: String,
        pub user_id: String,
        pub verified: Option<bool>,
        pub failed_verification_count: Option<i64>,
        pub locked_until: Option<DateTimeUtc>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

type Models = better_auth_seaorm::PluginModels<
    better_auth_seaorm::store::entities::api_key::Model,
    better_auth_seaorm::store::entities::device_code::Model,
    better_auth_seaorm::store::entities::passkey::Model,
    factor::Model,
>;

struct RejectEnrollment;

#[better_auth_core::database_hooks()]
impl better_auth_seaorm::SeaOrmHooks<BundledSchema> for RejectEnrollment {
    async fn before_update_user(
        &self,
        _id: &str,
        update: &UpdateUser,
        _ctx: &better_auth_seaorm::SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<better_auth_seaorm::DatabaseHookUpdate<UpdateUser>> {
        if update.two_factor_enabled == Some(true) {
            return Err(AuthError::internal("Enrollment user update rejected"));
        }
        Ok(better_auth_seaorm::DatabaseHookUpdate::Continue)
    }
}

struct Fixture {
    ctx: AuthContext<BundledSchema>,
    user: UserView,
    session: SessionView,
}

impl Fixture {
    async fn new(verified: Option<bool>, reject_enrollment: bool) -> Self {
        let connection = Database::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&connection).await.unwrap();
        connection
            .execute(
                &Schema::new(connection.get_database_backend())
                    .create_table_from_entity(factor::Entity),
            )
            .await
            .unwrap();
        let config = Arc::new(test_helpers::create_test_config());
        let mut store = SeaOrmStore::<BundledSchema>::new(config.clone(), connection.clone())
            .with_plugin_schema::<Models>();
        if reject_enrollment {
            store = store.hook(RejectEnrollment);
        }
        let mut ctx = AuthContext::new(config, Arc::new(store));
        ctx.set_metadata(METADATA_ENABLED, json!(true));
        let ctx = ctx
            .initialize_request_context()
            .await
            .unwrap()
            .as_ref()
            .clone();
        let (user, session) = test_helpers::create_user_and_session(
            &ctx,
            better_auth_core::CreateUser::new()
                .with_email("native-factor@example.test")
                .with_name("Native Factor"),
            Duration::hours(1),
        )
        .await;
        factor::ActiveModel {
            id: Set("native-factor".into()),
            secret: Set(encrypt_value(
                ctx.config.encryption_secret(),
                "ordinary-factor-secret-for-totp",
            )
            .unwrap()),
            backup_codes: Set(encrypt_value(
                ctx.config.encryption_secret(),
                "[\"ordinary-backup-code\"]",
            )
            .unwrap()),
            user_id: Set(user.id.typed().unwrap().clone()),
            verified: Set(verified),
            failed_verification_count: Set(Some(0)),
            locked_until: Set(None),
        }
        .insert(&connection)
        .await
        .unwrap();
        Self { ctx, user, session }
    }

    async fn record(&self) -> TwoFactor {
        self.ctx
            .database
            .get_two_factor_by_user_id(self.user.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap()
    }

    async fn code(&self) -> String {
        let row = self.record().await;
        let secret = decrypt_value(self.ctx.config.encryption_secret(), &row.secret).unwrap();
        build_totp(
            &TwoFactorConfig::default(),
            &secret,
            None,
            &self.user,
            &self.ctx,
        )
        .unwrap()
        .generate_current()
        .unwrap()
    }

    fn request(&self, path: &str, body: serde_json::Value) -> AuthRequest {
        test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            path,
            Some(&self.session.token),
            Some(serde_json::to_vec(&body).unwrap()),
        )
    }
}

#[tokio::test]
async fn native_verified_states_control_setup_and_sign_in_methods() {
    let plugin = TwoFactorPlugin {
        config: TwoFactorConfig {
            allow_passwordless: true,
            ..Default::default()
        },
    };
    for verified in [None, Some(false), Some(true)] {
        let fixture = Fixture::new(verified, false).await;
        let original = fixture.record().await;
        let challenge =
            begin_sign_in_challenge(&fixture.user, &fixture.ctx, &mut Default::default())
                .await
                .unwrap();
        assert_eq!(
            challenge.two_factor_methods,
            if verified == Some(false) {
                vec![]
            } else {
                vec!["totp"]
            }
        );
        let result = plugin
            .handle_enable(
                &fixture.request("/two-factor/enable", json!({})),
                &fixture.ctx,
            )
            .await;
        let stored = fixture.record().await;
        if verified == Some(false) {
            assert_eq!(result.unwrap().status, 200);
            assert_eq!(stored.id, original.id);
            assert_eq!(stored.verified, Some(false));
            assert_ne!(stored.secret, original.secret);
            assert_ne!(stored.backup_codes, original.backup_codes);
        } else {
            assert_eq!(
                result.unwrap_err().error_payload().1.as_deref(),
                Some("TOTP_ALREADY_ENABLED")
            );
            assert_eq!(stored, original);
        }
    }
}

#[tokio::test]
async fn native_totp_completion_rotates_sessions_only_for_incomplete_enrollment() {
    let plugin = TwoFactorPlugin::new();
    for verified in [None, Some(false), Some(true)] {
        let fixture = Fixture::new(verified, false).await;
        let original = fixture.record().await;
        let request = fixture.request(
            "/two-factor/verify-totp",
            json!({"code": fixture.code().await}),
        );
        let response = plugin
            .handle_verify_totp(&request, &fixture.ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["token"], fixture.session.token);
        assert_eq!(body["user"]["twoFactorEnabled"], false);
        let stored = fixture.record().await;
        assert_eq!(stored.verified, Some(true));
        assert_eq!(stored.id, original.id);
        assert_eq!(stored.secret, original.secret);
        assert_eq!(stored.backup_codes, original.backup_codes);
        assert!(stored.created_at.is_undefined());
        assert!(stored.updated_at.is_undefined());
        let user = fixture
            .ctx
            .database
            .get_user_by_id(fixture.user.id.typed().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(user.two_factor_enabled(), verified != Some(true));
        assert_eq!(
            fixture
                .ctx
                .database
                .get_session(&fixture.session.token)
                .await
                .unwrap()
                .is_some(),
            verified == Some(true)
        );
        assert_eq!(
            request
                .take_response_headers()
                .unwrap()
                .get_all("set-cookie")
                .count(),
            usize::from(verified != Some(true))
        );
    }
}

#[tokio::test]
async fn native_pending_totp_accepts_null_but_rejects_explicit_false() {
    let plugin = TwoFactorPlugin::new();
    for verified in [None, Some(false), Some(true)] {
        let fixture = Fixture::new(verified, false).await;
        let user = fixture
            .ctx
            .database
            .update_user(
                fixture.user.id.typed().unwrap(),
                UpdateUser {
                    two_factor_enabled: Some(true),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let mut headers = better_auth_core::Headers::new();
        let _ = begin_sign_in_challenge(&user, &fixture.ctx, &mut headers)
            .await
            .unwrap();
        let mut request = AuthRequest::new(HttpMethod::Post, "/two-factor/verify-totp");
        request.headers.insert(
            "cookie".into(),
            headers
                .get_all("set-cookie")
                .next()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .into(),
        );
        request.body = Some(serde_json::to_vec(&json!({"code": fixture.code().await})).unwrap());
        let identifier = read_signed_cookie(&request, TWO_FACTOR_COOKIE_SUFFIX, &fixture.ctx)
            .unwrap()
            .unwrap();
        let result = plugin.handle_verify_totp(&request, &fixture.ctx).await;
        if verified == Some(false) {
            assert_eq!(result.unwrap_err().to_string(), "TOTP not enabled");
            assert_eq!(fixture.record().await.verified, Some(false));
            assert!(
                fixture
                    .ctx
                    .database
                    .get_verification_by_identifier(&identifier)
                    .await
                    .unwrap()
                    .is_some()
            );
        } else {
            let response = result.unwrap();
            assert_eq!(response.status, 200);
            let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(body["user"]["twoFactorEnabled"], true);
            assert_ne!(body["token"], fixture.session.token);
            assert_eq!(fixture.record().await.verified, Some(true));
            assert!(
                fixture
                    .ctx
                    .database
                    .get_verification_by_identifier(&identifier)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }
}

#[tokio::test]
async fn enrollment_failure_preserves_unverified_factor_and_original_session() {
    let plugin = TwoFactorPlugin::new();
    for verified in [None, Some(false)] {
        let fixture = Fixture::new(verified, true).await;
        let original = fixture.record().await;
        let request = fixture.request(
            "/two-factor/verify-totp",
            json!({"code": fixture.code().await}),
        );
        let error = plugin
            .handle_verify_totp(&request, &fixture.ctx)
            .await
            .unwrap_err();
        assert!(
            matches!(error, AuthError::Internal(message) if message == "Enrollment user update rejected")
        );
        assert_eq!(fixture.record().await, original);
        assert!(
            fixture
                .ctx
                .database
                .get_session(&fixture.session.token)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            request
                .take_response_headers()
                .unwrap()
                .get_all("set-cookie")
                .count(),
            0
        );
    }
}
