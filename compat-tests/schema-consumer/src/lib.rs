#[cfg(test)]
#[path = "../../../tests/support/ordinary_field_policies.rs"]
mod ordinary_field_policies;

#[cfg(test)]
mod tests {
    mod account_verification;
    mod api_key_additional_fields;
    mod device_additional_fields;
    mod device_intervals;
    mod dynamic_fields;
    mod field_attributes;
    mod ids;
    mod jwk_additional_fields;
    mod model_declarations;
    mod organization;
    mod passkey_additional_fields;
    mod plugins;
    mod rate_limit_declarations;
    mod rate_limits;
    mod reference_fields;
    mod sqlite_json;
    mod two_factor_additional_fields;
    mod wallet_additional_fields;

    use std::sync::Arc;

    use axum::{
        Json, Router,
        body::Body,
        http::{Request, StatusCode},
        routing::get,
    };
    use better_auth::integrations::axum::{AxumIntegration, CurrentSession};
    use better_auth::plugins::{
        ApiKeyPlugin, EmailPasswordPlugin, SessionManagementPlugin, TwoFactorPlugin,
    };
    use better_auth::seaorm::sea_orm::ConnectionTrait;
    use better_auth::seaorm::{Database, SeaOrmStore};
    use better_auth::{AuthConfig, BetterAuth};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    mod generated {
        include!(env!("BETTER_AUTH_GENERATED_SCHEMA"));
    }

    async fn protected(session: CurrentSession<generated::AppAuthSchema>) -> Json<Value> {
        Json(json!({"userId": session.user.id}))
    }

    async fn request(
        router: &Router,
        path: &str,
        body: Option<Value>,
        token: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder().uri(path);
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        let request = if let Some(body) = body {
            request
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        } else {
            request.body(Body::empty()).unwrap()
        };
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let body = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
            panic!("{path} returned {status} with invalid JSON: {error}; body={bytes:?}")
        });
        (status, body)
    }

    #[tokio::test]
    async fn generated_schema_supports_authentication_and_two_factor() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        generated::create_auth_tables(&database).await.unwrap();
        assert!(
            generated::create_auth_tables(&database).await.is_err(),
            "the initial scaffold must not silently accept an existing schema"
        );
        let mut config = AuthConfig::new("consumer-test-secret-at-least-32-characters")
            .base_url("http://localhost:3000");
        config.session.bearer = Some(Default::default());
        let auth = Arc::new(
            BetterAuth::<generated::AppAuthSchema>::new(config.clone())
                .store(
                    SeaOrmStore::<generated::AppAuthSchema>::new(config, database.clone())
                        .with_organization_schema::<generated::AppOrganizationSchema>()
                        .with_plugin_schema::<generated::AppPluginSchema>(),
                )
                .plugin(EmailPasswordPlugin::new().enable_signup(true))
                .plugin(SessionManagementPlugin::new())
                .plugin(TwoFactorPlugin::new())
                .plugin(ApiKeyPlugin::builder().build())
                .build()
                .await
                .unwrap(),
        );
        let router = Router::new()
            .nest("/auth", auth.clone().axum_router())
            .route("/protected", get(protected))
            .with_state(auth);
        assert_eq!(
            request(&router, "/protected", None, None).await.0,
            StatusCode::UNAUTHORIZED
        );
        let credentials = json!({"email": "consumer@example.com", "password": "test-password-123", "name": "Consumer"});
        let (status, signup) = request(
            &router,
            "/auth/sign-up/email",
            Some(credentials.clone()),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{signup}");
        let (status, signin) = request(
            &router,
            "/auth/sign-in/email",
            Some(credentials.clone()),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{signin}");
        let token = signin["token"].as_str().unwrap();
        let (status, protected) = request(&router, "/protected", None, Some(token)).await;
        assert_eq!(status, StatusCode::OK, "{protected}");
        assert_eq!(protected["userId"], signup["user"]["id"]);

        let (status, api_key) = request(
            &router,
            "/auth/api-key/create",
            Some(json!({"name": "consumer key"})),
            Some(token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{api_key}");
        assert_eq!(api_key["referenceId"], signup["user"]["id"]);
        assert_eq!(api_key["configId"], "default");

        let (status, enabled) = request(
            &router,
            "/auth/two-factor/enable",
            Some(json!({"password": "test-password-123", "method": "totp"})),
            Some(token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{enabled}");
        let totp = totp_rs::TOTP::from_url(enabled["totpURI"].as_str().unwrap()).unwrap();
        let (status, verified) = request(
            &router,
            "/auth/two-factor/verify-totp",
            Some(json!({"code": totp.generate_current().unwrap()})),
            Some(token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{verified}");
        let (status, challenge) =
            request(&router, "/auth/sign-in/email", Some(credentials), None).await;
        assert_eq!(status, StatusCode::OK, "{challenge}");
        assert_eq!(challenge["twoFactorRedirect"], true, "{challenge}");
        assert!(challenge.get("token").is_none());

        // The database must enforce invariants when concurrent requests bypass prechecks.
        for (statement, expected) in [
            (
                "INSERT INTO user (id, name, email, emailVerified, image, createdAt, updatedAt, role, banned, ban_reason, ban_expires, metadata, two_factor_enabled, username, display_username) SELECT 'duplicate', name, email, emailVerified, image, createdAt, updatedAt, role, banned, ban_reason, ban_expires, metadata, two_factor_enabled, username, display_username FROM user LIMIT 1",
                "UNIQUE constraint failed: user.email",
            ),
            (
                "UPDATE session SET userId = 'missing-user'",
                "FOREIGN KEY constraint failed",
            ),
            (
                "INSERT INTO two_factor SELECT 'duplicate', secret, backup_codes, user_id, verified, failed_verification_count, locked_until, created_at, updated_at FROM two_factor LIMIT 1",
                "UNIQUE constraint failed: two_factor.user_id",
            ),
        ] {
            let error = database.execute_unprepared(statement).await.unwrap_err();
            assert!(
                error.to_string().contains(expected),
                "unexpected constraint error: {error}"
            );
        }
        database.execute_unprepared("INSERT INTO account SELECT 'duplicate', accountId, providerId, userId, accessToken, refreshToken, idToken, accessTokenExpiresAt, refreshTokenExpiresAt, scope, password, createdAt, updatedAt FROM account LIMIT 1").await.unwrap();
        let store =
            SeaOrmStore::<generated::AppAuthSchema>::new(AuthConfig::default(), database.clone());
        let store: &dyn better_auth::store::AuthStore<generated::AppAuthSchema> = &store;
        let error = store
            .get_account("credential", signup["user"]["id"].as_str().unwrap())
            .await
            .unwrap_err();
        assert_eq!(
            error.instrumentation_message(),
            "Multiple accounts match the same accountId for provider \"credential\". Resolve duplicate account identities before continuing."
        );
        database.close().await.unwrap();
    }
}
