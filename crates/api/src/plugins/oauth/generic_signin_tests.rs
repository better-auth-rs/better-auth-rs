use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthUser,
    HttpMethod, UpdateUser, wire::UserView,
};
use serde_json::{Value, json};

use super::{
    GenericOAuthConfig, GenericOAuthUserInfoHandler, OAuthCodeExchange, OAuthPlugin,
    OAuthTokenHandler, OAuthTokenSet, OAuthUserInfoRequest,
};
use crate::plugins::{
    email_verification::{EmailVerificationConfig, EmailVerificationPlugin, SendVerificationEmail},
    test_helpers,
};

struct Provider;

#[async_trait]
impl OAuthTokenHandler for Provider {
    async fn get_token(&self, _: OAuthCodeExchange<'_>) -> AuthResult<OAuthTokenSet> {
        Ok(OAuthTokenSet::default())
    }
}

#[async_trait]
impl GenericOAuthUserInfoHandler for Provider {
    async fn get_user_info(&self, _: &OAuthUserInfoRequest) -> AuthResult<Option<Value>> {
        Ok(Some(
            json!({ "id": "stable-subject", "email": "unverified@example.com", "emailVerified": false }),
        ))
    }
}

#[derive(Default)]
struct Mailbox {
    urls: Mutex<Vec<String>>,
    fail: bool,
}

#[async_trait]
impl SendVerificationEmail for Mailbox {
    async fn send(
        &self,
        user: &better_auth_core::FieldValue,
        url: &str,
        _: &str,
    ) -> AuthResult<()> {
        assert_eq!(
            user.as_object()
                .unwrap()
                .get("email")
                .and_then(better_auth_core::FieldValue::as_str),
            Some("unverified@example.com")
        );
        self.urls.lock().unwrap().push(url.to_owned());
        if self.fail {
            return Err(AuthError::internal("test sender rejected the message"));
        }
        Ok(())
    }
}

async fn sign_in(
    plugin: &OAuthPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResponse {
    sign_in_with_provider(plugin, ctx, "generic").await
}

async fn sign_in_with_provider(
    plugin: &OAuthPlugin,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    provider: &str,
) -> AuthResponse {
    let mut request = AuthRequest::new(HttpMethod::Post, "/sign-in/social");
    request.body = Some(
        serde_json::to_vec(&json!({
            "provider": provider,
            "callbackURL": "http://localhost:3000/welcome",
            "errorCallbackURL": "http://localhost:3000/error",
            "disableRedirect": true
        }))
        .unwrap(),
    );
    let _ = request
        .headers
        .insert("content-type".to_owned(), "application/json".to_owned());
    let response = plugin.on_request(&request, ctx).await.unwrap().unwrap();
    let body: Value = serde_json::from_slice(&response.body.bytes().unwrap()).unwrap();
    let url = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
    let state = url
        .query_pairs()
        .find(|(name, _)| name == "state")
        .unwrap()
        .1
        .into_owned();
    let mut callback = AuthRequest::new(HttpMethod::Get, format!("/callback/{provider}"));
    let _ = callback
        .query
        .get_or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .unwrap()
        .insert("state".to_owned(), serde_json::Value::from(state));
    let _ = callback
        .query
        .get_or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .unwrap()
        .insert(
            "code".to_owned(),
            serde_json::Value::from("test-code".to_owned()),
        );
    let mut response = plugin.on_request(&callback, ctx).await.unwrap().unwrap();
    ctx.session_manager()
        .finish_response(&callback, &mut response)
        .unwrap();
    response
}

#[tokio::test]
async fn verification_policy_persists_identity_before_denial_and_sends_only_when_configured() {
    for (send_on_sign_up, send_on_sign_in, fail_sender, first_count, second_count) in [
        (None, false, false, 1, 1),
        (Some(false), true, false, 0, 1),
        (Some(true), true, true, 1, 2),
    ] {
        let mut config = test_helpers::create_test_config().base_url("http://localhost:3000");
        config.account.skip_state_cookie_check = true;
        let ctx = test_helpers::create_test_context_with_config(config).await;
        let mailbox = Arc::new(Mailbox {
            fail: fail_sender,
            ..Default::default()
        });
        let verification = EmailVerificationConfig {
            send_on_sign_up,
            send_on_sign_in,
            send_verification_email: Some(mailbox.clone()),
            ..Default::default()
        };
        let plugin = OAuthPlugin::new()
            .with_email_verification(Arc::new(EmailVerificationPlugin::with_config(verification)))
            .add_generic_provider(
                "generic",
                GenericOAuthConfig {
                    client_id: "client".to_owned(),
                    authorization_url: Some("https://provider.example/authorize".to_owned()),
                    get_token: Some(Arc::new(Provider)),
                    get_user_info: Some(Arc::new(Provider)),
                    require_email_verification: true,
                    ..Default::default()
                },
            );
        for count in [first_count, second_count] {
            let response = sign_in(&plugin, &ctx).await;
            assert_eq!(response.status, 302);
            assert_eq!(
                response.headers.get("Location").map(String::as_str),
                Some("http://localhost:3000/error?error=email_not_verified")
            );
            assert_eq!(mailbox.urls.lock().unwrap().len(), count);
            let user = ctx
                .database
                .get_user_by_email("unverified@example.com")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                ctx.database
                    .get_user_accounts(user.id().typed().unwrap())
                    .await
                    .unwrap()
                    .len(),
                1
            );
            assert!(
                ctx.session_manager()
                    .list_user_sessions(user.id().typed().unwrap())
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
        for sent_url in mailbox.urls.lock().unwrap().iter() {
            let url = url::Url::parse(sent_url).unwrap();
            assert!(
                url.query_pairs().any(|(name, value)| name == "callbackURL"
                    && value == "http://localhost:3000/welcome")
            );
            assert!(
                url.query_pairs()
                    .any(|(name, value)| name == "token" && !value.is_empty())
            );
        }
        let user = ctx
            .database
            .get_user_by_email("unverified@example.com")
            .await
            .unwrap()
            .unwrap();
        let _ = ctx
            .database
            .update_user(
                user.id().typed().unwrap(),
                UpdateUser {
                    email_verified: Some(true),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let response = sign_in(&plugin, &ctx).await;
        assert_eq!(
            response.headers.get("Location").map(String::as_str),
            Some("http://localhost:3000/welcome")
        );
        assert_eq!(
            ctx.session_manager()
                .list_user_sessions(user.id().typed().unwrap())
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(mailbox.urls.lock().unwrap().len(), second_count);
    }
}

struct MutableProfile(Mutex<Value>);

#[async_trait]
impl GenericOAuthUserInfoHandler for MutableProfile {
    async fn get_user_info(&self, _: &OAuthUserInfoRequest) -> AuthResult<Option<Value>> {
        Ok(Some(self.0.lock().unwrap().clone()))
    }
}

#[tokio::test]
async fn verified_email_change_preserves_the_user_account_and_allows_sign_in() {
    let mut config = test_helpers::create_test_config().base_url("http://localhost:3000");
    config.account.skip_state_cookie_check = true;
    let ctx = test_helpers::create_test_context_with_config(config).await;
    let profile = Arc::new(MutableProfile(Mutex::new(json!({
        "id": "stable-subject",
        "email": "old@example.com",
        "emailVerified": true
    }))));
    let plugin = OAuthPlugin::new().add_generic_provider(
        "generic",
        GenericOAuthConfig {
            client_id: "client".to_owned(),
            authorization_url: Some("https://provider.example/authorize".to_owned()),
            get_token: Some(Arc::new(Provider)),
            get_user_info: Some(profile.clone()),
            override_user_info: true,
            require_email_verification: true,
            ..Default::default()
        },
    );
    let response = sign_in(&plugin, &ctx).await;
    assert_eq!(response.status, 302);
    assert_eq!(
        response.headers.get("Location").map(String::as_str),
        Some("http://localhost:3000/welcome")
    );
    let original_user = ctx
        .database
        .get_user_by_email("old@example.com")
        .await
        .unwrap()
        .unwrap();
    let original_account = ctx
        .database
        .get_account("generic", "stable-subject")
        .await
        .unwrap()
        .unwrap();

    *profile.0.lock().unwrap() = json!({
        "id": "stable-subject",
        "email": "new@example.com",
        "emailVerified": true
    });
    let response = sign_in(&plugin, &ctx).await;
    assert_eq!(response.status, 302);
    assert_eq!(
        response.headers.get("Location").map(String::as_str),
        Some("http://localhost:3000/welcome")
    );
    let updated_user = ctx
        .database
        .get_user_by_email("new@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated_user.id(), original_user.id());
    assert!(updated_user.email_verified().is_truthy().unwrap());
    assert!(
        ctx.database
            .get_user_by_email("old@example.com")
            .await
            .unwrap()
            .is_none()
    );
    let accounts = ctx
        .database
        .get_user_accounts(updated_user.id().typed().unwrap())
        .await
        .unwrap();
    assert_eq!(accounts.len(), 1);
    let account = accounts.first().unwrap();
    assert_eq!(account.id, original_account.id);
    assert_eq!(account.account_id, "stable-subject");
    assert_eq!(
        account.user_id.typed().unwrap().as_str(),
        updated_user.id().typed().unwrap()
    );
    assert_eq!(
        ctx.session_manager()
            .list_user_sessions(updated_user.id().typed().unwrap())
            .await
            .unwrap()
            .len(),
        2
    );
}

struct MutableTokens(Mutex<OAuthTokenSet>);

#[async_trait]
impl OAuthTokenHandler for MutableTokens {
    async fn get_token(&self, _: OAuthCodeExchange<'_>) -> AuthResult<OAuthTokenSet> {
        Ok(self.0.lock().unwrap().clone())
    }
}

#[tokio::test]
async fn sign_in_preserves_scopes_and_account_cookie_while_explicit_link_merges_scopes() {
    for update_on_sign_in in [false, true] {
        let mut config = test_helpers::create_test_config().base_url("http://localhost:3000");
        config.account.skip_state_cookie_check = true;
        config.account.store_account_cookie = Some(true);
        config.account.update_account_on_sign_in = Some(update_on_sign_in);
        let ctx = test_helpers::create_test_context_with_config(config).await;
        let tokens = Arc::new(MutableTokens(Mutex::new(OAuthTokenSet {
            access_token: Some("first-token".into()),
            scopes: [" stored ", "common", "", "dup", "common"]
                .map(str::to_owned)
                .to_vec(),
            ..Default::default()
        })));
        let profile = Arc::new(MutableProfile(Mutex::new(json!({
            "id":"stable-subject", "email":"owner@example.test", "emailVerified":true
        }))));
        let plugin = OAuthPlugin::new().add_generic_provider(
            "generic",
            GenericOAuthConfig {
                client_id: "client".into(),
                authorization_url: Some("https://provider.example/authorize".into()),
                get_token: Some(tokens.clone()),
                get_user_info: Some(profile),
                ..Default::default()
            },
        );
        assert_eq!(
            sign_in(&plugin, &ctx)
                .await
                .headers
                .get("Location")
                .map(String::as_str),
            Some("http://localhost:3000/welcome")
        );
        let incoming = OAuthTokenSet {
            access_token: Some("second-token".into()),
            scopes: [" new ", "common", "", "new"].map(str::to_owned).to_vec(),
            ..Default::default()
        };
        *tokens.0.lock().unwrap() = incoming.clone();
        let response = sign_in(&plugin, &ctx).await;
        assert_eq!(
            response.headers.get("Location").map(String::as_str),
            Some("http://localhost:3000/welcome")
        );
        let stored = ctx
            .database
            .get_account("generic", "stable-subject")
            .await
            .unwrap()
            .unwrap();
        let expected_token = if update_on_sign_in {
            "second-token"
        } else {
            "first-token"
        };
        assert_eq!(
            stored.scope.typed().unwrap().as_deref(),
            Some(" stored ,common,,dup,common")
        );
        assert_eq!(
            stored.access_token.typed().unwrap().as_deref(),
            Some(expected_token)
        );
        let cookies = response
            .headers
            .get_all("Set-Cookie")
            .map(|value| value.split(';').next().unwrap())
            .collect::<Vec<_>>()
            .join("; ");
        let mut request = AuthRequest::new(HttpMethod::Get, "/get-session");
        let _ = request.headers.insert("cookie".into(), cookies);
        let cookie = super::handlers::decode_account_cookie(&request, &ctx.config)
            .unwrap()
            .unwrap();
        assert_eq!(cookie.scope, stored.scope);
        assert_eq!(
            cookie.access_token.typed().unwrap().as_deref(),
            Some(expected_token)
        );
        let endpoint = crate::plugins::endpoint_context::EndpointContext::new(
            None,
            better_auth_core::FieldValue::Null,
            &ctx,
        );
        super::handlers::complete_link_social(
            "generic",
            &super::providers::OAuthUserInfo {
                id: "stable-subject".into(),
                email: Some("owner@example.test".into()).into(),
                name: Default::default(),
                image: None,
                email_verified: Some(true).into(),
                additional_fields: Default::default(),
            },
            &incoming,
            &super::state::OAuthStateLink::new(
                stored.user_id.field_value(),
                "owner@example.test".into(),
            ),
            None,
            &endpoint,
        )
        .await
        .unwrap_or_else(|_| panic!("explicit link must succeed"));
        let linked = ctx
            .database
            .get_account("generic", "stable-subject")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            linked.scope.typed().unwrap().as_deref(),
            Some("stored,common,dup,new")
        );
        assert_eq!(
            linked.access_token.typed().unwrap().as_deref(),
            Some("second-token")
        );
    }
}

#[tokio::test]
async fn social_verification_policy_uses_configured_profile_and_sender() {
    for (required, verified, expected_location, expected_sessions, first_count, second_count) in [
        (
            Some(true),
            false,
            "http://localhost:3000/error?error=email_not_verified",
            0,
            1,
            2,
        ),
        (Some(true), true, "http://localhost:3000/welcome", 2, 0, 0),
        (Some(false), false, "http://localhost:3000/welcome", 2, 0, 0),
        (None, false, "http://localhost:3000/welcome", 2, 0, 0),
    ] {
        let fixture = super::google_test_support::GoogleFixture::start(json!({
            "sub": "ordinary-social-profile",
            "email": "unverified@example.com",
            "email_verified": verified,
            "name": "Ordinary Social User",
            "picture": "https://images.example.test/ordinary.png"
        }))
        .await;
        let mut provider = fixture.provider();
        provider.require_email_verification = required;
        let mailbox = Arc::new(Mailbox::default());
        let verification = EmailVerificationConfig {
            send_on_sign_in: true,
            send_verification_email: Some(mailbox.clone()),
            ..Default::default()
        };
        let plugin = OAuthPlugin::new()
            .with_email_verification(Arc::new(EmailVerificationPlugin::with_config(verification)))
            .add_provider("google", provider);
        let mut config = test_helpers::create_test_config().base_url("http://localhost:3000");
        config.account.skip_state_cookie_check = true;
        let ctx = test_helpers::create_test_context_with_config(config).await;

        for count in [first_count, second_count] {
            let response = sign_in_with_provider(&plugin, &ctx, "google").await;
            assert_eq!(response.status, 302);
            assert_eq!(
                response.headers.get("Location").map(String::as_str),
                Some(expected_location)
            );
            assert_eq!(mailbox.urls.lock().unwrap().len(), count);
        }

        let user = ctx
            .database
            .get_user_by_email("unverified@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(user.email_verified(), verified);
        let user_view = serde_json::to_value(UserView::from(&user)).unwrap();
        assert_eq!(user_view["name"], "Ordinary Social User");
        assert_eq!(
            user_view["image"],
            "https://images.example.test/ordinary.png"
        );
        assert_eq!(
            ctx.database
                .get_user_accounts(user.id().typed().unwrap())
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            ctx.session_manager()
                .list_user_sessions(user.id().typed().unwrap())
                .await
                .unwrap()
                .len(),
            expected_sessions
        );
        for sent_url in mailbox.urls.lock().unwrap().iter() {
            let url = url::Url::parse(sent_url).unwrap();
            assert!(
                url.query_pairs().any(|(name, value)| name == "callbackURL"
                    && value == "http://localhost:3000/welcome")
            );
        }
    }
}

#[path = "signin_name_tests.rs"]
mod signin_name_tests;
