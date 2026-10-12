#![expect(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Fixture indexing must fail when an expected record or property is missing."
)]
#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
//! Token refresh preserves adapter values, Cookie property order, and explicit account sources.

use super::*;
use better_auth_api::plugins::oauth::{
    OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use better_auth_core::{
    AuthResponse, AuthResult, FieldMap, FieldValue,
    endpoint_dispatch::EndpointDispatcher,
    store::database_hooks::{DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks},
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType},
};

pub(super) async fn dispatch<S: better_auth_core::AuthSchema>(
    plugin: &OAuthPlugin,
    request: &AuthRequest,
    context: &AuthContext<S>,
) -> AuthResult<AuthResponse> {
    let dispatcher = EndpointDispatcher::new(
        Arc::new(Vec::new()),
        Default::default(),
        AuthPlugin::<S>::routes(plugin),
    );
    let mut input = request.clone();
    let mut scope = better_auth_core::RequestHookContext::from_request(request)?;
    scope.is_http = true;
    better_auth_core::with_request_hook_context_value(
        scope,
        dispatcher.run(
            &mut input,
            true,
            context,
            None,
            |request, context| async move {
                plugin.on_request(&request, &context).await?.ok_or_else(|| {
                    better_auth_core::AuthError::internal(
                        "OAuth endpoint did not match the request",
                    )
                })
            },
        ),
    )
    .await
}

struct RefreshWrites(Arc<std::sync::Mutex<Vec<FieldMap>>>);

#[better_auth_core::database_hooks]
impl DatabaseHooks<TestSchema> for RefreshWrites {
    async fn before_update_account(
        &self,
        fields: &mut FieldMap,
        _: &DatabaseHookContext<'_, TestSchema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.0.lock().unwrap().push(fields.clone());
        Ok(DatabaseHookUpdate::Continue)
    }
}

fn refreshed_cookie_claims(response: &better_auth_core::AuthResponse) -> serde_json::Value {
    assert_eq!(response.headers.get_all("Set-Cookie").count(), 1);
    let cookie = response
        .headers
        .get_all("Set-Cookie")
        .find_map(|value| value.strip_prefix("better-auth.account_data="))
        .expect("refresh must issue an account cookie");
    let token = cookie.split(';').next().unwrap();
    let mut claims =
        better_auth_core::utils::jwe::decode(token, TEST_SECRET, "better-auth-account")
            .expect("account cookie must decrypt");
    let issued = claims["iat"].as_i64().unwrap();
    assert_eq!(claims["exp"].as_i64().unwrap() - issued, 300);
    assert!(!claims["jti"].as_str().unwrap().is_empty());
    claims.retain(|name, _| !matches!(name.as_str(), "iat" | "exp" | "jti"));
    serde_json::Value::Object(claims)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RefreshSelection {
    Cookie,
    AccountId,
    OtherCookieId,
    NoAccountId,
    ForeignCookieOwner,
    OutputError,
}

// Better Auth 1.7.6 spreads the complete adapter result, or the original update after a missing ID.
// The cookie remains a JSON object until the token consumer explicitly converts a date.
#[tokio::test]
async fn test_token_refresh_preserves_complete_cookie_spread_and_account_selection() {
    for (path, selection) in [
        ("/get-access-token", RefreshSelection::Cookie),
        ("/refresh-token", RefreshSelection::Cookie),
        ("/refresh-token", RefreshSelection::AccountId),
        ("/refresh-token", RefreshSelection::OtherCookieId),
        ("/get-access-token", RefreshSelection::NoAccountId),
        ("/refresh-token", RefreshSelection::NoAccountId),
        ("/refresh-token", RefreshSelection::ForeignCookieOwner),
        ("/get-access-token", RefreshSelection::OutputError),
        ("/refresh-token", RefreshSelection::OutputError),
    ] {
        assert_token_refresh_cookie_spread(path, selection).await;
    }
}

async fn assert_token_refresh_cookie_spread(path: &str, selection: RefreshSelection) {
    let mut config = test_config_with_account_cookie();
    let db = create_test_database().await;
    let (user_id, session_token, account_id) = setup_user_with_account(
        &db,
        &Arc::new(config.clone()),
        "cookie-spread@example.com",
        "google",
        Some("old-access-token".into()),
        Some("old-refresh-token".into()),
    )
    .await;
    let original = db
        .update_account(
            &account_id,
            better_auth_core::UpdateAccount {
                id_token: Some("old-id-token".into()).into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let mut expected_storage = original.internal_fields().unwrap().json().unwrap();
    let replaced_password = json!({"secret": null, "parts": ["first", {"nested": true}]});
    for (name, value) in [
        ("idToken", FieldValue::Undefined),
        (
            "password",
            FieldValue::from_json(replaced_password.clone()).unwrap(),
        ),
        ("createdAt", "adapter-created".into()),
        ("updatedAt", "adapter-updated".into()),
    ] {
        let fail_output = selection == RefreshSelection::OutputError && name == "idToken";
        config.account.additional_fields.insert(
            name.into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |_| {
                        if fail_output {
                            Err(better_auth_core::AuthError::type_error(
                                "token-output-rejected",
                            ))
                        } else {
                            Ok(value.clone())
                        }
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    }
    let no_id = selection == RefreshSelection::NoAccountId;
    let by_id = matches!(
        selection,
        RefreshSelection::AccountId | RefreshSelection::OtherCookieId
    );
    let writes = Arc::new(std::sync::Mutex::new(Vec::new()));
    let config = Arc::new(config);
    let runtime = db
        .with_runtime(
            config.clone(),
            vec![Arc::new(RefreshWrites(writes.clone()))],
            Default::default(),
        )
        .unwrap();
    let ctx = AuthContext::new(config, runtime)
        .expect("fixture context initializes")
        .initialize_request_context()
        .await
        .unwrap();
    let expired = json!("2000-01-01T00:00:00.000Z");
    let next_expiry = better_auth_core::FieldDate::from_milliseconds(4_102_444_800_000.0);
    let next_expiry_json = FieldValue::from(next_expiry.clone())
        .json()
        .unwrap()
        .unwrap();
    let mut initial = json!({
        "marker": {"first": 1, "second": null},
        "userId": if selection == RefreshSelection::ForeignCookieOwner { "foreign-owner" } else { &user_id },
        "refreshToken": "old-refresh-token",
        "password": null,
        "idToken": "old-id-token",
        "scope": "cookie-scope",
        "providerId": "google",
        "accountId": "google-account-id",
        "accessToken": "old-access-token",
        "accessTokenExpiresAt": expired,
        "createdAt": "cookie-created-without-date-conversion"
    });
    if !no_id {
        initial["id"] = json!(if selection == RefreshSelection::OtherCookieId {
            "another-account"
        } else {
            &account_id
        });
    }
    let cookie = better_auth_core::utils::jwe::encode(
        initial.as_object().unwrap().clone(),
        TEST_SECRET,
        "better-auth-account",
        300.0,
    )
    .unwrap();
    let sequence = Arc::new(std::sync::Mutex::new(vec![(
        "old-refresh-token".into(),
        OAuthTokenSet {
            access_token: if no_id {
                Default::default()
            } else {
                Some("rotated-access-token".into()).into()
            },
            refresh_token: (Some("rotated-refresh-token".into())).into(),
            access_token_expires_at: if no_id {
                Default::default()
            } else {
                Some(next_expiry).into()
            },
            ..Default::default()
        },
    )]));
    let mut provider = make_test_provider("http://localhost:65535");
    provider.refresh_access_token = Some(Arc::new(RotatingRefreshHandler {
        sequence: sequence.clone(),
    }));
    let mut oauth_config = OAuthConfig::default();
    oauth_config.providers.insert("google".into(), provider);
    let plugin = OAuthPlugin::with_config(oauth_config);
    let mut req = AuthRequest::new(HttpMethod::Post, path);
    req.body = Some(
        if by_id {
            json!({"accountId": account_id})
        } else {
            json!({"useAccountCookie": true})
        }
        .to_string()
        .into_bytes(),
    );
    req.headers
        .insert("content-type".into(), "application/json".into());
    set_session_and_account_cookies(&mut req, &session_token, &cookie);
    let response = dispatch(&plugin, &req, &ctx).await.unwrap();
    let rejected = selection == RefreshSelection::ForeignCookieOwner;
    let failed_output = selection == RefreshSelection::OutputError;
    assert_eq!(
        response.status,
        if rejected || failed_output { 400 } else { 200 },
        "{path} {selection:?}"
    );
    assert_eq!(sequence.lock().unwrap().len(), usize::from(rejected));
    {
        let writes = writes.lock().unwrap();
        if no_id || rejected {
            assert!(writes.is_empty());
        } else {
            assert_eq!(writes.len(), 1);
            let order = if path == "/get-access-token" {
                [
                    "accessToken",
                    "accessTokenExpiresAt",
                    "refreshToken",
                    "refreshTokenExpiresAt",
                    "idToken",
                ]
            } else {
                [
                    "accessToken",
                    "refreshToken",
                    "accessTokenExpiresAt",
                    "refreshTokenExpiresAt",
                    "idToken",
                ]
            };
            assert_eq!(
                writes[0].keys().map(String::as_str).collect::<Vec<_>>(),
                order
            );
            assert_eq!(
                writes[0]["idToken"],
                if by_id {
                    FieldValue::Undefined
                } else {
                    "old-id-token".into()
                }
            );
            expected_storage.insert("accessToken".into(), json!("rotated-access-token"));
            expected_storage.insert("refreshToken".into(), json!("rotated-refresh-token"));
            expected_storage.insert("accessTokenExpiresAt".into(), next_expiry_json.clone());
        }
    }
    let stored = db.get_user_accounts(&user_id).await.unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(
        stored[0].internal_fields().unwrap().json().unwrap(),
        expected_storage
    );
    if rejected || failed_output || by_id {
        assert!(
            !response
                .headers
                .get_all("Set-Cookie")
                .any(|value| value.starts_with("better-auth.account_data="))
        );
        if rejected || failed_output {
            let body: serde_json::Value =
                serde_json::from_slice(&response.body.bytes().unwrap()).unwrap();
            assert_eq!(
                body,
                if rejected {
                    json!({"code": "ACCOUNT_NOT_FOUND", "message": "Account not found"})
                } else if path == "/get-access-token" {
                    json!({"code": "FAILED_TO_GET_ACCESS_TOKEN", "message": "Failed to get a valid access token"})
                } else {
                    json!({"code": "FAILED_TO_REFRESH_ACCESS_TOKEN", "message": "Failed to refresh access token"})
                }
            );
        }
        return;
    }
    let mut expected = initial;
    expected["refreshToken"] = json!("rotated-refresh-token");
    if no_id {
        expected
            .as_object_mut()
            .unwrap()
            .retain(|name, _| !matches!(name.as_str(), "accessToken" | "accessTokenExpiresAt"));
    } else {
        expected
            .as_object_mut()
            .unwrap()
            .retain(|name, _| name != "idToken");
        expected["password"] = replaced_password;
        expected["scope"] = json!("email profile");
        expected["accessToken"] = json!("rotated-access-token");
        expected["accessTokenExpiresAt"] = next_expiry_json;
        expected["createdAt"] = json!("adapter-created");
        expected["refreshTokenExpiresAt"] = serde_json::Value::Null;
        expected["updatedAt"] = json!("adapter-updated");
    }
    let actual = refreshed_cookie_claims(&response);
    assert_eq!(actual, expected, "{path} {selection:?}");
    assert_eq!(
        actual.as_object().unwrap().keys().collect::<Vec<_>>(),
        expected.as_object().unwrap().keys().collect::<Vec<_>>(),
        "{path} {selection:?}"
    );
}

struct ObserveAccountInfo(Arc<std::sync::Mutex<Vec<OAuthUserInfoRequest>>>);

#[async_trait]
impl OAuthUserInfoHandler for ObserveAccountInfo {
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        self.0.lock().unwrap().push(request);
        Ok(Some(OAuthUserInfoResponse {
            user: OAuthUserInfo {
                id: "provider-user".into(),
                email: Some("account-info-date@example.com".into()).into(),
                name: Some("Account Owner".into()).into(),
                image: None,
                email_verified: Some(true).into(),
                additional_fields: Default::default(),
            },
            data: json!({"sub": "provider-user"}),
        }))
    }
}

#[tokio::test]
async fn test_account_info_consumes_converted_cookie_expiry_and_refreshed_expiry() {
    for refresh in [false, true] {
        let config = Arc::new(test_config_with_account_cookie());
        let db = create_test_database().await;
        let (user_id, session_token, _) = setup_user_with_account(
            &db,
            &config,
            "account-info-date@example.com",
            "google",
            Some("old-access-token".into()),
            Some("old-refresh-token".into()),
        )
        .await;
        let account = db.get_user_accounts(&user_id).await.unwrap().remove(0);
        let next_expiry = better_auth_core::FieldDate::from_milliseconds(4_102_444_800_000.0);
        let cookie = encode_account_cookie(
            &account,
            Some("old-access-token"),
            Some("old-refresh-token"),
            Some(if refresh {
                better_auth_core::FieldDate::from_milliseconds(946_684_800_000.0)
            } else {
                next_expiry.clone()
            }),
        );
        let sequence = Arc::new(std::sync::Mutex::new(if refresh {
            vec![(
                "old-refresh-token".into(),
                OAuthTokenSet {
                    access_token: (Some("refreshed-access-token".into())).into(),
                    access_token_expires_at: (Some(next_expiry.clone())).into(),
                    ..Default::default()
                },
            )]
        } else {
            Vec::new()
        }));
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut provider = make_test_provider("http://localhost:65535");
        provider.refresh_access_token = Some(Arc::new(RotatingRefreshHandler {
            sequence: sequence.clone(),
        }));
        provider.get_user_info = Some(Arc::new(ObserveAccountInfo(calls.clone())));
        let mut oauth_config = OAuthConfig::default();
        oauth_config.providers.insert("google".into(), provider);
        let plugin = OAuthPlugin::with_config(oauth_config);
        let ctx = AuthContext::new(config, db)
            .expect("fixture context initializes")
            .initialize_request_context()
            .await
            .unwrap();
        let mut req = AuthRequest::new(HttpMethod::Get, "/account-info");
        req.query = Some(json!({"useAccountCookie": true}));
        set_session_and_account_cookies(&mut req, &session_token, &cookie);
        let response = dispatch(&plugin, &req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);
        assert!(sequence.lock().unwrap().is_empty());
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].access_token.field_value().as_str(),
            Some(if refresh {
                "refreshed-access-token"
            } else {
                "old-access-token"
            })
        );
        assert_eq!(
            calls[0]
                .access_token_expires_at
                .field_value()
                .as_date()
                .unwrap()
                .milliseconds(),
            next_expiry.milliseconds()
        );
        assert_eq!(json!(calls[0].scopes), json!(["email profile"]));
    }
}

struct RejectUserInfo(Arc<std::sync::Mutex<Vec<OAuthUserInfoRequest>>>);

fn profile_rejection() -> serde_json::Value {
    json!({
        "code":"PROVIDER_PROFILE_REJECTED",
        "message":"Provider refused the refreshed token",
        "details":{"source":"userinfo","retryable":false}
    })
}

#[async_trait]
impl OAuthUserInfoHandler for RejectUserInfo {
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        self.0.lock().unwrap().push(request);
        Err(AuthResponse::json(409, &profile_rejection())?.into())
    }
}

#[tokio::test]
async fn test_get_access_token_preserves_refreshed_cookie_after_scope_failure() {
    assert_refresh_cookie_survives_failure(false).await;
}

#[tokio::test]
async fn test_account_info_preserves_refreshed_cookie_after_provider_failure() {
    assert_refresh_cookie_survives_failure(true).await;
}

async fn assert_refresh_cookie_survives_failure(profile: bool) {
    let updated_at = better_auth_core::FieldDate::from_milliseconds(1_893_456_000_000.0);
    let mut config = test_config_with_account_cookie();
    let timestamp = updated_at.clone();
    config.account.additional_fields.insert(
        "updatedAt".into(),
        UserFieldConfig {
            field_type: UserFieldType::Date,
            on_update: Some(better_auth_core::user_fields::UserFieldFactory::new(
                move || Ok(timestamp.clone().into()),
            )),
            ..Default::default()
        },
    );
    let config = Arc::new(config);
    let db = create_test_database().await;
    let (user_id, session_token, account_id) = setup_user_with_account(
        &db,
        &config,
        "refresh-failure@example.com",
        "google",
        Some("old-access-token".into()),
        Some("old-refresh-token".into()),
    )
    .await;
    let original = db.get_user_accounts(&user_id).await.unwrap().remove(0);
    let mut cookie_fields = original.internal_fields().unwrap().json().unwrap();
    cookie_fields.insert(
        "accessTokenExpiresAt".into(),
        json!("2000-01-01T00:00:00.000Z"),
    );
    if !profile {
        cookie_fields.insert("scope".into(), json!(7));
    }
    let cookie = better_auth_core::utils::jwe::encode(
        cookie_fields,
        TEST_SECRET,
        "better-auth-account",
        300.0,
    )
    .unwrap();
    let next_expiry = better_auth_core::FieldDate::from_milliseconds(4_102_444_800_000.0);
    let sequence = Arc::new(std::sync::Mutex::new(vec![(
        "old-refresh-token".into(),
        OAuthTokenSet {
            access_token: (Some("rotated-access-token".into())).into(),
            refresh_token: (Some("rotated-refresh-token".into())).into(),
            access_token_expires_at: (Some(next_expiry.clone())).into(),
            ..Default::default()
        },
    )]));
    let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut provider = make_test_provider("http://localhost:65535");
    provider.refresh_access_token = Some(Arc::new(RotatingRefreshHandler {
        sequence: sequence.clone(),
    }));
    provider.get_user_info = Some(Arc::new(RejectUserInfo(calls.clone())));
    let mut oauth_config = OAuthConfig::default();
    oauth_config.providers.insert("google".into(), provider);
    let plugin = OAuthPlugin::with_config(oauth_config);
    let writes = Arc::new(std::sync::Mutex::new(Vec::new()));
    let runtime = db
        .with_runtime(
            config.clone(),
            vec![Arc::new(RefreshWrites(writes.clone()))],
            Default::default(),
        )
        .unwrap();
    let ctx = AuthContext::new(config, runtime)
        .expect("fixture context initializes")
        .initialize_request_context()
        .await
        .unwrap();
    let mut req = if profile {
        let mut request = AuthRequest::new(HttpMethod::Get, "/account-info");
        request.query = Some(json!({"useAccountCookie":true}));
        request
    } else {
        let mut request = AuthRequest::new(HttpMethod::Post, "/get-access-token");
        request.body = Some(json!({"useAccountCookie":true}).to_string().into_bytes());
        request
            .headers
            .insert("content-type".into(), "application/json".into());
        request
    };
    set_session_and_account_cookies(&mut req, &session_token, &cookie);
    let response = dispatch(&plugin, &req, &ctx).await.unwrap();
    assert_eq!(response.status, if profile { 409 } else { 400 });
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&response.body.bytes().unwrap()).unwrap(),
        if profile {
            profile_rejection()
        } else {
            json!({
                "code":"FAILED_TO_GET_ACCESS_TOKEN",
                "message":"Failed to get a valid access token"
            })
        }
    );
    assert!(sequence.lock().unwrap().is_empty());
    {
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), usize::from(profile));
        if profile {
            assert_eq!(
                calls[0].access_token.field_value().as_str(),
                Some("rotated-access-token")
            );
            assert_eq!(
                calls[0]
                    .access_token_expires_at
                    .field_value()
                    .as_date()
                    .unwrap()
                    .milliseconds(),
                next_expiry.milliseconds()
            );
            assert_eq!(json!(calls[0].scopes), json!(["email profile"]));
        }
    }
    let expected_write = FieldMap::from([
        ("accessToken".into(), "rotated-access-token".into()),
        ("accessTokenExpiresAt".into(), next_expiry.into()),
        ("refreshToken".into(), "rotated-refresh-token".into()),
        (
            "refreshTokenExpiresAt".into(),
            original.refresh_token_expires_at.field_value(),
        ),
        ("idToken".into(), original.id_token.field_value()),
    ]);
    {
        let writes = writes.lock().unwrap();
        assert_eq!(writes.as_slice(), std::slice::from_ref(&expected_write));
        assert_eq!(
            writes[0].keys().collect::<Vec<_>>(),
            expected_write.keys().collect::<Vec<_>>()
        );
    }
    let mut expected_storage = original.internal_fields().unwrap().json().unwrap();
    expected_storage.extend(expected_write.json().unwrap());
    expected_storage.insert(
        "updatedAt".into(),
        FieldValue::from(updated_at).json().unwrap().unwrap(),
    );
    let stored = db.get_user_accounts(&user_id).await.unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].id, account_id);
    assert_eq!(
        stored[0].internal_fields().unwrap().json().unwrap(),
        expected_storage
    );
    assert_eq!(
        refreshed_cookie_claims(&response),
        serde_json::Value::Object(expected_storage)
    );
    assert!(req.take_response_headers().unwrap().is_empty());
}
