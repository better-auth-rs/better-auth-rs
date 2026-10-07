use super::*;
use crate::plugins::test_helpers::{create_test_context, finalize_response};
use std::collections::HashMap;

fn cookies(response: &AuthResponse) -> String {
    response
        .headers
        .get_all("set-cookie")
        .map(|cookie| cookie.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ")
}

#[tokio::test]
async fn signed_paybin_code_account_info_and_refresh_persist_normal_sqlite_records() {
    let fixture = fixture();
    let sample = &fixture["profileCases"][0];
    let server = Server::start(sample["profile"].clone()).await;
    let seen = Arc::default();
    let mut provider = server.provider();
    provider.map_profile_to_user = Some(Arc::new(Mapper {
        patch: sample["patch"].clone(),
        seen: Arc::clone(&seen),
        error: false,
    }));
    let plugin = OAuthPlugin::new().add_provider("paybin", provider);
    let ctx = create_test_context().await;
    let mut start = AuthRequest::new(HttpMethod::Post, "/sign-in/social");
    start.body = Some(serde_json::to_vec(&json!({"provider":"paybin", "callbackURL":"http://localhost:3000/welcome", "disableRedirect":true})).unwrap());
    let start_response = finalize_response(
        &ctx,
        &start,
        plugin.on_request(&start, &ctx).await.unwrap().unwrap(),
    );
    assert_eq!(start_response.status, 200);
    let start_cookies = cookies(&start_response);
    assert!(!start_cookies.is_empty());
    let start_body: Value = serde_json::from_slice(&start_response.body.bytes().unwrap()).unwrap();
    let url = url::Url::parse(start_body["url"].as_str().unwrap()).unwrap();
    assert_eq!(url.path(), "/oauth2/authorize");
    let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(query["code_challenge_method"], "S256");
    let mut callback = AuthRequest::new(HttpMethod::Get, "/callback/paybin");
    callback.query = Some(json!({"code":"ordinary-code", "state":query["state"]}));
    let _ = callback.headers.insert("cookie".into(), start_cookies);
    let response = finalize_response(
        &ctx,
        &callback,
        plugin.on_request(&callback, &ctx).await.unwrap().unwrap(),
    );
    assert_eq!(response.status, 302);
    assert_eq!(
        response.headers.get("location").map(String::as_str),
        Some("http://localhost:3000/welcome")
    );
    assert!(
        response
            .headers
            .get_all("set-cookie")
            .any(|cookie| cookie.starts_with("better-auth.session_token="))
    );
    let session_cookie = cookies(&response);
    let user = ctx
        .database
        .get_user_by_email(sample["result"]["user"]["email"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    let stored_user = serde_json::to_value(&user).unwrap();
    for field in ["name", "email", "image", "emailVerified"] {
        assert_eq!(
            stored_user[field], sample["result"]["user"][field],
            "{field}"
        );
    }
    let user_id = user.id.display_string().unwrap();
    let accounts = ctx.database.get_user_accounts(&user_id).await.unwrap();
    assert_eq!(accounts.len(), 1);
    let account = serde_json::to_value(&accounts[0]).unwrap();
    let code = &fixture["grants"][0]["response"];
    assert_eq!(account["providerId"], "paybin");
    assert_eq!(account["accountId"], server.claims["sub"]);
    assert_eq!(account["accessToken"], code["accessToken"]);
    assert_eq!(account["refreshToken"], code["refreshToken"]);
    assert_eq!(account["idToken"], server.token);
    let scopes: Vec<String> = serde_json::from_value(code["scopes"].clone()).unwrap();
    assert_eq!(account["scope"], scopes.join(","));
    let captured = server.requests.lock().unwrap()[0].clone();
    let fields: HashMap<String, String> =
        url::form_urlencoded::parse(captured["body"].as_str().unwrap().as_bytes())
            .into_owned()
            .collect();
    assert_eq!(fields["grant_type"], "authorization_code");
    assert_eq!(
        fields["client_id"],
        fixture["metadata"]["clientId"].as_str().unwrap()
    );
    assert_eq!(
        fields["client_secret"],
        fixture["metadata"]["clientSecret"].as_str().unwrap()
    );
    assert_eq!(fields["redirect_uri"], query["redirect_uri"]);
    assert_eq!(fields["code"], "ordinary-code");
    assert_eq!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(fields["code_verifier"].as_bytes())),
        query["code_challenge"]
    );
    assert!(!fields.contains_key("device_id"));

    let mut info = AuthRequest::new(HttpMethod::Get, "/account-info");
    info.query = Some(json!({"accountId":account["id"]}));
    let _ = info.headers.insert("cookie".into(), session_cookie.clone());
    let response = finalize_response(
        &ctx,
        &info,
        plugin.on_request(&info, &ctx).await.unwrap().unwrap(),
    );
    assert_eq!(response.status, 200);
    let body: Value = serde_json::from_slice(&response.body.bytes().unwrap()).unwrap();
    assert_eq!(body["user"], sample["result"]["user"]);
    assert_eq!(body["data"], server.claims);
    assert_eq!(
        *seen.lock().unwrap(),
        [server.claims.clone(), server.claims.clone()]
    );

    let mut refresh = AuthRequest::new(HttpMethod::Post, "/refresh-token");
    refresh.body = Some(serde_json::to_vec(&json!({"accountId":account["id"]})).unwrap());
    let _ = refresh.headers.insert("cookie".into(), session_cookie);
    let response = finalize_response(
        &ctx,
        &refresh,
        plugin.on_request(&refresh, &ctx).await.unwrap().unwrap(),
    );
    assert_eq!(response.status, 200);
    let body: Value = serde_json::from_slice(&response.body.bytes().unwrap()).unwrap();
    let expected = &fixture["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "refresh")
        .unwrap()["response"];
    assert_eq!(body["accessToken"], expected["accessToken"]);
    assert_eq!(body["refreshToken"], expected["refreshToken"]);
    assert_eq!(body["scope"], account["scope"]);
    let accounts = ctx.database.get_user_accounts(&user_id).await.unwrap();
    assert_eq!(accounts.len(), 1);
    let updated = serde_json::to_value(&accounts[0]).unwrap();
    for field in [
        "id",
        "userId",
        "accountId",
        "providerId",
        "scope",
        "idToken",
    ] {
        assert_eq!(updated[field], account[field], "{field}");
    }
    assert_eq!(updated["accessToken"], expected["accessToken"]);
    assert_eq!(updated["refreshToken"], expected["refreshToken"]);
    assert_eq!(
        *server.paths.lock().unwrap(),
        [
            "/oauth2/token",
            "/.well-known/openid-configuration",
            "/keys/active",
            "/.well-known/openid-configuration",
            "/keys/active",
            "/oauth2/token"
        ]
    );
}
