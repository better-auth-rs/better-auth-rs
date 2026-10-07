use super::*;
use crate::plugins::test_helpers::{create_test_context_with_user, finalize_response};
use better_auth_core::{CreateUser, HttpMethod};

fn verify_request(token: &str) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Post, "/one-time-token/verify");
    let _ = req
        .headers
        .insert("content-type".into(), "application/json".into());
    req.body = Some(serde_json::to_vec(&serde_json::json!({ "token": token })).unwrap());
    req
}

#[tokio::test]
async fn concurrent_redemption_issues_one_cookie_and_expired_proofs_cannot_authenticate() {
    let (ctx, user, session) = create_test_context_with_user(
        CreateUser::new()
            .with_email("transfer@example.com")
            .with_name("Fixture"),
        Duration::hours(1),
    )
    .await;
    let plugin = OneTimeTokenPlugin::new().store_token(TokenStorage::Hashed);
    let token = plugin
        .generate(&ctx, session.clone(), user.clone())
        .await
        .unwrap();
    assert!(
        ctx.database
            .get_verification_by_identifier(&format!("one-time-token:{token}"))
            .await
            .unwrap()
            .is_none()
    );
    let first_request = verify_request(&token);
    let second_request = verify_request(&token);
    let (first, second) = tokio::join!(
        plugin.handle_verify(&first_request, &ctx),
        plugin.handle_verify(&second_request, &ctx)
    );
    let responses = [
        finalize_response(&ctx, &first_request, first.unwrap()),
        finalize_response(&ctx, &second_request, second.unwrap()),
    ];
    assert_eq!(
        responses
            .iter()
            .filter(|response| response.status == 200)
            .count(),
        1
    );
    assert_eq!(
        responses
            .iter()
            .filter(|response| response.headers.contains_key("set-cookie"))
            .count(),
        1
    );
    assert_eq!(
        responses
            .iter()
            .filter(|response| response.status == 400)
            .count(),
        1
    );
    let expired = OneTimeTokenPlugin::new().expires_in(Duration::seconds(-1));
    let token = expired.generate(&ctx, session, user).await.unwrap();
    let request = verify_request(&token);
    let response = expired.handle_verify(&request, &ctx).await.unwrap();
    let response = finalize_response(&ctx, &request, response);
    assert_eq!(response.status, 400);
    assert!(!response.headers.contains_key("set-cookie"));
    assert!(
        ctx.database
            .get_verification_by_identifier(&format!("one-time-token:{token}"))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn custom_hashing_does_not_extend_token_lifetime() {
    let (ctx, user, session) = create_test_context_with_user(
        CreateUser::new()
            .with_email("slow-hash@example.com")
            .with_name("Slow Hash"),
        Duration::hours(1),
    )
    .await;
    let lifetime = Duration::milliseconds(50);
    let hash_times = Arc::new(std::sync::Mutex::new(Vec::new()));
    let callback_times = hash_times.clone();
    let plugin = OneTimeTokenPlugin::new()
        .expires_in(lifetime)
        .store_token(TokenStorage::Custom(Arc::new(move |token| {
            let times = callback_times.clone();
            Box::pin(async move {
                let entered = Utc::now();
                let first = times.lock().unwrap().is_empty();
                if first {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                times.lock().unwrap().push((entered, Utc::now()));
                Ok(format!("hashed:{token}"))
            })
        })));
    let token = plugin.generate(&ctx, session, user).await.unwrap();
    let identifier = format!("one-time-token:hashed:{token}");
    let proof = ctx
        .database
        .get_verification_including_expired(&identifier)
        .await
        .unwrap()
        .unwrap();
    let (entered, completed) = hash_times.lock().unwrap().first().copied().unwrap();
    assert!(completed - entered > lifetime);
    let expires_at = proof.expires_at.date_milliseconds().unwrap();
    assert!(
        expires_at <= (entered + lifetime).timestamp_millis() as f64,
        "the token deadline must be computed before the custom hasher starts"
    );
    assert!(expires_at < completed.timestamp_millis() as f64);
    for attempt in ["verification", "replay"] {
        let request = verify_request(&token);
        let response = plugin.handle_verify(&request, &ctx).await.unwrap();
        let response = finalize_response(&ctx, &request, response);
        assert_eq!(response.status, 400, "{attempt}");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&response.body.bytes().unwrap()).unwrap(),
            serde_json::json!({ "message": "Invalid token" }),
            "{attempt}"
        );
        assert!(!response.headers.contains_key("set-cookie"), "{attempt}");
        assert!(
            ctx.database
                .get_verification_including_expired(&identifier)
                .await
                .unwrap()
                .is_none(),
            "{attempt} must leave the proof consumed"
        );
    }
}
