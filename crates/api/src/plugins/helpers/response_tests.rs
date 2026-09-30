use better_auth_core::{AuthPlugin, AuthRequest, AuthResponse, HttpMethod};
use serde_json::{Value, json};

use crate::plugins::{
    anonymous::AnonymousPlugin, phone_number::PhoneNumberPlugin, test_helpers::create_test_context,
};

#[tokio::test]
async fn identity_defaults_preserve_metadata_that_resembles_a_user() {
    let mut ctx = create_test_context().await;
    ctx.set_metadata("anonymous.enabled", json!(true));
    ctx.set_metadata("phone-number.enabled", json!(true));
    let user =
        json!({"id":"identity", "emailVerified":false, "createdAt":"2026-09-30T00:00:00.000Z"});
    let metadata = json!({"user":user, "members":[{"user":user}], "nested":user});
    let mut response = AuthResponse::json(
        200,
        &json!({
            "user":user,
            "users":[user],
            "members":[{"user":user,"metadata":metadata}],
            "metadata":metadata,
            "arbitrary":[user],
        }),
    )
    .unwrap();
    let request = AuthRequest::new(HttpMethod::Post, "/api-key/create");
    AnonymousPlugin::new()
        .after_request(&request, &mut response, &ctx)
        .await
        .unwrap();
    PhoneNumberPlugin::new()
        .after_request(&request, &mut response, &ctx)
        .await
        .unwrap();
    let actual: Value = serde_json::from_slice(&response.body).unwrap();
    let mut projected_user = user.clone();
    let fields = projected_user.as_object_mut().unwrap();
    fields.insert("isAnonymous".into(), json!(false));
    fields.insert("phoneNumber".into(), Value::Null);
    fields.insert("phoneNumberVerified".into(), Value::Null);
    assert_eq!(
        actual,
        json!({
            "user":projected_user,
            "users":[projected_user],
            "members":[{"user":projected_user,"metadata":metadata}],
            "metadata":metadata,
            "arbitrary":[user],
        })
    );
}
