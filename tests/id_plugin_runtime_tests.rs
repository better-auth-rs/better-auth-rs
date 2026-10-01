#![allow(
    clippy::unwrap_used,
    reason = "Contract fixtures fail on unexpected setup or response errors"
)]
#[path = "common/id_runtime.rs"]
mod support;
use better_auth::config::{IdGeneration, IdGenerator};
use better_auth::plugins::organization::OrganizationTeamsConfig;
use better_auth::plugins::{
    ApiKeyPlugin, DeviceAuthorizationPlugin, EmailPasswordPlugin, OrganizationPlugin,
    SessionManagementPlugin, TwoFactorPlugin,
};
use better_auth::{AuthConfig, BetterAuth};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use support::{Hasher, request};

#[tokio::test]
async fn missing_plugin_ids_preserve_create_and_followup_operations() {
    for model in [
        "organization",
        "member",
        "team",
        "teamMember",
        "invitation",
        "organizationRole",
        "apikey",
        "deviceCode",
        "twoFactor",
    ] {
        let mut config = AuthConfig::new("plugin-id-secret-at-least-thirty-two-characters")
            .base_url("http://localhost:3000");
        let calls = Arc::new(AtomicUsize::new(0));
        config.advanced.database.generate_id =
            Some(IdGeneration::Custom(IdGenerator::new(move |request| {
                let count = calls.fetch_add(1, Ordering::SeqCst) + 1;
                Ok(Some(if request.model == model {
                    String::new()
                } else {
                    format!("{}-{count}", request.model)
                }))
            })));
        let auth = BetterAuth::stateless(config)
            .plugin(EmailPasswordPlugin::new().password_hasher(Arc::new(Hasher)))
            .plugin(SessionManagementPlugin::new())
            .plugin(ApiKeyPlugin::with_config(Default::default()))
            .plugin(DeviceAuthorizationPlugin::new())
            .plugin(TwoFactorPlugin::new())
            .plugin(
                OrganizationPlugin::new()
                    .dynamic_access_control(true)
                    .access_control(std::collections::HashMap::from([(
                        "invitation".into(),
                        vec!["create".into()],
                    )]))
                    .teams(OrganizationTeamsConfig {
                        enabled: true,
                        ..Default::default()
                    }),
            )
            .build()
            .await
            .unwrap();
        let signup=request(&auth,"/sign-up/email",Some(json!({"email":"plugin@example.com","name":"Fixture","password":"long-enough-password"})),"").await;
        assert_eq!(signup.0, 200, "{model}: {}", signup.1);
        let cookie = signup.2;
        match model {
            "apikey" => {
                let create = request(&auth, "/api-key/create", Some(json!({})), &cookie).await;
                assert_eq!(create.0, 200, "{}", create.1);
                assert!(create.1.get("id").is_none());
                let verify = auth
                    .api_keys()
                    .unwrap()
                    .verify(create.1["key"].as_str().unwrap(), Default::default())
                    .await
                    .unwrap();
                assert!(verify.id.is_undefined());
                assert_eq!(verify.request_count, Some(1.0));
            }
            "deviceCode" => {
                let create = request(
                    &auth,
                    "/device/code",
                    Some(json!({"client_id":"client"})),
                    &cookie,
                )
                .await;
                assert_eq!(create.0, 200, "{}", create.1);
                let body = json!({"client_id":"client","grant_type":"urn:ietf:params:oauth:grant-type:device_code","device_code":create.1["device_code"]});
                let poll = request(&auth, "/device/token", Some(body.clone()), &cookie).await;
                assert_eq!(poll.0, 400);
                assert_eq!(poll.1["error"], "authorization_pending");
                let poll = request(&auth, "/device/token", Some(body), &cookie).await;
                assert_eq!(poll.0, 400);
                assert_eq!(poll.1["error"], "slow_down");
            }
            "twoFactor" => {
                for _ in 0..2 {
                    let enable = request(
                        &auth,
                        "/two-factor/enable",
                        Some(json!({"password":"long-enough-password"})),
                        &cookie,
                    )
                    .await;
                    assert_eq!(enable.0, 200, "{}", enable.1);
                    assert_eq!(enable.1["backupCodes"].as_array().unwrap().len(), 10);
                }
            }
            _ => {
                let create = request(
                    &auth,
                    "/organization/create",
                    Some(json!({"name":"Org","slug":"org"})),
                    &cookie,
                )
                .await;
                assert_eq!(create.0, 200, "{model}: {}", create.1);
                assert_eq!(create.1.get("id").is_none(), model == "organization");
                assert_eq!(
                    create.1["members"][0].get("id").is_none(),
                    model == "member"
                );
                if model == "team" || model == "teamMember" {
                    let team = request(
                        &auth,
                        "/organization/create-team",
                        Some(json!({"name":"Second","organizationId":create.1["id"]})),
                        &cookie,
                    )
                    .await;
                    assert_eq!(team.0, 200, "{model}: {}", team.1);
                    assert_eq!(team.1.get("id").is_none(), model == "team");
                }
                if model == "organizationRole" {
                    let role=request(&auth,"/organization/create-role",Some(json!({"organizationId":create.1["id"],"role":"custom","permission":{"invitation":["create"]}})),&cookie).await;
                    assert_eq!(role.0, 200, "{}", role.1);
                    assert!(role.1["roleData"].get("id").is_none());
                }
                if model == "invitation" {
                    let invitation=request(&auth,"/organization/invite-member",Some(json!({"email":"invite@example.com","role":"member","organizationId":create.1["id"]})),&cookie).await;
                    assert_eq!(invitation.0, 200, "{}", invitation.1);
                    assert!(invitation.1.get("id").is_none());
                }
            }
        }
    }
}
