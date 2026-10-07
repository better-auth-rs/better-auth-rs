use better_auth::plugins::EmailPasswordPlugin;
use better_auth::{AuthConfig, AuthError, AuthResult, BetterAuth, PasswordHasher};
use better_auth_core::{
    CreateAccount, CreateUser, UpdateUser,
    store::{AccountStore, EphemeralStore, UserStore},
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[path = "common/id_runtime.rs"]
mod support;
use support::{Hasher, request};

#[tokio::test]
async fn email_signin_preserves_the_selected_user_without_repeating_output() -> AuthResult<()> {
    let password = "long-enough-password";
    for joins in [false, true] {
        let mut config = AuthConfig::new("signin-snapshot-secret-at-least-thirty-two-characters")
            .base_url("http://localhost:3000");
        config.advanced.database.joins = Some(joins);
        let raw = Arc::new(EphemeralStore::new(Arc::new(config.clone())));
        let _ = raw
            .create_user(CreateUser {
                id: Some("snapshot-user".into()),
                name: Some("Original name".into()).into(),
                email: Some("snapshot@example.test".into()),
                email_verified: Some(true),
                ..Default::default()
            })
            .await?;
        let _ = raw
            .create_account(CreateAccount {
                user_id: "snapshot-user".into(),
                account_id: "snapshot-user".into(),
                provider_id: "credential".into(),
                password: Some(Hasher.hash(password).await?).into(),
                ..Default::default()
            })
            .await?;

        let outputs = Arc::new(AtomicUsize::new(0));
        let calls = outputs.clone();
        let _ = config.user.fields_mut().insert(
            "name".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |value| {
                        let _ = calls.fetch_add(1, Ordering::SeqCst);
                        let name = value
                            .as_str()
                            .ok_or_else(|| AuthError::internal("Expected a User name"))?;
                        Ok(format!("selected:{name}").into())
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let writer = raw.clone();
        let _ = config.account.additional_fields.insert(
            "accountId".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new_async(move |value| {
                        let writer = writer.clone();
                        async move {
                            // The credential output runs after the join has selected and projected its User.
                            let _ = writer
                                .update_user(
                                    "snapshot-user",
                                    UpdateUser {
                                        name: Some("Changed during Account output".into()).into(),
                                        ..Default::default()
                                    },
                                )
                                .await?;
                            Ok(value)
                        }
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let auth = BetterAuth::stateless(config)
            .store_arc(raw.clone())
            .plugin(EmailPasswordPlugin::new().password_hasher(Arc::new(Hasher)))
            .build()
            .await?;
        let (status, body, _) = request(
            &auth,
            "/sign-in/email",
            Some(json!({"email": "snapshot@example.test", "password": password})),
            "",
        )
        .await;

        assert_eq!(status, 200, "joins={joins}: {body}");
        assert_eq!(
            body.pointer("/user/name"),
            Some(&json!("selected:Original name")),
            "joins={joins}"
        );
        assert_eq!(outputs.load(Ordering::SeqCst), 1, "joins={joins}");
        let stored = raw
            .get_user_by_id("snapshot-user")
            .await?
            .ok_or_else(|| AuthError::internal("Expected the stored User"))?;
        assert_eq!(
            stored.name.json()?,
            Some(json!("Changed during Account output")),
            "joins={joins}"
        );
    }
    Ok(())
}
