use super::super::{
    GenericOAuthConfig, GenericOAuthUserInfoHandler, OAuthPlugin, OAuthUserInfoRequest,
};
use super::{MutableProfile, Provider, sign_in, test_helpers};
use crate::plugins::endpoint_context::EndpointContext;
use crate::plugins::user_admission::{
    UserValidationData, UserValidationRejection, ValidateUserInfo,
};
use async_trait::async_trait;
use better_auth_core::{AuthResult, AuthSchema, AuthUser, UpdateUser};
use better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct AdmissionRecords(Mutex<Vec<Value>>);

#[async_trait]
impl<S: AuthSchema> ValidateUserInfo<S> for AdmissionRecords {
    async fn validate(
        &self,
        data: &UserValidationData,
        _: &EndpointContext<'_, S>,
    ) -> AuthResult<Option<UserValidationRejection>> {
        self.0.lock().unwrap().push(json!({
            "name": data.user.get("name"),
            "source": data.source,
        }));
        Ok(None)
    }
}

#[tokio::test]
async fn callback_names_normalize_for_storage_and_admission_without_changing_raw_profiles()
-> Result<(), Box<dyn std::error::Error>> {
    for override_user_info in [false, true] {
        for (name, expected_name) in [
            (None, ""),
            (Some(Value::Null), ""),
            (Some(json!("")), ""),
            (Some(json!("Profile Reader")), "Profile Reader"),
        ] {
            let mut raw = json!({
                "id": "ordinary-name-subject",
                "email": "name@example.test",
                "emailVerified": true,
            });
            if let Some(name) = name {
                raw["name"] = name;
            }
            let profile = Arc::new(MutableProfile(Mutex::new(raw.clone())));
            let plugin = OAuthPlugin::new().add_generic_provider(
                "generic",
                GenericOAuthConfig {
                    client_id: "client".into(),
                    authorization_url: Some("https://provider.example/authorize".into()),
                    get_token: Some(Arc::new(Provider)),
                    get_user_info: Some(profile.clone()),
                    override_user_info,
                    ..Default::default()
                },
            );
            let mut config = test_helpers::create_test_config();
            config.account.skip_state_cookie_check = true;
            let mut ctx = test_helpers::create_test_context_with_config(config).await;
            let records = Arc::new(AdmissionRecords::default());
            let admission: Arc<dyn ValidateUserInfo<BundledSchema>> = records.clone();
            ctx.extensions.insert(admission);

            let first = sign_in(&plugin, &ctx).await;
            assert_eq!(first.status, 302);
            assert_eq!(
                first.headers.get("Location").map(String::as_str),
                Some("http://localhost:3000/welcome"),
            );
            let registered = ctx
                .database
                .get_user_by_email("name@example.test")
                .await?
                .ok_or("missing registered user")?;
            assert_eq!(
                serde_json::to_value(ctx.user_view(&registered).await?)?["name"],
                expected_name
            );
            let id = registered.id().typed()?.to_string();
            let _ = ctx
                .database
                .update_user(
                    &id,
                    UpdateUser {
                        name: Some("Previously stored".to_owned()).into(),
                        ..Default::default()
                    },
                )
                .await?;

            let second = sign_in(&plugin, &ctx).await;
            assert_eq!(second.status, 302);
            assert_eq!(
                second.headers.get("Location").map(String::as_str),
                Some("http://localhost:3000/welcome"),
            );
            let stored = ctx
                .database
                .get_user_by_email("name@example.test")
                .await?
                .ok_or("missing stored user")?;
            assert_eq!(stored.id().typed()?.as_ref(), id.as_str());
            let expected_stored = if override_user_info {
                expected_name
            } else {
                "Previously stored"
            };
            assert_eq!(
                serde_json::to_value(ctx.user_view(&stored).await?)?["name"],
                expected_stored
            );
            let expected: Vec<_> = ["create-user", "sign-in"]
                .into_iter()
                .map(|action| {
                    json!({
                        "name": expected_name,
                        "source": {
                            "action": action,
                            "method": "oauth",
                            "oauth": { "providerId": "generic", "profile": raw },
                        },
                    })
                })
                .collect();
            assert_eq!(*records.0.lock().unwrap(), expected);
            assert_eq!(
                profile
                    .get_user_info(&OAuthUserInfoRequest::default())
                    .await?
                    .ok_or("missing ordinary profile")?,
                raw
            );
        }
    }
    Ok(())
}
