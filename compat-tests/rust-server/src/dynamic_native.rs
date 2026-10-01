use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use better_auth::plugins::{
    EmailPasswordPlugin,
    admin::{AdminPlugin, CreateAdminUser},
    api_key::ApiKeyPlugin,
    email_otp::{EmailOtpCallbacks, EmailOtpPlugin, EmailOtpType},
    endpoint_context::EndpointContext,
    user_admission::{UserValidationData, UserValidationRejection, ValidateUserInfo},
};
use better_auth::server_api::{CreateKeyOptions, UpdateKeyOptions, VerifyKeyOptions};
use better_auth::{AuthBuilder, AuthConfig, AuthResult, BetterAuth};
use better_auth_core::{
    AuthRequest, AuthUser, CreateUser, HttpMethod,
    middleware::RateLimitConfig,
    request_runtime::{BaseUrl, DynamicBaseUrl, TrustedValues, TrustedValuesResolver},
};
use better_auth_seaorm::{
    Database, SeaOrmStore,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use serde_json::{Value, json};

#[derive(Clone)]
struct Probe {
    events: Arc<Mutex<Vec<Value>>>,
    scenario: String,
}

#[async_trait]
impl TrustedValuesResolver for Probe {
    async fn resolve(&self, request: Option<&AuthRequest>) -> AuthResult<Vec<String>> {
        self.events.lock().unwrap().push(json!({"event":"origins","host":request.and_then(|request|request.headers.get("host"))}));
        Ok(vec!["https://alpha.auth.test".into()])
    }
}

#[async_trait]
impl ValidateUserInfo<BundledSchema> for Probe {
    async fn validate(
        &self,
        data: &UserValidationData,
        endpoint: &EndpointContext<'_, BundledSchema>,
    ) -> AuthResult<Option<UserValidationRejection>> {
        if !self.scenario.starts_with("transaction-") {
            return Ok(None);
        }
        let email = data.user["email"].as_str().unwrap();
        let api = endpoint.email_otp()?;
        let before = api.get(email, EmailOtpType::SignIn).await?;
        let created = api.create(email, EmailOtpType::SignIn).await?;
        let after = api.get(email, EmailOtpType::SignIn).await?;
        self.events
            .lock()
            .unwrap()
            .push(json!({"event":"admission","before":before,"created":created,"after":after}));
        Ok((self.scenario == "transaction-deny")
            .then(|| UserValidationRejection::new("fixture_denied")))
    }
}

fn result<T: serde::Serialize>(calls: &mut Vec<Value>, op: &str, value: AuthResult<T>) {
    calls.push(match value {
        Ok(value) => json!({"op":op,"ok":true,"value":value}),
        Err(_) => json!({"op":op,"ok":false}),
    });
}

pub async fn run(input: Value) -> AuthResult<Value> {
    let scenario = input["scenario"].as_str().unwrap().to_owned();
    let probe = Probe {
        events: Arc::default(),
        scenario: scenario.clone(),
    };
    let mut config =
        AuthConfig::new("dynamic-native-fixture-secret-at-least-thirty-two-characters");
    config.base_url = BaseUrl::Dynamic(DynamicBaseUrl {
        allowed_hosts: vec!["*.auth.test".into()],
        fallback: (scenario == "fallback").then(|| "https://fallback.auth.test".into()),
        protocol: None,
    });
    config.trusted_origins = Some(TrustedValues::Dynamic(Arc::new(probe.clone())));
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    let store = SeaOrmStore::<BundledSchema>::new(Arc::new(config.clone()), database);
    let events = probe.events.clone();
    let otp = EmailOtpCallbacks::<BundledSchema>::default().generate(move |_, _, endpoint| {
        events
            .lock()
            .unwrap()
            .push(json!({"event":"generate","baseURL":endpoint.auth.base_url()}));
        Ok(Some("123456".into()))
    });
    let auth: BetterAuth<BundledSchema> = AuthBuilder::new(config)
        .store(store)
        .rate_limit(RateLimitConfig::new().enabled(false))
        .validate_user_info(Arc::new(probe.clone()))
        .plugin(AdminPlugin::new())
        .plugin(ApiKeyPlugin::builder().build())
        .plugin(EmailOtpPlugin::new().callbacks(otp))
        .plugin(EmailPasswordPlugin::new().password_hasher(Arc::new(super::jwt_adapter::Hasher)))
        .build()
        .await?;
    let seed = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_email("seed@example.com")
                .with_name("Seed"),
        )
        .await?;
    probe.events.lock().unwrap().clear();
    let mut calls = Vec::new();
    let body = CreateAdminUser {
        email: "admin@example.com".into(),
        name: "Admin".into(),
        password: None,
        role: None,
        data: None,
    };
    if scenario.starts_with("transaction-") {
        let mut request = AuthRequest::new(HttpMethod::Post, "/api/auth/sign-up/email")
            .with_url(url::Url::parse("https://alpha.auth.test/api/auth/sign-up/email").unwrap());
        request
            .headers
            .insert("host".into(), "alpha.auth.test".into());
        request
            .headers
            .insert("origin".into(), "https://alpha.auth.test".into());
        request
            .headers
            .insert("content-type".into(), "application/json".into());
        request.body = Some(serde_json::to_vec(
            &json!({"name":"Signup","email":"signup@example.com","password":"fixture-password"}),
        )?);
        let response = auth.handle_request(request).await?;
        calls.push(json!({"op":"signup","ok":(200..300).contains(&response.status),"status":response.status}));
    } else if scenario == "headers" {
        let headers = HashMap::from([("host".into(), "alpha.auth.test".into())]);
        result(
            &mut calls,
            "admin",
            auth.admin()?
                .create_user(&body, Some(&headers))
                .await
                .map(|_| true),
        );
    } else {
        result(
            &mut calls,
            "admin",
            auth.admin()?.create_user(&body, None).await.map(|_| true),
        );
        result(
            &mut calls,
            "otp-create",
            auth.email_otp()?
                .create("native@example.com", EmailOtpType::SignIn)
                .await,
        );
        result(
            &mut calls,
            "otp-get",
            auth.email_otp()?
                .get("native@example.com", EmailOtpType::SignIn)
                .await,
        );
        let key = auth
            .api_keys()?
            .create(
                seed.id().typed().unwrap(),
                CreateKeyOptions {
                    name: Some("Native key".into()),
                    ..Default::default()
                },
            )
            .await;
        let key = match key {
            Ok(key) => {
                result(&mut calls, "key-create", Ok(key.api_key.name.clone()));
                Some(key)
            }
            Err(error) => {
                result::<Value>(&mut calls, "key-create", Err(error));
                None
            }
        };
        result(
            &mut calls,
            "key-update",
            auth.api_keys()?
                .update(
                    seed.id().typed().unwrap(),
                    key.as_ref()
                        .map_or("missing", |key| key.api_key.id.typed().unwrap()),
                    UpdateKeyOptions {
                        name: Some("Updated key".into()),
                        ..Default::default()
                    },
                )
                .await
                .map(|key| key.name),
        );
        let verified = auth
            .api_keys()?
            .verify(
                key.as_ref().map_or("missing", |key| &key.key),
                VerifyKeyOptions::default(),
            )
            .await;
        calls.push(match verified {
            Ok(_) => json!({"op":"key-verify","ok":true,"value":true}),
            Err(better_auth::plugins::api_key::ApiKeyVerificationError::Endpoint(_)) => {
                json!({"op":"key-verify","ok":false})
            }
            Err(_) => json!({"op":"key-verify","ok":true,"value":false}),
        });
    }
    let email = if scenario.starts_with("transaction-") {
        "signup@example.com"
    } else {
        "native@example.com"
    };
    let snapshot = json!({"admin":auth.store().get_user_by_email("admin@example.com").await?.is_some(),"signup":auth.store().get_user_by_email("signup@example.com").await?.is_some(),"otp":auth.store().get_verification_including_expired(&format!("sign-in-otp-{email}")).await?.is_some(),"keys":auth.store().list_api_keys_by_reference(seed.id().typed().unwrap()).await?.len()});
    Ok(json!({"calls":calls,"events":*probe.events.lock().unwrap(),"snapshot":snapshot}))
}
