use better_auth::{
    AuthBuilder, AuthConfig, AuthResult,
    plugins::oauth::{
        OAuthIdTokenVerifier, OAuthPlugin, OAuthProvider, OAuthUserInfo, OAuthUserInfoHandler,
        OAuthUserInfoRequest, OAuthUserInfoResponse,
    },
};
use better_auth_core::{
    AuthRequest, AuthUser, BaseUrl, CreateUser, DynamicBaseUrl, HttpMethod, TrustedValues,
    TrustedValuesResolver, middleware::RateLimitConfig,
};
use better_auth_seaorm::{
    Database, SeaOrmStore,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use serde_json::{Value, json};
use std::sync::Arc;
struct Provider;
#[async_trait::async_trait]
impl TrustedValuesResolver for Provider {
    async fn resolve(&self, request: Option<&AuthRequest>) -> AuthResult<Vec<String>> {
        Ok(
            if request
                .and_then(|r| r.headers.get("host"))
                .map(String::as_str)
                == Some("a.tenant.test")
            {
                vec!["google".into()]
            } else {
                vec![]
            },
        )
    }
}
#[async_trait::async_trait]
impl OAuthIdTokenVerifier for Provider {
    async fn verify_id_token(&self, _: &str, _: Option<&str>) -> Result<bool, String> {
        Ok(true)
    }
}
#[async_trait::async_trait]
impl OAuthUserInfoHandler for Provider {
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        let data: Value = serde_json::from_str(request.id_token.as_deref().unwrap()).unwrap();
        Ok(Some(OAuthUserInfoResponse {
            user: OAuthUserInfo {
                id: data["id"].as_str().unwrap().into(),
                email: Some(data["email"].as_str().unwrap().into()).into(),
                name: data["name"].as_str().map(str::to_owned),
                image: None,
                email_verified: Some(false).into(),
                additional_fields: Default::default(),
            },
            data,
        }))
    }
}
pub async fn run() -> AuthResult<Value> {
    let mut config = AuthConfig::new("dynamic-oauth-fixture-secret-at-least-thirty-two-characters");
    config.base_url = BaseUrl::Dynamic(DynamicBaseUrl {
        allowed_hosts: vec!["*.tenant.test".into()],
        fallback: None,
        protocol: None,
    });
    config.account.account_linking.trusted_providers =
        Some(TrustedValues::Dynamic(Arc::new(Provider)));
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    let store = SeaOrmStore::<BundledSchema>::new(config.clone(), database);
    let mut provider = OAuthProvider::google("fixture-google", "fixture-secret");
    provider.verify_id_token = Some(Arc::new(Provider));
    provider.get_user_info = Some(Arc::new(Provider));
    let auth = AuthBuilder::new(config)
        .store(store)
        .rate_limit(RateLimitConfig::new().enabled(false))
        .plugin(OAuthPlugin::new().add_provider("google", provider))
        .build()
        .await?;
    let mut results = Vec::new();
    for tenant in ["b", "a"] {
        let email = format!("{tenant}@tenant.test");
        let mut input = CreateUser::new().with_email(&email).with_name(tenant);
        input.email_verified = Some(true);
        let user = auth.store().create_user(input).await?;
        let request = |body: Value| {
            let url = url::Url::parse(&format!(
                "https://{tenant}.tenant.test/api/auth/sign-in/social"
            ))
            .unwrap();
            let mut request = AuthRequest::new(HttpMethod::Post, url.path()).with_url(url);
            request
                .headers
                .insert("host".into(), format!("{tenant}.tenant.test"));
            request
                .headers
                .insert("content-type".into(), "application/json".into());
            request.body = Some(serde_json::to_vec(&body).unwrap());
            request
        };
        let response=auth.handle_request(request(json!({"provider":"google","idToken":{"token":json!({"id":format!("provider-{tenant}"),"email":email,"name":tenant,"emailVerified":false}).to_string()}}))).await?;
        let body: Value = serde_json::from_slice(&response.body)?;
        let accounts = auth
            .store()
            .get_user_accounts(user.id().typed().unwrap())
            .await?;
        let authorization=auth.handle_request(request(json!({"provider":"google","callbackURL":format!("https://{tenant}.tenant.test/done"),"disableRedirect":true}))).await?;
        let data: Value = serde_json::from_slice(&authorization.body)?;
        let url = url::Url::parse(data["url"].as_str().unwrap()).unwrap();
        let query = url
            .query_pairs()
            .collect::<std::collections::HashMap<_, _>>();
        let state = query.get("state").unwrap();
        let stored = auth.store().get_verification_by_identifier(state).await?;
        let payload: Option<Value> = stored
            .as_ref()
            .map(|row| {
                serde_json::from_str(&row.value.display_string()?)
                    .map_err(better_auth::AuthError::from)
            })
            .transpose()?;
        results.push(json!({"tenant":tenant,"status":response.status,"error":body.get("message"),"signedIn":body.get("token").is_some_and(|v|!v.is_null()),"accounts":accounts.iter().map(|row|json!({"providerId":row.provider_id,"accountId":row.account_id,"sameUser":row.user_id==user.id().into_owned()})).collect::<Vec<_>>(),"redirectURI":query.get("redirect_uri"),"statePersisted":stored.is_some(),"stateCallback":payload.as_ref().and_then(|p|p.get("callbackURL")),"stateBound":payload.as_ref().and_then(|p|p.get("oauthState")).and_then(Value::as_str)==Some(state.as_ref())}));
    }
    Ok(json!(results))
}
