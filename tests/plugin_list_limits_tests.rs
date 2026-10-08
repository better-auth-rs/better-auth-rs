#![cfg(feature = "seaorm2")]

use std::{collections::HashMap, sync::Arc};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth::plugins::{
    JwtAlgorithm, JwtKeyPairConfig, JwtPlugin, JwtPluginConfig, PasskeyPlugin,
};
use better_auth::server_api::EndpointInput;
use better_auth::{AuthConfig, AuthError, AuthResult, AuthSchema, BetterAuth};
use better_auth_core::store::{EphemeralStore, RuntimeStore};
use better_auth_core::utils::cookie_utils::sign_cookie_value;
use better_auth_core::{
    AuthStore, CreateJwk, CreatePasskey, CreateSession, CreateUser, HttpMethod, Jwk,
};
use better_auth_seaorm::store::__private_test_support::{bundled_schema::BundledSchema, migrator};
use better_auth_seaorm::{SeaOrmStore, sea_orm::Database};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

const SECRET: &str = "plugin-list-limit-secret-at-least-32-characters";
fn jwt() -> JwtPlugin {
    JwtPlugin::with_config(JwtPluginConfig {
        disable_private_key_encryption: true,
        ..Default::default()
    })
}
fn date(value: &str) -> AuthResult<DateTime<Utc>> {
    value
        .parse()
        .map_err(|error: chrono::ParseError| AuthError::internal(error.to_string()))
}
async fn run<S: AuthSchema>(
    config: AuthConfig,
    store: Arc<dyn AuthStore<S>>,
    material: &Jwk,
    case: &Value,
) -> AuthResult<Value> {
    let auth = BetterAuth::new(config)
        .store_arc(store.clone())
        .plugin(PasskeyPlugin::new())
        .plugin(jwt())
        .build()
        .await?;
    let user = store
        .create_user(
            CreateUser::new()
                .with_name("Owner")
                .with_email("owner@lists.test"),
        )
        .await?;
    let session = store
        .create_session(CreateSession {
            inherited_fields: Default::default(),
            additional_fields: Default::default(),
            user_id: user.id.clone(),
            expires_at: date("2099-01-01T00:00:00Z")?.into(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?;
    let mut names = HashMap::new();
    for (index, name) in ["first", "second", "third"].into_iter().enumerate() {
        let _ = store
            .create_passkey(CreatePasskey {
                additional_fields: Default::default(),
                user_id: user.id.typed()?.clone(),
                name: Some(name.into()).into(),
                credential_id: URL_SAFE_NO_PAD.encode(name),
                public_key: "fixture-public-key".into(),
                counter: 0,
                device_type: "singleDevice".into(),
                backed_up: false,
                transports: None,
                credential: "fixture-credential".into(),
                aaguid: None.into(),
            })
            .await?;
        let key = store
            .create_jwk(CreateJwk {
                additional_fields: Default::default(),
                public_key: material.public_key.typed()?.clone(),
                private_key: material.private_key.typed()?.clone(),
                created_at: date(&format!("{}-01-01T00:00:00Z", 2000 + index))?.into(),
                expires_at: Some(
                    date(if index == 0 {
                        "2001-01-01T00:00:00Z"
                    } else {
                        "2099-01-01T00:00:00Z"
                    })?
                    .into(),
                ),
                alg: "EdDSA".into(),
                crv: Some("Ed25519".into()),
            })
            .await?;
        let _ = names.insert(key.id.typed()?.clone(), name);
    }
    let response = auth
        .call_endpoint(
            HttpMethod::Get,
            "/passkey/list-user-passkeys",
            EndpointInput {
                headers: Some(HashMap::from([(
                    "cookie".into(),
                    format!(
                        "better-auth.session_token={}",
                        sign_cookie_value(session.token.typed()?, SECRET)
                    ),
                )])),
                ..Default::default()
            },
        )
        .await?;
    let passkeys: Vec<Value> = serde_json::from_slice(&response.body.bytes()?)?;
    let keys = store.list_jwks().await?;
    let signed = auth
        .jwt()?
        .sign(serde_json::Map::from_iter([(
            "sub".into(),
            json!("fixture"),
        )]))
        .await?;
    let encoded_header = signed
        .split('.')
        .next()
        .ok_or_else(|| AuthError::internal("JWT header is absent"))?;
    let header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(encoded_header)
            .map_err(|error| AuthError::internal(error.to_string()))?,
    )?;
    let kid = header["kid"]
        .as_str()
        .ok_or_else(|| AuthError::internal("JWT kid is absent"))?;
    let key_names = keys
        .iter()
        .map(|key| Ok(names.get(key.id.typed()?).copied()))
        .collect::<AuthResult<Vec<_>>>()?;
    Ok(json!({"backend":case["backend"],"limit":case["limit"],
        "passkeys":passkeys.iter().map(|key| &key["name"]).collect::<Vec<_>>(),
        "keys":key_names,"selected":names.get(kid).copied().unwrap_or("generated")}))
}

#[tokio::test]
async fn passkey_lists_and_jwt_key_selection_apply_upstream_query_limits() -> AuthResult<()> {
    let seed = BetterAuth::new(AuthConfig::new(SECRET).base_url("http://lists.test"))
        .store(EphemeralStore::default())
        .plugin(jwt())
        .build()
        .await?;
    let material = seed
        .jwt()?
        .create_key_pair(JwtKeyPairConfig::new(JwtAlgorithm::EdDsa))
        .await?
        .ok_or_else(|| AuthError::internal("Expected created fixture key"))?;
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/plugin-list-limits-upstream.json"))?;
    for case in cases {
        let mut config = AuthConfig::new(SECRET).base_url("http://lists.test");
        config.logger.disabled = Some(true);
        config.advanced.database.default_find_many_limit = case["limit"].as_f64();
        let actual =
            if case["backend"] == "sqlite" {
                let database = Database::connect("sqlite::memory:")
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                migrator::run_migrations(&database)
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                let store = SeaOrmStore::<BundledSchema>::new(config.clone(), database)
                    .with_runtime(Arc::new(config.clone()), Vec::new(), Default::default())?;
                run(config, store, &material, &case).await?
            } else {
                let store = EphemeralStore::default().with_runtime(
                    Arc::new(config.clone()),
                    Vec::new(),
                    Default::default(),
                )?;
                run(config, store, &material, &case).await?
            };
        assert_eq!(actual, case);
    }
    Ok(())
}
