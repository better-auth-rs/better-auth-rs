use super::google_test_support::GoogleFixture;
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::AuthError;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{error::Error, sync::mpsc};

pub(super) type TestResult<T> = Result<T, Box<dyn Error>>;

pub(super) fn fixture() -> TestResult<Value> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/social-apple-1.7.6.json");
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

pub(super) fn text<'a>(value: &'a Value, path: &str) -> TestResult<&'a str> {
    value
        .pointer(path)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Missing Apple fixture string: {path}").into())
}

pub(super) fn rows<'a>(value: &'a Value, path: &str) -> TestResult<&'a [Value]> {
    value
        .pointer(path)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| format!("Missing Apple fixture rows: {path}").into())
}

pub(super) fn normalized(mut value: Value) -> Value {
    match &mut value {
        Value::Object(fields) => {
            for (name, value) in fields {
                *value = match name.as_str() {
                    "iat" => json!("<issued-at>"),
                    "exp" => json!("<expiry>"),
                    _ => normalized(value.take()),
                };
            }
        }
        Value::Array(values) => {
            for value in values {
                *value = normalized(value.take());
            }
        }
        _ => {}
    }
    value
}

pub(super) fn configured(
    fixture: &Value,
    options: &Value,
    server: Option<&GoogleFixture>,
) -> TestResult<OAuthProvider> {
    let clients = options
        .get("clientId")
        .map(|value| serde_json::from_value::<Vec<String>>(value.clone()))
        .transpose()?;
    let client_id = clients
        .as_ref()
        .and_then(|values| values.first())
        .map(String::as_str)
        .unwrap_or(text(fixture, "/metadata/clientId")?);
    let mut config = OAuthProvider::apple(
        client_id,
        text(fixture, "/metadata/clientSecret")?,
        AppleOptions {
            audience: options
                .get("audience")
                .cloned()
                .map(serde_json::from_value)
                .transpose()?,
            app_bundle_identifier: options
                .get("appBundleIdentifier")
                .and_then(Value::as_str)
                .map(str::to_owned),
            additional_client_ids: clients
                .as_ref()
                .map(|values| values.iter().skip(1).cloned().collect())
                .unwrap_or_default(),
            jwks_url: server.map(|server| format!("{}/jwks", server.url)),
        },
    );
    config.scopes = options
        .get("scope")
        .cloned()
        .map(serde_json::from_value)
        .transpose()?;
    config.disable_default_scope = options
        .get("disableDefaultScope")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    config.redirect_uri = options
        .get("redirectURI")
        .and_then(Value::as_str)
        .map(str::to_owned);
    config.prompt = options
        .get("prompt")
        .and_then(Value::as_str)
        .map(str::to_owned);
    config.client_key = options
        .get("clientKey")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let Some(endpoint) = options.get("authorizationEndpoint").and_then(Value::as_str) {
        config.auth_url = endpoint.into();
    }
    if let Some(server) = server {
        config.token_url = format!("{}/token", server.url);
    }
    Ok(config)
}

pub(super) struct Mapper {
    pub(super) patch: Value,
    pub(super) seen: mpsc::Sender<Value>,
    pub(super) calls: mpsc::Sender<&'static str>,
}

#[async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(&self, profile: &Value) -> AuthResult<OAuthProfile> {
        self.seen
            .send(normalized(profile.clone()))
            .map_err(|error| AuthError::internal(error.to_string()))?;
        self.calls
            .send("map")
            .map_err(|error| AuthError::internal(error.to_string()))?;
        Ok(OAuthProfile {
            name: self
                .patch
                .get("name")
                .cloned()
                .map(serde_json::from_value::<Option<String>>)
                .transpose()
                .map_err(|error| AuthError::internal(error.to_string()))?
                .map(Into::into),
            email: self
                .patch
                .get("email")
                .cloned()
                .map(serde_json::from_value::<Option<String>>)
                .transpose()
                .map_err(|error| AuthError::internal(error.to_string()))?
                .map(Into::into),
            image: self
                .patch
                .get("image")
                .cloned()
                .map(serde_json::from_value)
                .transpose()
                .map_err(|error| AuthError::internal(error.to_string()))?,
            email_verified: self
                .patch
                .get("emailVerified")
                .cloned()
                .map(serde_json::from_value::<Option<bool>>)
                .transpose()
                .map_err(|error| AuthError::internal(error.to_string()))?
                .map(Into::into),
            ..Default::default()
        })
    }
}

struct Custom {
    response: OAuthUserInfoResponse,
    calls: mpsc::Sender<&'static str>,
}

#[async_trait]
impl OAuthUserInfoHandler for Custom {
    async fn get_user_info(
        &self,
        _request: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        self.calls
            .send("get")
            .map_err(|error| AuthError::internal(error.to_string()))?;
        Ok(Some(self.response.clone()))
    }
}

fn public_response(response: OAuthUserInfoResponse, custom: bool) -> Value {
    let user = response.user;
    json!({ "user": types::AccountInfoUser {
        id: custom.then_some(user.id), name: user.name, email: user.email, image: user.image,
        email_verified: user.email_verified, additional_fields: user.additional_fields,
    }, "data": response.data })
}

#[test]
fn apple_authorization_matches_the_pinned_complete_urls() -> TestResult<()> {
    let fixture = fixture()?;
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(
        text(&fixture, "/metadata/codeVerifier")?.as_bytes(),
    ));
    for sample in rows(&fixture, "/authorization")? {
        let config = configured(
            &fixture,
            sample.get("options").ok_or("Missing options")?,
            None,
        )?;
        let scopes: Option<Vec<String>> = sample
            .get("scopes")
            .cloned()
            .map(serde_json::from_value)
            .transpose()?;
        let additional: Option<indexmap::IndexMap<String, String>> = sample
            .get("additionalParams")
            .cloned()
            .map(serde_json::from_value)
            .transpose()?;
        let url = authorization::build_authorization_url(
            &resolved::ResolvedProvider {
                config,
                generic: None,
            },
            authorization::AuthorizationRequest {
                callback_url: text(&fixture, "/metadata/callbackURL")?,
                scopes: scopes.as_deref(),
                state: "ordinary-state",
                code_challenge: &challenge,
                login_hint: Some("ignored@example.test"),
                nonce: Some("ordinary-nonce"),
                additional_params: additional.as_ref(),
            },
        )?;
        assert_eq!(url, text(sample, "/url")?, "{}", text(sample, "/name")?);
    }
    Ok(())
}

#[cfg(feature = "axum")]
#[tokio::test]
async fn apple_code_and_refresh_match_the_pinned_wire_contract() -> TestResult<()> {
    let fixture = fixture()?;
    for sample in rows(&fixture, "/grants")? {
        let config = configured(
            &fixture,
            sample.get("options").ok_or("Missing options")?,
            None,
        )?;
        let (requests, tokens) = social_token_wire_tests::grants(
            config,
            text(&fixture, "/metadata/callbackURL")?,
            text(&fixture, "/metadata/codeVerifier")?,
            fixture
                .get("tokenResponse")
                .ok_or("Missing token response")?
                .clone(),
        )
        .await?;
        assert_eq!(
            json!(requests),
            *sample.get("requests").ok_or("Missing requests")?
        );
        assert_eq!(tokens, *sample.get("tokens").ok_or("Missing tokens")?);
    }
    Ok(())
}

#[tokio::test]
async fn apple_signed_profiles_preserve_callback_names_mapper_precedence_and_data() -> TestResult<()>
{
    let fixture = fixture()?;
    for sample in rows(&fixture, "/profiles")? {
        let server =
            GoogleFixture::start(sample.get("claims").ok_or("Missing claims")?.clone()).await;
        let (seen, captured) = mpsc::channel();
        let (calls, called) = mpsc::channel();
        let mut config = configured(&fixture, &json!({}), Some(&server))?;
        if let Some(patch) = sample.get("patch") {
            config.map_profile_to_user = Some(Arc::new(Mapper {
                patch: patch.clone(),
                seen,
                calls: calls.clone(),
            }));
        }
        if let Some(custom) = sample.get("custom") {
            config.get_user_info = Some(Arc::new(Custom {
                calls,
                response: OAuthUserInfoResponse {
                    user: OAuthUserInfo {
                        id: text(custom, "/user/id")?.into(),
                        name: Some(text(custom, "/user/name")?.to_owned()).into(),
                        email: Some(text(custom, "/user/email")?.to_owned()).into(),
                        image: Some(None),
                        email_verified: Some(true).into(),
                        additional_fields: Default::default(),
                    },
                    data: custom.get("data").ok_or("Missing custom data")?.clone(),
                },
            }));
        }
        let response = social_profile::fetch_user_info_for_code(
            &resolved::ResolvedProvider {
                config: config.resolve(),
                generic: None,
            },
            OAuthUserInfoRequest {
                id_token: Some(server.token.clone()),
                user: sample
                    .get("user")
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()?,
                ..Default::default()
            },
            None,
        )
        .await?
        .ok_or("Missing Apple profile")?;
        assert_eq!(response.user.id, text(sample, "/subject")?);
        assert_eq!(
            normalized(public_response(response, sample.get("custom").is_some())),
            *sample.get("result").ok_or("Missing result")?,
            "{}",
            text(sample, "/name")?
        );
        assert_eq!(
            json!(captured.try_iter().collect::<Vec<_>>()),
            *sample.get("mapperInputs").ok_or("Missing mapper inputs")?
        );
        assert_eq!(
            json!(called.try_iter().collect::<Vec<_>>()),
            *sample.get("calls").ok_or("Missing calls")?
        );
        assert_eq!(
            json!(*server.requests.lock().map_err(|error| error.to_string())?),
            *sample.get("requests").ok_or("Missing requests")?
        );
    }
    Ok(())
}

#[tokio::test]
async fn apple_valid_signed_tokens_use_audience_precedence_and_both_nonce_forms() -> TestResult<()>
{
    let fixture = fixture()?;
    for sample in rows(&fixture, "/verification")? {
        let server =
            GoogleFixture::start(sample.get("claims").ok_or("Missing claims")?.clone()).await;
        let config = configured(
            &fixture,
            sample.get("options").ok_or("Missing options")?,
            Some(&server),
        )?;
        assert_eq!(
            json!(
                config
                    .apple_options()
                    .ok_or("Missing Apple options")?
                    .audiences(&config.client_id)
            ),
            *sample.get("audiences").ok_or("Missing audiences")?
        );
        let provider = resolved::ResolvedProvider {
            config,
            generic: None,
        };
        let request = types::OAuthIdTokenRequest {
            token: server.token.clone(),
            nonce: sample
                .get("nonce")
                .and_then(Value::as_str)
                .map(str::to_owned),
            access_token: None,
            refresh_token: None,
            user: None,
        };
        let verified = id_token::verify(&provider, &request, None).await?;
        assert_eq!(
            json!(verified.is_some()),
            *sample.get("accepted").ok_or("Missing acceptance")?
        );
        let response = social_profile::fetch_user_info_with_claims(
            &provider,
            OAuthUserInfoRequest {
                id_token: Some(server.token.clone()),
                ..Default::default()
            },
            request.nonce.as_deref(),
            verified,
        )
        .await?
        .ok_or("Missing verified Apple profile")?;
        let mut expected = sample.get("claims").ok_or("Missing claims")?.clone();
        let fields = expected.as_object_mut().ok_or("Claims must be an object")?;
        let _ = fields.insert("iat".into(), json!("<issued-at>"));
        let _ = fields.insert("exp".into(), json!("<expiry>"));
        assert_eq!(normalized(response.data), expected);
        assert_eq!(
            *server.requests.lock().map_err(|error| error.to_string())?,
            ["/jwks"]
        );
        assert_eq!(
            *sample.get("requests").ok_or("Missing requests")?,
            json!(["/auth/keys"])
        );
    }
    Ok(())
}
