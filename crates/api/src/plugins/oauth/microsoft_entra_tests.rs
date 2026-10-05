use super::*;
use crate::plugins::{oauth::*, test_helpers};
use better_auth_core::{AuthPlugin, AuthRequest, AuthUser, HttpMethod, wire::UserView};
use josekit::{jwk::Jwk, jws::JwsHeader};
use serde_json::json;
use std::sync::{Mutex, atomic::Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TENANT: &str = "AABBCCDD-1122-3344-5566-778899AABBCC";
const ISSUER: &str = "https://login.microsoftonline.com/aabbccdd-1122-3344-5566-778899aabbcc/v2.0";

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/microsoft-entra-1.7.6.json"
    ))
    .unwrap()
}

#[test]
fn entra_constructor_matches_pinned_tenant_and_endpoint_contract() {
    let expected = fixture();
    let provider = GenericOAuthConfig::microsoft_entra_id("client", "secret", TENANT).unwrap();
    assert_eq!(
        json!({
            "providerId":"microsoft-entra-id", "discoveryUrl":provider.discovery_url,
            "requireIdTokenVerification":provider.require_id_token_verification,
            "authorizationUrl":provider.authorization_url,"tokenUrl":provider.token_url,
            "userInfoUrl":provider.user_info_url,"scopes":provider.scopes
        }),
        expected["config"]
    );
    for tenant in expected["rejectedTenants"].as_array().unwrap() {
        assert!(
            GenericOAuthConfig::microsoft_entra_id("client", "secret", tenant.as_str().unwrap())
                .is_err()
        );
    }
}

struct Server {
    url: String,
    key: Jwk,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    async fn start(input: &Value) -> Self {
        let mut key = Jwk::generate_rsa_key(2048).unwrap();
        key.set_key_id("entra-normal-fixture");
        let mut public = key.to_public_key().unwrap();
        public.set_key_id("entra-normal-fixture");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let address = url.clone();
        let input = input.clone();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let logged = requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                while !bytes.windows(4).any(|part| part == b"\r\n\r\n") {
                    let mut chunk = [0; 4096];
                    let size = stream.read(&mut chunk).await.unwrap();
                    assert_ne!(size, 0);
                    bytes.extend_from_slice(&chunk[..size]);
                }
                let request = String::from_utf8(bytes).unwrap();
                let path = request.split_whitespace().nth(1).unwrap();
                logged.lock().unwrap().push(path.to_owned());
                let (status, body) = match path {
                    "/discovery" => (
                        200,
                        json!({"issuer":ISSUER,"jwks_uri":format!("{address}/jwks"),"id_token_signing_alg_values_supported":["RS256"]}),
                    ),
                    "/jwks" => (200, json!({"keys":[public]})),
                    "/userinfo" => {
                        assert!(
                            request
                                .to_lowercase()
                                .contains("authorization: bearer ordinary-access\r\n")
                        );
                        (
                            input["graphStatus"].as_u64().unwrap_or(200),
                            input["graph"].clone(),
                        )
                    }
                    _ => panic!("unexpected Entra fixture request: {path}"),
                };
                let body = body.to_string();
                let response = format!(
                    "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        Self {
            url,
            key,
            requests,
            task,
        }
    }

    fn token(&self, input: &Value, nonce: &str) -> String {
        let mut claims = input["claims"].clone();
        let now = chrono::Utc::now().timestamp();
        claims.as_object_mut().unwrap().extend([
            ("iss".into(), json!(ISSUER)),
            ("aud".into(), json!("client")),
            ("iat".into(), json!(now)),
            ("exp".into(), json!(now + 3600)),
            ("nonce".into(), json!(nonce)),
        ]);
        let mut header = JwsHeader::new();
        header.set_algorithm("RS256");
        header.set_key_id("entra-normal-fixture");
        josekit::jws::serialize_compact(
            claims.to_string().as_bytes(),
            &header,
            &josekit::jws::RS256.signer_from_jwk(&self.key).unwrap(),
        )
        .unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct TokenHandler(Mutex<OAuthTokenSet>);
#[async_trait]
impl OAuthTokenHandler for TokenHandler {
    async fn get_token(&self, _: OAuthCodeExchange<'_>) -> AuthResult<OAuthTokenSet> {
        Ok(self.0.lock().unwrap().clone())
    }
}

struct Observer {
    inner: Arc<dyn GenericOAuthUserInfoHandler>,
    calls: Arc<Mutex<Vec<&'static str>>>,
}
#[async_trait]
impl GenericOAuthUserInfoHandler for Observer {
    async fn get_user_info(&self, _: &OAuthUserInfoRequest) -> AuthResult<Value> {
        panic!("Entra must receive verified claims");
    }
    async fn get_user_info_with_context(
        &self,
        tokens: &OAuthUserInfoRequest,
        context: GenericOAuthProfileContext<'_>,
    ) -> AuthResult<Value> {
        assert_eq!(context.verified_claims().unwrap().as_value()["iss"], ISSUER);
        self.calls.lock().unwrap().push("get");
        self.inner.get_user_info_with_context(tokens, context).await
    }
}

struct Mapper {
    calls: Arc<Mutex<Vec<&'static str>>>,
    expected: Value,
}
#[async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(&self, profile: &Value) -> AuthResult<OAuthProfile> {
        self.calls.lock().unwrap().push("map");
        let mut data = profile.clone();
        for key in ["iss", "aud", "iat", "exp", "nonce"] {
            data.as_object_mut().unwrap().remove(key);
        }
        assert_eq!(data, self.expected);
        Ok(OAuthProfile {
            name: Some(Some(format!("Mapped {}", profile["name"].as_str().unwrap())).into()),
            ..Default::default()
        })
    }
}

#[tokio::test]
async fn signed_entra_direct_and_code_sign_in_verify_once_and_match_pinned_profiles() {
    for case in fixture()["results"].as_array().unwrap() {
        let input = &case["input"];
        let server = Server::start(input).await;
        let calls = Arc::new(Mutex::new(Vec::new()));
        let token_handler = Arc::new(TokenHandler(Mutex::new(OAuthTokenSet::default())));
        let mut provider =
            GenericOAuthConfig::microsoft_entra_id("client", "secret", TENANT).unwrap();
        provider.discovery_url = Some(format!("{}/discovery", server.url));
        provider.user_info_url = Some(format!("{}/userinfo", server.url));
        provider.get_user_info = Some(Arc::new(Observer {
            inner: provider.get_user_info.take().unwrap(),
            calls: calls.clone(),
        }));
        provider.get_token = Some(token_handler.clone());
        provider.map_profile_to_user = Some(Arc::new(Mapper {
            calls: calls.clone(),
            expected: case["profile"].clone(),
        }));
        let plugin = OAuthPlugin::new().add_generic_provider("microsoft-entra-id", provider);
        let mut config = test_helpers::create_test_config();
        config.account.skip_state_cookie_check = true;
        let ctx = test_helpers::create_test_context_with_config(config).await;
        let response = if case["direct"] == true {
            let mut request = AuthRequest::new(HttpMethod::Post, "/sign-in/social");
            let mut id_token =
                json!({"token":server.token(input, "ordinary-nonce"),"nonce":"ordinary-nonce"});
            if input.get("graph").is_some() {
                id_token["accessToken"] = json!("ordinary-access");
            }
            request.body = Some(
                serde_json::to_vec(&json!({"provider":"microsoft-entra-id","idToken":id_token}))
                    .unwrap(),
            );
            plugin.on_request(&request, &ctx).await.unwrap().unwrap()
        } else {
            let mut start = AuthRequest::new(HttpMethod::Post, "/sign-in/social");
            start.body = Some(serde_json::to_vec(&json!({"provider":"microsoft-entra-id","callbackURL":"http://localhost:3000/welcome","disableRedirect":true})).unwrap());
            let response = plugin.on_request(&start, &ctx).await.unwrap().unwrap();
            assert_eq!(response.status, 200);
            let body: Value = serde_json::from_slice(&response.body).unwrap();
            let url = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
            let params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
            *token_handler.0.lock().unwrap() = OAuthTokenSet {
                id_token: Some(server.token(input, &params["nonce"])),
                access_token: input.get("graph").map(|_| "ordinary-access".into()),
                ..Default::default()
            };
            let mut callback = AuthRequest::new(HttpMethod::Get, "/callback/microsoft-entra-id");
            callback.query = Some(json!({"code":"ordinary-code","state":params["state"]}));
            let response = plugin.on_request(&callback, &ctx).await.unwrap().unwrap();
            assert_eq!(
                response.headers.get("Location").map(String::as_str),
                Some("http://localhost:3000/welcome")
            );
            response
        };
        assert_eq!(json!(response.status), case["status"]);
        let resolved = plugin.resolved_config().await.unwrap();
        let verifier = resolved.providers["microsoft-entra-id"]
            .generic
            .as_ref()
            .unwrap()
            .verifier
            .as_ref()
            .unwrap();
        assert_eq!(
            verifier.verification_calls.load(Ordering::SeqCst),
            1,
            "{} direct={}",
            input["name"],
            case["direct"]
        );
        assert_eq!(json!(*calls.lock().unwrap()), case["calls"]);
        let requests = server.requests.lock().unwrap().clone();
        assert_eq!(
            requests
                .iter()
                .filter(|path| path.as_str() == "/userinfo")
                .count(),
            case["graphRequests"].as_u64().unwrap() as usize
        );
        let user = ctx
            .database
            .get_user_by_email(case["user"]["email"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap();
        let accounts = ctx
            .database
            .get_user_accounts(&user.id().display_string().unwrap())
            .await
            .unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(
            ctx.session_manager()
                .list_user_sessions(&user.id().display_string().unwrap())
                .await
                .unwrap()
                .len(),
            1
        );
        let view = serde_json::to_value(UserView::from(&user)).unwrap();
        assert_eq!(
            json!({"name":view["name"],"email":view["email"],"image":view["image"],"emailVerified":view["emailVerified"],"accountSubject":accounts[0].account_id}),
            case["user"]
        );
    }
}
