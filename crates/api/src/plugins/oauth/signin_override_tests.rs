use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    sync::{Arc, mpsc},
};

use async_trait::async_trait;
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthSchema,
    HttpMethod, ListUsersParams, UpdateUser,
};
use serde_json::{Value, json};

use super::super::{
    OAuthPlugin, OAuthProfile, OAuthProfileMapper, google_test_support::GoogleFixture,
};
use crate::plugins::test_helpers;

type TestResult<T> = Result<T, Box<dyn Error>>;
const BASE_URL: &str = "http://localhost:3000";

fn text<'a>(value: &'a Value, pointer: &str) -> TestResult<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Missing profile override fixture string: {pointer}").into())
}

fn profile(user: &Value) -> Value {
    json!({
        "name": user.get("name"), "image": user.get("image"),
        "email": user.get("email"), "emailVerified": user.get("emailVerified"),
    })
}

struct Mapper {
    name: String,
    image: String,
    seen: mpsc::Sender<Value>,
}

#[async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(&self, raw: &Value) -> AuthResult<OAuthProfile> {
        let mut normalized = raw.clone();
        let fields = normalized
            .as_object_mut()
            .ok_or_else(|| AuthError::internal("Expected ordinary Google profile object"))?;
        let _ = fields.remove("iat");
        let _ = fields.remove("exp");
        self.seen
            .send(normalized)
            .map_err(|error| AuthError::internal(error.to_string()))?;
        Ok(OAuthProfile {
            name: Some(Some(self.name.clone()).into()),
            image: Some(Some(self.image.clone())),
            ..Default::default()
        })
    }
}

async fn send(
    plugin: &OAuthPlugin,
    ctx: &AuthContext<impl AuthSchema>,
    cookies: &mut BTreeMap<String, String>,
    path: &str,
    body: Option<Value>,
) -> TestResult<AuthResponse> {
    let url = url::Url::parse(&format!("{BASE_URL}/api/auth{path}"))?;
    let route = path.split('?').next().ok_or("Missing request route")?;
    let mut request = AuthRequest::new(
        if body.is_some() {
            HttpMethod::Post
        } else {
            HttpMethod::Get
        },
        route,
    )
    .with_url(url.clone());
    let _ = request.headers.insert("origin".into(), BASE_URL.into());
    let _ = request.headers.insert(
        "accept".into(),
        if body.is_some() {
            "application/json"
        } else {
            "text/html"
        }
        .into(),
    );
    if let Some(body) = body {
        let _ = request
            .headers
            .insert("content-type".into(), "application/json".into());
        request.body = Some(serde_json::to_vec(&body)?);
    }
    if url.query().is_some() {
        request.query = Some(serde_json::to_value(
            url.query_pairs().into_owned().collect::<BTreeMap<_, _>>(),
        )?);
    }
    if !cookies.is_empty() {
        let _ = request.headers.insert(
            "cookie".into(),
            cookies
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; "),
        );
    }
    let response = plugin
        .on_request(&request, ctx)
        .await?
        .ok_or("Missing OAuth response")?;
    let response = test_helpers::finalize_response(ctx, &request, response);
    for header in response.headers.get_all("set-cookie") {
        let pair = header.split(';').next().ok_or("Missing cookie pair")?;
        let (name, value) = pair.split_once('=').ok_or("Missing cookie value")?;
        if value.is_empty() {
            let _ = cookies.remove(name);
        } else {
            let _ = cookies.insert(name.to_owned(), value.to_owned());
        }
    }
    Ok(response)
}

#[tokio::test]
async fn only_normal_callback_applies_profile_override_for_linked_user() -> TestResult<()> {
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/oauth-profile-override-1.7.6.json"
    ))?)?;
    let metadata = fixture.get("metadata").ok_or("Missing metadata")?;
    let claims = metadata.get("claims").ok_or("Missing claims")?;
    let rows = fixture
        .get("rows")
        .and_then(Value::as_array)
        .ok_or("Missing override rows")?;
    assert_eq!(rows.len(), 4);
    for sample in rows {
        let entry = text(sample, "/entry")?;
        let override_user_info = sample
            .get("overrideUserInfoOnSignIn")
            .and_then(Value::as_bool)
            .ok_or("Missing override option")?;
        let server = GoogleFixture::start(claims.clone()).await;
        let (seen, captured) = mpsc::channel();
        let mut provider = server.provider();
        provider.override_user_info_on_sign_in = override_user_info;
        provider.map_profile_to_user = Some(Arc::new(Mapper {
            name: text(metadata, "/mappedProfile/name")?.to_owned(),
            image: text(metadata, "/mappedProfile/image")?.to_owned(),
            seen,
        }));
        let plugin = OAuthPlugin::new().add_provider("google", provider);
        let ctx = test_helpers::create_test_context().await;
        let mut cookies = BTreeMap::new();
        let direct_input = json!({
            "provider":"google", "idToken":{"token":server.token,"nonce":text(claims, "/nonce")?},
        });
        let first = send(
            &plugin,
            &ctx,
            &mut cookies,
            "/sign-in/social",
            Some(direct_input.clone()),
        )
        .await?;
        assert_eq!(first.status, 200);
        assert!(!cookies.is_empty());
        let first_body: Value = serde_json::from_slice(&first.body.bytes()?)?;
        let registered = ctx
            .database
            .get_user_by_email(text(claims, "/email")?)
            .await?
            .ok_or("Missing registered user")?;
        let user_id = registered.id.display_string()?;
        let initial_accounts = ctx.database.get_user_accounts(&user_id).await?;
        let account_id = initial_accounts
            .first()
            .ok_or("Missing initial account")?
            .id
            .display_string()?;
        assert_eq!(initial_accounts.len(), 1);
        let initial_sessions = ctx.database.get_user_sessions(&user_id).await?;
        let initial_session_id = initial_sessions
            .first()
            .ok_or("Missing initial session")?
            .id
            .display_string()?;
        assert_eq!(initial_sessions.len(), 1);
        let stored = ctx
            .database
            .update_user(
                &user_id,
                UpdateUser {
                    name: Some(text(metadata, "/storedProfile/name")?.to_owned()).into(),
                    image: Some(text(metadata, "/storedProfile/image")?.to_owned()).into(),
                    ..Default::default()
                },
            )
            .await?;
        let before = profile(&serde_json::to_value(stored)?);
        let mut statuses = vec![first.status];
        let mut response_user = None;
        let response = match entry {
            "direct" => {
                let response = send(
                    &plugin,
                    &ctx,
                    &mut cookies,
                    "/sign-in/social",
                    Some(direct_input),
                )
                .await?;
                assert_eq!(response.status, 200);
                let body: Value = serde_json::from_slice(&response.body.bytes()?)?;
                response_user = Some(profile(
                    body.get("user").ok_or("Missing direct response user")?,
                ));
                response
            }
            "callback" => {
                let start = send(&plugin, &ctx, &mut cookies, "/sign-in/social", Some(json!({
                    "provider":"google", "callbackURL":format!("{BASE_URL}/welcome"), "disableRedirect":true,
                }))).await?;
                assert_eq!(start.status, 200);
                statuses.push(start.status);
                let body: Value = serde_json::from_slice(&start.body.bytes()?)?;
                let url = url::Url::parse(text(&body, "/url")?)?;
                let state = url
                    .query_pairs()
                    .find(|(name, _)| name == "state")
                    .ok_or("Missing callback state")?
                    .1
                    .into_owned();
                let query = url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("code", "ordinary-profile-code")
                    .append_pair("state", &state)
                    .finish();
                let response = send(
                    &plugin,
                    &ctx,
                    &mut cookies,
                    &format!("/callback/google?{query}"),
                    None,
                )
                .await?;
                assert_eq!(response.status, 302);
                assert_eq!(
                    response.headers.get("Location").map(String::as_str),
                    Some("http://localhost:3000/welcome")
                );
                response
            }
            _ => return Err(format!("Unexpected profile override entry: {entry}").into()),
        };
        statuses.push(response.status);
        let user = ctx
            .database
            .get_user_by_email(text(claims, "/email")?)
            .await?
            .ok_or("Missing signed-in user")?;
        let accounts = ctx.database.get_user_accounts(&user_id).await?;
        let account = accounts.first().ok_or("Missing signed-in account")?;
        let sessions = ctx.database.get_user_sessions(&user_id).await?;
        let session_ids = sessions
            .iter()
            .map(|session| session.id.display_string())
            .collect::<Result<BTreeSet<_>, _>>()?;
        let (_, user_count) = ctx.database.list_users(ListUsersParams::default()).await?;
        let mapper_inputs = captured.try_iter().collect::<Vec<_>>();
        let after = profile(&serde_json::to_value(&user)?);
        assert_eq!(mapper_inputs, vec![claims.clone(), claims.clone()]);
        if let Some(response_user) = &response_user {
            assert_eq!(response_user, &after);
        }
        let observed = json!({
            "entry":entry, "overrideUserInfoOnSignIn":override_user_info, "statuses":statuses,
            "location":response.headers.get("Location"),
            "firstResponseUser":profile(first_body.get("user").ok_or("Missing first response user")?),
            "before":before, "after":after, "responseUser":response_user,
            "identity":{
                "sameUser":user.id.display_string()? == user_id,
                "sameAccount":account.id.display_string()? == account_id,
                "accountMatchesUser":account.user_id.as_str() == Some(user_id.as_str()),
                "provider":account.provider_id.as_str(), "subject":account.account_id.as_str(),
                "userCount":user_count, "accountCount":accounts.len(), "sessionCount":sessions.len(),
                "sessionsMatchUser":sessions.iter().all(|session| session.user_id.as_str() == Some(user_id.as_str())),
                "distinctSessions":session_ids.len() == 2,
                "firstSessionPreserved":session_ids.contains(&initial_session_id),
            },
            "mapperInputs":mapper_inputs,
        });
        assert_eq!(&observed, sample, "{entry}, override={override_user_info}");
    }
    Ok(())
}
