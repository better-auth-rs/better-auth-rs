use super::apple_tests::{Mapper, TestResult, configured, fixture, rows, text};
use super::google_test_support::GoogleFixture;
use super::*;
use serde_json::{Value, json};
use std::sync::mpsc;

#[tokio::test]
async fn apple_direct_and_form_post_success_persist_user_account_and_session() -> TestResult<()> {
    let fixture = fixture()?;
    for sample in rows(&fixture, "/flows")? {
        let mode = text(sample, "/mode")?;
        let server =
            GoogleFixture::start(sample.get("claims").ok_or("Missing claims")?.clone()).await;
        let mut provider = configured(&fixture, &json!({}), Some(&server))?;
        let (seen, captured) = mpsc::channel();
        let (calls, called) = mpsc::channel();
        provider.map_profile_to_user = Some(Arc::new(Mapper {
            patch: json!({"name":"Mapped Flow Owner"}),
            seen,
            calls,
        }));
        let plugin = OAuthPlugin::new().add_provider("apple", provider);
        let ctx = crate::plugins::test_helpers::create_test_context().await;
        let user_input = sample.get("userInput").ok_or("Missing callback user")?;
        let mut start = AuthRequest::new(HttpMethod::Post, "/sign-in/social");
        start.body = Some(serde_json::to_vec(&if mode == "direct" {
            json!({"provider":"apple", "idToken":{"token":server.token,"nonce":"ordinary-flow-nonce","user":user_input}})
        } else {
            json!({"provider":"apple","callbackURL":"http://localhost:3000/welcome","disableRedirect":true})
        })?);
        let response = plugin
            .on_request(&start, &ctx)
            .await?
            .ok_or("Missing sign-in response")?;
        let mut statuses = vec![response.status];
        let mut location = None;
        if mode == "form_post" {
            let body: Value = serde_json::from_slice(&response.body)?;
            let url = url::Url::parse(text(&body, "/url")?)?;
            let state = url
                .query_pairs()
                .find(|(key, _)| key == "state")
                .ok_or("Missing state")?
                .1
                .into_owned();
            let cookie = response
                .headers
                .get_all("set-cookie")
                .map(|value| value.split(';').next().ok_or("Missing state cookie"))
                .collect::<Result<Vec<_>, _>>()?
                .join("; ");
            assert!(!cookie.is_empty());
            let user = serde_json::to_string(user_input)?;
            let mut callback = AuthRequest::new(HttpMethod::Post, "/callback/apple");
            callback.headers.insert("cookie".into(), cookie.clone());
            callback
                .headers
                .insert("origin".into(), "http://localhost:3000".into());
            callback.headers.insert(
                "content-type".into(),
                "application/x-www-form-urlencoded".into(),
            );
            callback.body = Some(
                url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("state", &state)
                    .append_pair("code", "ordinary-code")
                    .append_pair("user", &user)
                    .finish()
                    .into_bytes(),
            );
            let redirect = plugin
                .on_request(&callback, &ctx)
                .await?
                .ok_or("Missing POST callback response")?;
            statuses.push(redirect.status);
            assert!(
                server
                    .requests
                    .lock()
                    .map_err(|error| error.to_string())?
                    .is_empty()
            );
            let target = url::Url::parse(
                redirect
                    .headers
                    .get("Location")
                    .ok_or("Missing callback Location")?,
            )?;
            assert_eq!(target.path(), "/api/auth/callback/apple");
            let query: std::collections::HashMap<String, String> =
                target.query_pairs().into_owned().collect();
            assert_eq!(query.get("state"), Some(&state));
            assert_eq!(query.get("code").map(String::as_str), Some("ordinary-code"));
            assert_eq!(query.get("user"), Some(&user));
            let mut complete = AuthRequest::new(HttpMethod::Get, "/callback/apple");
            complete.headers.insert("cookie".into(), cookie);
            complete.query = Some(serde_json::to_value(query)?);
            let response = plugin
                .on_request(&complete, &ctx)
                .await?
                .ok_or("Missing GET callback response")?;
            statuses.push(response.status);
            location = response.headers.get("Location").cloned();
        }
        assert_eq!(
            json!(statuses),
            *sample.get("status").ok_or("Missing status")?
        );
        assert_eq!(
            json!(location),
            *sample.get("location").ok_or("Missing location")?
        );
        let user = ctx
            .database
            .get_user_by_email(text(sample, "/claims/email")?)
            .await?
            .ok_or("Missing Apple user")?;
        let user_id = user.id.display_string()?;
        let accounts = ctx.database.get_user_accounts(&user_id).await?;
        let sessions = ctx.database.get_user_sessions(&user_id).await?;
        let account = accounts.first().ok_or("Missing Apple account")?;
        let session = serde_json::to_value(sessions.first().ok_or("Missing Apple session")?)?;
        let user = serde_json::to_value(user)?;
        let result = json!({
            "name":user.get("name"), "email":user.get("email"), "emailVerified":user.get("emailVerified"), "image":user.get("image"),
            "provider":account.provider_id.as_str(), "subject":account.account_id.as_str(), "accountCount":accounts.len(),
            "sessionCount":sessions.len(), "sessionMatchesUser":session.get("userId") == user.get("id"),
        });
        assert_eq!(result, *sample.get("result").ok_or("Missing result")?);
        assert_eq!(
            json!(captured.try_iter().collect::<Vec<_>>()),
            *sample.get("mapperInputs").ok_or("Missing mapper inputs")?
        );
        assert_eq!(called.try_iter().collect::<Vec<_>>(), ["map"]);
        let requests: Vec<_> = server
            .requests
            .lock()
            .map_err(|error| error.to_string())?
            .iter()
            .map(|path| match path.as_str() {
                "/jwks" => Ok("/auth/keys"),
                "/token" => Ok("/auth/token"),
                _ => Err(format!("Unexpected Apple test request: {path}")),
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            json!(requests),
            *sample.get("requests").ok_or("Missing requests")?
        );
    }
    Ok(())
}
