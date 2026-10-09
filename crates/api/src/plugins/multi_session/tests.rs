use super::*;
use better_auth_core::{
    AuthConfig, CreateSession, CreateUser, HttpMethod,
    store::{EphemeralStore, StatelessSchema},
    user_fields::{UserFieldConfig, UserFieldReference},
    wire::SessionView,
};
use std::sync::Arc;

async fn relationship_sessions() -> (AuthContext<StatelessSchema>, Vec<SessionView>) {
    let mut config = AuthConfig::new("multi-session-native-secret-at-least-thirty-two-characters");
    config.session.cookie_cache = None;
    let _ = config.user.fields_mut().insert(
        "image".into(),
        UserFieldConfig {
            references: Some(UserFieldReference {
                model: "session".into(),
                field: "id".into(),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let config = Arc::new(config);
    let ctx = AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config)));
    let mut sessions = Vec::new();
    for index in 0..2 {
        let session = ctx
            .database
            .create_session(CreateSession {
                inherited_fields: Default::default(),
                additional_fields: Default::default(),
                user_id: "canonical-owner".into(),
                expires_at: (Utc::now() + chrono::Duration::hours(1)).into(),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await
            .unwrap();
        let mut user = CreateUser::new()
            .with_email(format!("native-{index}@example.test"))
            .with_name(format!("Native {index}"));
        user.image = Some(session.id.typed().unwrap().clone()).into();
        ctx.database.create_user(user).await.unwrap();
        sessions.push(session);
    }
    (ctx, sessions)
}

fn device_request(
    ctx: &AuthContext<StatelessSchema>,
    sessions: &[SessionView],
    path: &str,
) -> AuthRequest {
    let mut request = AuthRequest::new(HttpMethod::Post, path);
    let _ = request.headers.insert(
        "cookie".into(),
        sessions
            .iter()
            .map(|session| {
                let token = session.token.typed().unwrap();
                format!(
                    "{}={}",
                    cookie_name(token, &ctx.config),
                    sign_cookie_value(token, ctx.config.signing_secret())
                )
            })
            .collect::<Vec<_>>()
            .join("; "),
    );
    request
}

#[tokio::test]
async fn session_list_deduplicates_raw_relationship_ids_before_public_projection() {
    let (ctx, sessions) = relationship_sessions().await;
    let request = device_request(&ctx, &sessions, "/multi-session/list-device-sessions");
    let raw = list_sessions(&request, &ctx, true).await.unwrap();
    assert_eq!(raw.len(), 2);
    assert!(raw.iter().all(|data| data.user.as_array().is_some()));
    let mut expected = raw.into_iter().next().unwrap();
    expected
        .session
        .filter_returned_fields(&ctx.config.session)
        .unwrap();
    expected.user = expected.public_user(&ctx.config.user).unwrap();
    let response = MultiSessionPlugin::new()
        .handle_list(&request, &ctx)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&response.body.bytes().unwrap()).unwrap(),
        serde_json::to_value(vec![expected]).unwrap(),
    );
}

#[tokio::test]
async fn active_session_preserves_the_selected_relationship_through_cookie_and_response() {
    let (ctx, sessions) = relationship_sessions().await;
    let mut request = device_request(&ctx, &sessions, "/multi-session/set-active");
    let _ = request
        .headers
        .insert("content-type".into(), "application/json".into());
    request.body =
        Some(serde_json::to_vec(&serde_json::json!({"sessionToken": sessions[0].token})).unwrap());
    let response = MultiSessionPlugin::new()
        .handle_set_active(&request, &ctx)
        .await
        .unwrap();
    let issued = request.new_session().unwrap().unwrap();
    assert!(issued.user.as_object().unwrap().get("0").unwrap().is_some());
    assert!(issued.user_field("id").unwrap().is_undefined());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&response.body.bytes().unwrap()).unwrap(),
        serde_json::to_value(issued).unwrap(),
    );
}

#[tokio::test]
async fn remember_session_uses_new_session_even_after_its_database_row_is_deleted() {
    let (ctx, sessions) = relationship_sessions().await;
    let request = AuthRequest::new(HttpMethod::Post, "/native-session");
    let session = sessions[0].clone();
    ctx.session_manager()
        .set_native_session_cookie(
            &request,
            NativeSessionData {
                session: session.clone(),
                user: vec![FieldValue::from(FieldMap::new())].into(),
            },
            None,
        )
        .await
        .unwrap();
    ctx.database
        .delete_session(session.token.typed().unwrap())
        .await
        .unwrap();
    let mut response =
        super::super::test_helpers::finalize_response(&ctx, &request, AuthResponse::new(200));
    MultiSessionPlugin::new()
        .remember_session(&request, &mut response, &ctx)
        .await
        .unwrap();
    let name = cookie_name(session.token.typed().unwrap(), &ctx.config);
    assert!(
        response
            .headers
            .get_all("set-cookie")
            .any(|value| value.starts_with(&format!("{name}=")))
    );
}
