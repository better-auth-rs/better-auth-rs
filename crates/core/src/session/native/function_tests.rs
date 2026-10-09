use super::*;
use crate::{
    AuthConfig, AuthRequest, CreateUser, HttpMethod,
    session::{SessionManager, SessionRead},
    store::{EphemeralStore, StatelessSchema},
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[test]
fn hidden_native_user_function_rejects_public_clone_before_filtering() -> AuthResult<()> {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let factory: crate::user_fields::UserFieldFactory = Arc::new(move || {
        let _ = observed.fetch_add(1, Ordering::SeqCst);
        Ok(FieldValue::Undefined)
    });
    let function = FieldValue::Function(crate::FieldFunction::from(factory));
    let mut config = UserConfig::default();
    let _ = config.fields_mut().insert(
        "hidden".into(),
        UserFieldConfig {
            returned: Some(false),
            ..Default::default()
        },
    );
    let data = NativeSessionData {
        session: SessionView::default(),
        user: FieldMap::from([
            ("id".into(), "native-user".into()),
            ("hidden".into(), vec![function.clone()].into()),
        ])
        .into(),
    };
    assert!(matches!(
        data.public_user(&config),
        Err(AuthError::DataClone)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(data.user_field("hidden")?.as_array().unwrap()[0].strict_equals(&function));
    Ok(())
}

#[tokio::test]
async fn session_public_clone_failure_precedes_request_snapshot_and_keeps_stored_session()
-> AuthResult<()> {
    for user_field in [false, true] {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let factory: crate::user_fields::UserFieldFactory = Arc::new(move || {
            let _ = observed.fetch_add(1, Ordering::SeqCst);
            Ok(FieldValue::Undefined)
        });
        let function = FieldValue::Function(crate::FieldFunction::from(factory));
        let output = function.clone();
        let field = UserFieldConfig {
            required: Some(false),
            returned: Some(false),
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |_| Ok(output.clone()))),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut config =
            AuthConfig::new("session-public-function-secret-at-least-thirty-two-characters");
        if user_field {
            let _ = config
                .user
                .fields_mut()
                .insert("hiddenFunction".into(), field);
        } else {
            let _ = config
                .session
                .fields_mut()
                .insert("hiddenFunction".into(), field);
        }
        let config = Arc::new(config);
        let manager = SessionManager::<StatelessSchema>::new(
            config.clone(),
            Arc::new(EphemeralStore::new(config.clone())),
        );
        let user = manager
            .database
            .create_user(CreateUser::new().with_email("session-function@example.test"))
            .await?;
        let session = manager.create_session(&user, None, None).await?;
        let mut request = AuthRequest::new(HttpMethod::Get, "/get-session");
        request.query = Some(serde_json::json!({"disableRefresh": true}));
        let _ = request.headers.insert(
            "cookie".into(),
            format!(
                "{}={}",
                config.auth_cookie("session_token", Default::default()).name,
                crate::utils::cookie_utils::sign_cookie_value(
                    session.token.typed()?,
                    config.signing_secret()
                ),
            ),
        );
        assert!(matches!(
            manager
                .resolve_native(&request, SessionRead::Authoritative)
                .await,
            Err(AuthError::DataClone)
        ));
        assert!(request.session_snapshot()?.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            request
                .take_response_headers()?
                .get_all("set-cookie")
                .count(),
            0
        );
        assert!(request.new_session()?.is_none());
        let stored = manager
            .database
            .get_session(session.token.typed()?)
            .await?
            .ok_or_else(|| {
                AuthError::internal("Expected stored Session after public clone failure")
            })?;
        assert_eq!(stored.expires_at, session.expires_at);
    }
    Ok(())
}
