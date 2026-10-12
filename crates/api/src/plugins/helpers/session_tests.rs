#![expect(
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Assertions report exact contract mismatches while Result propagates fixture errors. Unexpected fixture variants and deliberate callback panics must fail or exercise the recorded unwind path."
)]

use super::{SessionIssueError, issue_selected_user_session_optional, issue_user_session};
use crate::plugins::{
    admin::AdminPlugin,
    test_helpers::{create_test_config, initialize_test_context},
};
use better_auth_core::{
    AuthContext, AuthError, AuthResult, CreateUser, FieldMap, FieldValue, RequestMeta,
    store::{
        EphemeralStore, StatelessSchema,
        database_hooks::{DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks},
    },
};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct SessionOwners(Mutex<Vec<FieldValue>>);

#[better_auth_core::database_hooks()]
impl DatabaseHooks<StatelessSchema> for SessionOwners {
    async fn before_create_session(
        &self,
        fields: &mut FieldMap,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.0
            .lock()
            .unwrap()
            .push(fields.get("userId").cloned().unwrap_or_default());
        Ok(DatabaseHookUpdate::Continue)
    }
}

async fn context(owners: &Arc<SessionOwners>) -> AuthResult<AuthContext<StatelessSchema>> {
    let config = Arc::new(create_test_config());
    let store = EphemeralStore::new(config.clone()).with_hooks(vec![owners.clone()]);
    initialize_test_context(config, Arc::new(store), &[&AdminPlugin::new()]).await
}

#[tokio::test]
async fn selected_users_without_an_admin_identity_reach_session_storage() -> AuthResult<()> {
    let owners = Arc::new(SessionOwners::default());
    let ctx = context(&owners).await?;
    let ids = [
        FieldValue::Undefined,
        FieldValue::Null,
        false.into(),
        0.0.into(),
        "".into(),
        "missing-user".into(),
        7.0.into(),
    ];
    for id in &ids {
        let user: FieldValue = if id.is_undefined() {
            Vec::<FieldValue>::new().into()
        } else {
            FieldMap::from([("id".into(), id.clone())]).into()
        };
        let issued = issue_selected_user_session_optional(
            &ctx,
            user.clone(),
            &RequestMeta::default(),
            ctx.config.session.expires_in(),
        )
        .await
        .map_err(SessionIssueError::into_auth_error)?
        .ok_or_else(|| AuthError::internal("Expected created Session"))?;
        assert!(issued.user_value()?.strict_equals(&user));
        let stored = ctx
            .database
            .get_session(issued.session_property("token")?.as_str().unwrap())
            .await?
            .ok_or_else(|| AuthError::internal("Expected persisted Session"))?;
        assert_eq!(stored.id.field_value(), issued.session_property("id")?);
        assert_eq!(
            stored.user_id.field_value(),
            issued.session_property("userId")?
        );
    }
    assert_eq!(*owners.0.lock().unwrap(), ids);
    assert!(matches!(
        issue_user_session(&ctx, "missing-user", None, None).await,
        Err(SessionIssueError::Auth(AuthError::UserNotFound))
    ));
    Ok(())
}

#[tokio::test]
async fn selected_banned_user_is_rejected_before_session_hooks() -> AuthResult<()> {
    let owners = Arc::new(SessionOwners::default());
    let ctx = context(&owners).await?;
    let user = ctx
        .database
        .create_user(CreateUser {
            email: Some("banned@session.test".into()),
            banned: Some(true),
            ..Default::default()
        })
        .await?;
    let result = issue_selected_user_session_optional(
        &ctx,
        FieldMap::from(user.clone()).into(),
        &RequestMeta::default(),
        ctx.config.session.expires_in(),
    )
    .await;
    let Err(error @ SessionIssueError::Banned { .. }) = result else {
        panic!("Session admission must reject a banned user");
    };
    let message = error.banned_message().unwrap().to_owned();
    let error = error.into_auth_error();
    assert!(error.is_api_error_instance(better_auth_core::ApiErrorClass::BetterAuth));
    assert_eq!(error.status_value()?, FieldValue::from("FORBIDDEN"));
    assert_eq!(
        error.body_value()?.json()?,
        Some(serde_json::json!({"message": message, "code": "BANNED_USER"}))
    );
    assert!(owners.0.lock().unwrap().is_empty());
    assert!(
        ctx.database
            .get_user_sessions(user.id.typed()?)
            .await?
            .is_empty()
    );
    Ok(())
}
