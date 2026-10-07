use super::{SessionIssueError, issue_selected_user_session, issue_user_session};
use crate::plugins::test_helpers::create_test_config;
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

fn context(owners: &Arc<SessionOwners>) -> AuthContext<StatelessSchema> {
    let config = Arc::new(create_test_config());
    let store = EphemeralStore::new(config.clone()).with_hooks(vec![owners.clone()]);
    let mut ctx = AuthContext::new(config, Arc::new(store));
    ctx.set_metadata("admin.enabled", serde_json::Value::Bool(true));
    ctx
}

#[tokio::test]
async fn selected_users_without_an_admin_identity_reach_session_storage() -> AuthResult<()> {
    let owners = Arc::new(SessionOwners::default());
    let ctx = context(&owners);
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
        let issued = issue_selected_user_session(
            &ctx,
            user.clone(),
            &RequestMeta::default(),
            ctx.config.session.expires_in(),
        )
        .await
        .map_err(SessionIssueError::into_auth_error)?;
        assert!(issued.user.strict_equals(&user));
        let stored = ctx
            .database
            .get_session(&issued.session.token)
            .await?
            .ok_or_else(|| AuthError::internal("Expected persisted Session"))?;
        assert_eq!(stored.id, issued.session.id);
        assert_eq!(stored.user_id, issued.session.user_id);
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
    let ctx = context(&owners);
    let user = ctx
        .database
        .create_user(CreateUser {
            email: Some("banned@session.test".into()),
            banned: Some(true),
            ..Default::default()
        })
        .await?;
    let result = issue_selected_user_session(
        &ctx,
        FieldMap::from(user.clone()).into(),
        &RequestMeta::default(),
        ctx.config.session.expires_in(),
    )
    .await;
    assert!(matches!(result, Err(SessionIssueError::Banned { .. })));
    assert!(owners.0.lock().unwrap().is_empty());
    assert!(
        ctx.database
            .get_user_sessions(user.id.typed()?)
            .await?
            .is_empty()
    );
    Ok(())
}
