use crate::plugins::{
    email_otp::EmailOtpPlugin, email_password::EmailPasswordPlugin, magic_link::MagicLinkPlugin,
    password_management::PasswordManagementPlugin, test_helpers,
};
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResult, CreateAccount, CreateUser,
    CreateVerification, FieldMap, HttpMethod,
    store::{
        EphemeralStore, StatelessSchema,
        database_hooks::{DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks},
    },
    wire::{SessionView, UserView},
};
use chrono::{Duration, Utc};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

#[derive(Default)]
struct SessionHooks {
    cancel: AtomicBool,
    before: AtomicUsize,
    after: AtomicUsize,
}

#[better_auth_core::database_hooks()]
impl DatabaseHooks<StatelessSchema> for SessionHooks {
    async fn before_create_session(
        &self,
        _: &mut FieldMap,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.before.fetch_add(1, Ordering::SeqCst);
        Ok(if self.cancel.load(Ordering::SeqCst) {
            DatabaseHookUpdate::Cancel
        } else {
            DatabaseHookUpdate::Continue
        })
    }

    async fn after_create_session(
        &self,
        _: Option<&SessionView>,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        self.after.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn context(hooks: &Arc<SessionHooks>) -> AuthContext<StatelessSchema> {
    let config = Arc::new(test_helpers::create_test_config());
    let store = EphemeralStore::new(config.clone()).with_hooks(vec![hooks.clone()]);
    AuthContext::new(config, Arc::new(store))
}

async fn user(ctx: &AuthContext<StatelessSchema>) -> AuthResult<UserView> {
    ctx.database
        .create_user(
            CreateUser::new()
                .with_email("nullable@session.test")
                .with_name("Selected owner")
                .with_email_verified(true),
        )
        .await
}

async fn credential(ctx: &AuthContext<StatelessSchema>, user: &UserView) -> AuthResult<()> {
    let hash = better_auth_core::utils::password::hash_password(
        ctx.password_policy.hasher.as_ref(),
        "Password123!",
    )
    .await?;
    let _ = ctx
        .database
        .create_account(CreateAccount {
            user_id: user.id.clone(),
            account_id: user.id.clone(),
            provider_id: "credential".to_owned().into(),
            password: Some(hash).into(),
            ..Default::default()
        })
        .await?;
    Ok(())
}

fn assert_no_credentials(req: &AuthRequest) -> AuthResult<()> {
    assert!(req.new_session()?.is_none());
    assert!(!req.take_response_headers()?.contains_key("Set-Cookie"));
    Ok(())
}

fn assert_cancelled(hooks: &SessionHooks, existing: usize) {
    assert_eq!(hooks.before.load(Ordering::SeqCst), existing + 1);
    assert_eq!(hooks.after.load(Ordering::SeqCst), existing);
}

#[tokio::test]
async fn email_signin_null_session_keeps_credentials_and_returns_unauthorized() -> AuthResult<()> {
    let hooks = Arc::new(SessionHooks::default());
    hooks.cancel.store(true, Ordering::SeqCst);
    let ctx = context(&hooks);
    let owner = user(&ctx).await?;
    credential(&ctx, &owner).await?;
    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/sign-in/email",
        None,
        Some(
            serde_json::json!({"email":"nullable@session.test","password":"Password123!"})
                .to_string()
                .into_bytes(),
        ),
    );
    let result = EmailPasswordPlugin::new().on_request(&req, &ctx).await;
    assert!(matches!(
        result,
        Err(AuthError::Upstream {
            status: 401,
            code: "FAILED_TO_CREATE_SESSION",
            message: "Failed to create session",
        })
    ));
    assert!(
        ctx.database
            .get_user_sessions(owner.id.typed()?)
            .await?
            .is_empty()
    );
    assert_eq!(
        ctx.database
            .get_user_accounts(owner.id.typed()?)
            .await?
            .len(),
        1
    );
    assert_cancelled(&hooks, 0);
    assert_no_credentials(&req)
}

#[tokio::test]
async fn password_replacement_null_session_keeps_password_change_and_revocation() -> AuthResult<()>
{
    let hooks = Arc::new(SessionHooks::default());
    let ctx = context(&hooks);
    let owner = user(&ctx).await?;
    credential(&ctx, &owner).await?;
    let session = ctx
        .session_manager()
        .create_session(&owner, None, None)
        .await?;
    hooks.cancel.store(true, Ordering::SeqCst);
    let req = test_helpers::create_auth_request_no_query(HttpMethod::Post, "/change-password", Some(session.token.typed()?),
        Some(serde_json::json!({"currentPassword":"Password123!","newPassword":"Replacement123!","revokeOtherSessions":true}).to_string().into_bytes()));
    let result = PasswordManagementPlugin::new().on_request(&req, &ctx).await;
    assert!(matches!(
        result,
        Err(AuthError::Upstream {
            status: 500,
            code: "FAILED_TO_GET_SESSION",
            message: "Failed to get session",
        })
    ));
    assert!(
        ctx.database
            .get_user_sessions(owner.id.typed()?)
            .await?
            .is_empty()
    );
    let accounts = ctx.database.get_user_accounts(owner.id.typed()?).await?;
    assert_eq!(accounts.len(), 1);
    let account = accounts
        .first()
        .ok_or_else(|| AuthError::internal("Expected persisted account"))?;
    let password = account
        .password
        .typed()?
        .as_deref()
        .ok_or_else(|| AuthError::internal("Expected persisted password"))?;
    better_auth_core::utils::password::verify_password(
        ctx.password_policy.hasher.as_ref(),
        "Replacement123!",
        password,
    )
    .await?;
    assert_cancelled(&hooks, 1);
    assert_no_credentials(&req)
}

#[tokio::test]
async fn email_otp_null_session_consumes_proof_and_keeps_created_user() -> AuthResult<()> {
    let hooks = Arc::new(SessionHooks::default());
    hooks.cancel.store(true, Ordering::SeqCst);
    let ctx = context(&hooks);
    let identifier = "sign-in-otp-nullable@session.test";
    let _ = ctx
        .database
        .create_verification(CreateVerification {
            identifier: identifier.to_owned().into(),
            value: "234567:0".to_owned().into(),
            expires_at: (Utc::now() + Duration::minutes(5)).into(),
            ..Default::default()
        })
        .await?;
    let req = test_helpers::create_auth_request_no_query(HttpMethod::Post, "/sign-in/email-otp", None,
        Some(serde_json::json!({"email":"nullable@session.test","otp":"234567","name":"Created owner"}).to_string().into_bytes()));
    let result = EmailOtpPlugin::new().on_request(&req, &ctx).await;
    assert!(
        matches!(result, Err(AuthError::Internal(message)) if message == "Cannot read properties of null (reading 'token')")
    );
    assert!(
        ctx.database
            .get_verification_by_identifier(identifier)
            .await?
            .is_none()
    );
    let owner = ctx
        .database
        .get_user_by_email("nullable@session.test")
        .await?
        .ok_or_else(|| AuthError::internal("Expected committed user"))?;
    assert!(owner.email_verified);
    assert_eq!(owner.name.typed()?.as_deref(), Some("Created owner"));
    assert!(
        ctx.database
            .get_user_sessions(owner.id.typed()?)
            .await?
            .is_empty()
    );
    assert_cancelled(&hooks, 0);
    assert_no_credentials(&req)
}

#[tokio::test]
async fn magic_link_null_session_redirects_after_consuming_proof() -> AuthResult<()> {
    let hooks = Arc::new(SessionHooks::default());
    hooks.cancel.store(true, Ordering::SeqCst);
    let ctx = context(&hooks);
    let owner = user(&ctx).await?;
    let _ = ctx
        .database
        .create_verification(CreateVerification {
            identifier: "nullable-magic-token".to_owned().into(),
            value: serde_json::json!({"email":"nullable@session.test","name":"Selected owner"})
                .to_string()
                .into(),
            expires_at: (Utc::now() + Duration::minutes(5)).into(),
            ..Default::default()
        })
        .await?;
    let req = test_helpers::create_auth_request(
        HttpMethod::Get,
        "/magic-link/verify",
        None,
        None,
        HashMap::from([("token".to_owned(), "nullable-magic-token".to_owned())]),
    );
    let response = MagicLinkPlugin::new()
        .on_request(&req, &ctx)
        .await?
        .ok_or_else(|| AuthError::internal("Expected magic-link response"))?;
    assert_eq!(response.status, 302);
    assert_eq!(
        response.headers.get("Location").map(String::as_str),
        Some("http://localhost:3000/?error=failed_to_create_session")
    );
    assert!(
        ctx.database
            .get_verification_by_identifier("nullable-magic-token")
            .await?
            .is_none()
    );
    assert!(
        ctx.database
            .get_user_sessions(owner.id.typed()?)
            .await?
            .is_empty()
    );
    assert_cancelled(&hooks, 0);
    assert_no_credentials(&req)
}
