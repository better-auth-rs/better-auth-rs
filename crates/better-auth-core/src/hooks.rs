use async_trait::async_trait;
use std::sync::Arc;

use crate::error::AuthResult;
use crate::types::{User, Session, Account, Verification, CreateUser, UpdateUser, CreateSession, CreateAccount, CreateVerification};
use crate::adapters::DatabaseAdapter;
use chrono::{DateTime, Utc};

/// Database lifecycle hooks for intercepting operations.
///
/// All methods have default no-op implementations. Override only the hooks
/// you need. Returning `Err` from a `before_*` hook aborts the operation.
#[async_trait]
pub trait DatabaseHooks: Send + Sync {
    // --- User hooks ---

    /// Called before a user is created. Can modify the `CreateUser` or reject the operation.
    async fn before_create_user(&self, user: &mut CreateUser) -> AuthResult<()> {
        let _ = user;
        Ok(())
    }

    /// Called after a user is created.
    async fn after_create_user(&self, user: &User) -> AuthResult<()> {
        let _ = user;
        Ok(())
    }

    /// Called before a user is updated. Can modify the `UpdateUser` or reject the operation.
    async fn before_update_user(&self, id: &str, update: &mut UpdateUser) -> AuthResult<()> {
        let _ = (id, update);
        Ok(())
    }

    /// Called after a user is updated.
    async fn after_update_user(&self, user: &User) -> AuthResult<()> {
        let _ = user;
        Ok(())
    }

    /// Called before a user is deleted.
    async fn before_delete_user(&self, id: &str) -> AuthResult<()> {
        let _ = id;
        Ok(())
    }

    /// Called after a user is deleted.
    async fn after_delete_user(&self, id: &str) -> AuthResult<()> {
        let _ = id;
        Ok(())
    }

    // --- Session hooks ---

    /// Called before a session is created. Can modify the `CreateSession` or reject.
    async fn before_create_session(&self, session: &mut CreateSession) -> AuthResult<()> {
        let _ = session;
        Ok(())
    }

    /// Called after a session is created.
    async fn after_create_session(&self, session: &Session) -> AuthResult<()> {
        let _ = session;
        Ok(())
    }

    /// Called before a session is deleted.
    async fn before_delete_session(&self, token: &str) -> AuthResult<()> {
        let _ = token;
        Ok(())
    }

    /// Called after a session is deleted.
    async fn after_delete_session(&self, token: &str) -> AuthResult<()> {
        let _ = token;
        Ok(())
    }
}

/// A database adapter wrapper that calls hooks around the inner adapter's operations.
pub struct HookedDatabaseAdapter {
    inner: Arc<dyn DatabaseAdapter>,
    hooks: Vec<Arc<dyn DatabaseHooks>>,
}

impl HookedDatabaseAdapter {
    pub fn new(inner: Arc<dyn DatabaseAdapter>) -> Self {
        Self {
            inner,
            hooks: Vec::new(),
        }
    }

    pub fn with_hook(mut self, hook: Arc<dyn DatabaseHooks>) -> Self {
        self.hooks.push(hook);
        self
    }

    pub fn add_hook(&mut self, hook: Arc<dyn DatabaseHooks>) {
        self.hooks.push(hook);
    }
}

#[async_trait]
impl DatabaseAdapter for HookedDatabaseAdapter {
    // --- User operations ---

    async fn create_user(&self, mut user: CreateUser) -> AuthResult<User> {
        for hook in &self.hooks {
            hook.before_create_user(&mut user).await?;
        }
        let result = self.inner.create_user(user).await?;
        for hook in &self.hooks {
            hook.after_create_user(&result).await?;
        }
        Ok(result)
    }

    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<User>> {
        self.inner.get_user_by_id(id).await
    }

    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<User>> {
        self.inner.get_user_by_email(email).await
    }

    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<User>> {
        self.inner.get_user_by_username(username).await
    }

    async fn update_user(&self, id: &str, mut update: UpdateUser) -> AuthResult<User> {
        for hook in &self.hooks {
            hook.before_update_user(id, &mut update).await?;
        }
        let result = self.inner.update_user(id, update).await?;
        for hook in &self.hooks {
            hook.after_update_user(&result).await?;
        }
        Ok(result)
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        for hook in &self.hooks {
            hook.before_delete_user(id).await?;
        }
        self.inner.delete_user(id).await?;
        for hook in &self.hooks {
            hook.after_delete_user(id).await?;
        }
        Ok(())
    }

    // --- Session operations ---

    async fn create_session(&self, mut session: CreateSession) -> AuthResult<Session> {
        for hook in &self.hooks {
            hook.before_create_session(&mut session).await?;
        }
        let result = self.inner.create_session(session).await?;
        for hook in &self.hooks {
            hook.after_create_session(&result).await?;
        }
        Ok(result)
    }

    async fn get_session(&self, token: &str) -> AuthResult<Option<Session>> {
        self.inner.get_session(token).await
    }

    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<Session>> {
        self.inner.get_user_sessions(user_id).await
    }

    async fn update_session_expiry(&self, token: &str, expires_at: DateTime<Utc>) -> AuthResult<()> {
        self.inner.update_session_expiry(token, expires_at).await
    }

    async fn delete_session(&self, token: &str) -> AuthResult<()> {
        for hook in &self.hooks {
            hook.before_delete_session(token).await?;
        }
        self.inner.delete_session(token).await?;
        for hook in &self.hooks {
            hook.after_delete_session(token).await?;
        }
        Ok(())
    }

    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        self.inner.delete_user_sessions(user_id).await
    }

    async fn delete_expired_sessions(&self) -> AuthResult<usize> {
        self.inner.delete_expired_sessions().await
    }

    // --- Account operations (pass-through, no hooks) ---

    async fn create_account(&self, account: CreateAccount) -> AuthResult<Account> {
        self.inner.create_account(account).await
    }

    async fn get_account(&self, provider: &str, provider_account_id: &str) -> AuthResult<Option<Account>> {
        self.inner.get_account(provider, provider_account_id).await
    }

    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<Account>> {
        self.inner.get_user_accounts(user_id).await
    }

    async fn delete_account(&self, id: &str) -> AuthResult<()> {
        self.inner.delete_account(id).await
    }

    // --- Verification operations (pass-through, no hooks) ---

    async fn create_verification(&self, verification: CreateVerification) -> AuthResult<Verification> {
        self.inner.create_verification(verification).await
    }

    async fn get_verification(&self, identifier: &str, value: &str) -> AuthResult<Option<Verification>> {
        self.inner.get_verification(identifier, value).await
    }

    async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<Verification>> {
        self.inner.get_verification_by_value(value).await
    }

    async fn delete_verification(&self, id: &str) -> AuthResult<()> {
        self.inner.delete_verification(id).await
    }

    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        self.inner.delete_expired_verifications().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::MemoryDatabaseAdapter;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct CountingHook {
        before_create_count: AtomicU32,
        after_create_count: AtomicU32,
        before_update_count: AtomicU32,
        after_update_count: AtomicU32,
        before_delete_count: AtomicU32,
        after_delete_count: AtomicU32,
    }

    impl CountingHook {
        fn new() -> Self {
            Self {
                before_create_count: AtomicU32::new(0),
                after_create_count: AtomicU32::new(0),
                before_update_count: AtomicU32::new(0),
                after_update_count: AtomicU32::new(0),
                before_delete_count: AtomicU32::new(0),
                after_delete_count: AtomicU32::new(0),
            }
        }
    }

    #[async_trait]
    impl DatabaseHooks for CountingHook {
        async fn before_create_user(&self, _user: &mut CreateUser) -> AuthResult<()> {
            self.before_create_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn after_create_user(&self, _user: &User) -> AuthResult<()> {
            self.after_create_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn before_update_user(&self, _id: &str, _update: &mut UpdateUser) -> AuthResult<()> {
            self.before_update_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn after_update_user(&self, _user: &User) -> AuthResult<()> {
            self.after_update_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn before_delete_user(&self, _id: &str) -> AuthResult<()> {
            self.before_delete_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn after_delete_user(&self, _id: &str) -> AuthResult<()> {
            self.after_delete_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_hooks_called_on_create_user() {
        let hook = Arc::new(CountingHook::new());
        let db = HookedDatabaseAdapter::new(Arc::new(MemoryDatabaseAdapter::new()))
            .with_hook(hook.clone());

        let create = CreateUser::new().with_email("test@example.com").with_name("Test");
        db.create_user(create).await.unwrap();

        assert_eq!(hook.before_create_count.load(Ordering::SeqCst), 1);
        assert_eq!(hook.after_create_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_hooks_called_on_update_user() {
        let hook = Arc::new(CountingHook::new());
        let db = HookedDatabaseAdapter::new(Arc::new(MemoryDatabaseAdapter::new()))
            .with_hook(hook.clone());

        let create = CreateUser::new().with_email("test@example.com").with_name("Test");
        let user = db.create_user(create).await.unwrap();

        let update = UpdateUser {
            name: Some("Updated".to_string()),
            email: None, image: None, email_verified: None,
            username: None, display_username: None, role: None,
            banned: None, ban_reason: None, ban_expires: None,
            two_factor_enabled: None, metadata: None,
        };
        db.update_user(&user.id, update).await.unwrap();

        assert_eq!(hook.before_update_count.load(Ordering::SeqCst), 1);
        assert_eq!(hook.after_update_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_hooks_called_on_delete_user() {
        let hook = Arc::new(CountingHook::new());
        let db = HookedDatabaseAdapter::new(Arc::new(MemoryDatabaseAdapter::new()))
            .with_hook(hook.clone());

        let create = CreateUser::new().with_email("test@example.com").with_name("Test");
        let user = db.create_user(create).await.unwrap();

        db.delete_user(&user.id).await.unwrap();

        assert_eq!(hook.before_delete_count.load(Ordering::SeqCst), 1);
        assert_eq!(hook.after_delete_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_before_hook_can_reject() {
        struct RejectHook;

        #[async_trait]
        impl DatabaseHooks for RejectHook {
            async fn before_create_user(&self, _user: &mut CreateUser) -> AuthResult<()> {
                Err(crate::error::AuthError::forbidden("Hook rejected"))
            }
        }

        let db = HookedDatabaseAdapter::new(Arc::new(MemoryDatabaseAdapter::new()))
            .with_hook(Arc::new(RejectHook));

        let create = CreateUser::new().with_email("test@example.com").with_name("Test");
        let result = db.create_user(create).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().status_code(), 403);
    }

    #[tokio::test]
    async fn test_multiple_hooks() {
        let hook1 = Arc::new(CountingHook::new());
        let hook2 = Arc::new(CountingHook::new());
        let db = HookedDatabaseAdapter::new(Arc::new(MemoryDatabaseAdapter::new()))
            .with_hook(hook1.clone())
            .with_hook(hook2.clone());

        let create = CreateUser::new().with_email("test@example.com").with_name("Test");
        db.create_user(create).await.unwrap();

        assert_eq!(hook1.before_create_count.load(Ordering::SeqCst), 1);
        assert_eq!(hook2.before_create_count.load(Ordering::SeqCst), 1);
        assert_eq!(hook1.after_create_count.load(Ordering::SeqCst), 1);
        assert_eq!(hook2.after_create_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_passthrough_operations() {
        let db = HookedDatabaseAdapter::new(Arc::new(MemoryDatabaseAdapter::new()));

        // get_user_by_email should work without hooks
        let result = db.get_user_by_email("nonexistent@test.com").await.unwrap();
        assert!(result.is_none());
    }
}
