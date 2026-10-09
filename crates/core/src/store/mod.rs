mod api_key_usage;
pub use api_key_usage::ApiKeyUsageWrite;

use async_trait::async_trait;
use std::any::Any;
use std::future::Future;
use std::pin::Pin;

pub mod cache;
mod capabilities;
mod runtime;
mod session_create;
mod user_verification;
pub use session_create::{
    PreparedSessionCreate, SessionCreateWriter, session_create_native_fields,
    session_create_schema, session_field_schema, session_from_create_fields,
};
#[doc(hidden)]
pub use user_verification::revoke_unproven_account_access;
pub mod schema;
pub use runtime::RuntimeStore;
pub mod database_hooks;
mod ephemeral;
pub use capabilities::StoreCapabilities;
pub use ephemeral::{EphemeralStore, StatelessSchema};
pub mod secondary;

use crate::error::{AuthError, AuthResult};
use crate::schema::AuthSchema;
use crate::types::{
    ApiKey, CreateAccount, CreateApiKey, CreateDeviceCode, CreateInvitation, CreateMember,
    CreateOrganization, CreatePasskey, CreateSession, CreateTwoFactor, CreateUser,
    CreateVerification, DeviceCode, Invitation, InvitationStatus, ListUsersParams, Member,
    Organization, Passkey, TwoFactor, UpdateAccount, UpdateApiKey, UpdateDeviceCode,
    UpdateOrganization, UpdatePasskey, UpdatePasskeyAuthentication, UpdateUser,
};

pub use cache::{CacheAdapter, MemoryCacheAdapter, SecondaryStorage};

/// Reject atomic updates after field conversion removes every assignment.
#[doc(hidden)]
pub fn validate_increment_one_update(has_increment: bool, has_set: bool) -> AuthResult<()> {
    if !has_increment && !has_set {
        return Err(AuthError::internal(
            "incrementOne resolved to an empty update: every increment/set field was unknown to the schema or transformed away.",
        ));
    }
    Ok(())
}

#[cfg(feature = "redis-cache")]
pub use cache::RedisAdapter;

pub type BoxedTransactionValue = Box<dyn Any + Send>;
pub type TransactionFuture<'a> =
    Pin<Box<dyn Future<Output = AuthResult<BoxedTransactionValue>> + Send + 'a>>;
pub type TypedTransactionFuture<'a, T> = Pin<Box<dyn Future<Output = AuthResult<T>> + Send + 'a>>;
pub type TransactionWork<S> =
    dyn for<'tx> FnOnce(&'tx dyn AuthTransaction<S>) -> TransactionFuture<'tx> + Send;

/// A secondary write that runs after update-before hooks and before the database write.
pub struct SessionUpdateWriter {
    /// Run the database update after the secondary write succeeds.
    pub write_database: bool,
    /// Receive the complete hook patch, before adapter field transformations.
    pub write: Box<
        dyn FnOnce(
                database_hooks::SessionUpdate,
            ) -> TypedTransactionFuture<'static, Option<crate::wire::SessionView>>
            + Send,
    >,
}

/// Write a projected verification to secondary storage before database after hooks are queued.
/// The write is immediate inside a transaction; database rollback does not undo secondary storage.
pub type VerificationCreateWriter =
    Box<dyn FnOnce(crate::FieldMap) -> TypedTransactionFuture<'static, ()> + Send>;

#[async_trait]
pub trait AuthTransaction<S: AuthSchema>:
    JwksStore + DeviceCodeStore + WalletStore + Send + Sync
{
    /// Query a user ID through this transaction without string coercion.
    async fn get_user_by_id_value(
        &self,
        id: &crate::FieldValue,
    ) -> AuthResult<Option<crate::UserView>> {
        self.get_user_by_id_field(&crate::SchemaValue::from_field(id.clone()))
            .await
    }
    /// Run `get_member_value` through this transaction's organization adapter.
    async fn get_member_value(
        &self,
        _organization_id: &crate::FieldValue,
        _user_id: &crate::FieldValue,
    ) -> AuthResult<Option<crate::Member>> {
        Err(AuthError::config(
            "The store must support transactional organization operations",
        ))
    }
    /// Run `get_organization_by_id_value` through this transaction's organization adapter.
    async fn get_organization_by_id_value(
        &self,
        _id: &crate::FieldValue,
    ) -> AuthResult<Option<crate::Organization>> {
        Err(AuthError::config(
            "The store must support transactional organization operations",
        ))
    }
    /// Run `get_team_value` through this transaction's organization adapter.
    async fn get_team_value(&self, _id: &crate::FieldValue) -> AuthResult<Option<crate::Team>> {
        Err(AuthError::config(
            "The store must support transactional organization operations",
        ))
    }
    /// Run `count_organization_members_value` through this transaction's organization adapter.
    async fn count_organization_members_value(&self, _id: &crate::FieldValue) -> AuthResult<i64> {
        Err(AuthError::config(
            "The store must support transactional organization operations",
        ))
    }
    /// Run `create_member` through this transaction's organization adapter.
    async fn create_member(&self, _input: crate::CreateMember) -> AuthResult<crate::Member> {
        Err(AuthError::config(
            "The store must support transactional organization operations",
        ))
    }
    /// Run `add_team_member` through this transaction's organization adapter.
    async fn add_team_member(
        &self,
        _team_id: &crate::SchemaValue<String>,
        _user_id: &str,
        _maximum: Option<usize>,
    ) -> AuthResult<Option<crate::TeamMember>> {
        Err(AuthError::config(
            "The store must support transactional organization operations",
        ))
    }
    /// Delete a member and its team memberships through this transaction.
    async fn delete_member(&self, _id: &str) -> AuthResult<()> {
        Err(AuthError::config(
            "The store must support transactional organization operations",
        ))
    }
    /// Delete a member and the original user's team memberships through this transaction.
    async fn delete_member_for_user(
        &self,
        _id: &str,
        _organization_id: &str,
        _user_id: &str,
    ) -> AuthResult<()> {
        Err(AuthError::config(
            "The store must support transactional organization operations",
        ))
    }

    /// Retain this transaction adapter after the enclosing operation finishes.
    /// Preserve the adapter's own commit, rollback, and pending-hook behavior.
    fn clone_handle(&self) -> std::sync::Arc<dyn AuthTransaction<S>>;

    /// Create a user while preserving cancellation and the active transaction.
    async fn create_user_optional(
        &self,
        input: CreateUser,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        self.create_user_fields_optional(input.into_user_fields()?)
            .await
    }
    /// Create a user from prepared internal-adapter fields without repeating input preparation.
    /// Preserve this transaction and the complete database-hook lifecycle.
    async fn create_user_fields_optional(
        &self,
        input: crate::FieldMap,
    ) -> AuthResult<Option<crate::wire::UserView>>;
    /// Preserve a nullable Account creation result in this transaction.
    async fn create_account_optional(
        &self,
        _input: CreateAccount,
    ) -> AuthResult<Option<crate::wire::AccountView>> {
        Err(AuthError::config(
            "The store must support nullable transactional account creation",
        ))
    }
    /// Create a session while preserving cancellation and the active transaction.
    async fn create_session_optional(
        &self,
        _input: CreateSession,
    ) -> AuthResult<Option<crate::wire::SessionView>> {
        Err(AuthError::config(
            "The store must support nullable transactional session creation",
        ))
    }
    /// Run one Session creation lifecycle with an optional secondary write.
    async fn create_session_with_writer(
        &self,
        input: CreateSession,
        writer: Option<SessionCreateWriter>,
    ) -> AuthResult<Option<crate::wire::SessionView>> {
        if writer.is_some() {
            return Err(AuthError::config(
                "The store must support ordered secondary session creation",
            ));
        }
        self.create_session_optional(input).await
    }
    /// Run session before hooks without converting cancellation into an API error.
    async fn before_create_runtime_session_optional(
        &self,
        input: &mut PreparedSessionCreate,
    ) -> AuthResult<bool> {
        self.before_create_runtime_session(input).await?;
        Ok(true)
    }
    /// Queue an effect in write order. Run it after commit, discard it on rollback,
    /// and stop later effects if it fails. Execute in the committing caller's request scope.
    /// Capture any explicit hook request argument separately when queuing the effect.
    fn queue_after_commit(&self, effect: TypedTransactionFuture<'static, ()>) -> AuthResult<()>;

    /// Run verification creation hooks for secondary-only values in this transaction.
    /// Run verification before hooks without converting cancellation into an error.
    async fn before_create_runtime_verification_optional(
        &self,
        verification: &mut CreateVerification,
    ) -> AuthResult<bool> {
        self.before_create_runtime_verification(verification)
            .await?;
        Ok(true)
    }

    async fn before_create_runtime_verification(
        &self,
        _verification: &mut CreateVerification,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Create a verification using the active transaction and its configured storage policy.
    async fn create_verification(
        &self,
        verification: CreateVerification,
    ) -> AuthResult<crate::wire::VerificationView>;
    /// Preserve cancellation and a successful adapter creation with no returned row.
    async fn create_verification_optional(
        &self,
        _verification: CreateVerification,
    ) -> AuthResult<Option<crate::wire::VerificationView>> {
        Err(AuthError::config(
            "The store must support nullable verification creation",
        ))
    }

    /// Run a verification create lifecycle, then its secondary write, then queue database after hooks.
    async fn create_verification_with_writer(
        &self,
        verification: CreateVerification,
        writer: Option<VerificationCreateWriter>,
    ) -> AuthResult<Option<crate::wire::VerificationView>> {
        if writer.is_some() {
            return Err(AuthError::config(
                "The store must support ordered verification creation",
            ));
        }
        self.create_verification_optional(verification).await
    }

    /// Update adapter fields and return the projection produced after the write.
    async fn update_verification(
        &self,
        identifier: &str,
        update: database_hooks::VerificationUpdate,
    ) -> AuthResult<Option<crate::wire::VerificationView>>;

    /// Read the latest verification, including expired values, inside the active transaction.
    async fn get_verification_including_expired(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<crate::wire::VerificationView>>;
    /// Consume the latest verification and remove older matches through this transaction.
    async fn consume_verification_including_expired(
        &self,
        _identifier: &str,
    ) -> AuthResult<Option<crate::wire::VerificationView>> {
        Err(AuthError::config(
            "The store must support transactional verification consumption",
        ))
    }
    /// Consume through this transaction, then discard an expired result.
    async fn consume_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<crate::wire::VerificationView>> {
        match self
            .consume_verification_including_expired(identifier)
            .await?
        {
            Some(record) if !record.expires_at.is_before(chrono::Utc::now())? => Ok(Some(record)),
            _ => Ok(None),
        }
    }
    /// Delete a verification through the active transaction and its storage policy.
    async fn delete_verification_by_identifier(&self, identifier: &str) -> AuthResult<()>;
    /// Delete expired verification records inside the active transaction.
    async fn delete_expired_verifications(&self) -> AuthResult<usize>;
    /// Run session creation hooks before creating a session outside the database.
    async fn before_create_runtime_session(
        &self,
        _session: &mut PreparedSessionCreate,
    ) -> AuthResult<()> {
        Ok(())
    }
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<crate::wire::UserView>>;
    /// Query the adapter ID field without the internal adapter's falsy-ID guard.
    /// Pure secondary session creation uses this lookup before publishing its user snapshot.
    async fn get_user_by_id_field(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        self.get_user_by_id(id.typed()?).await
    }

    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<crate::wire::UserView>>;
    /// Look up a username using the active transaction.
    async fn get_user_by_username(
        &self,
        _username: &str,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        Err(AuthError::config(
            "The store must support transactional username lookup",
        ))
    }
    /// Query a native User field value using the active transaction.
    async fn get_user_by_field_value(
        &self,
        _field: &str,
        _value: &crate::FieldValue,
    ) -> AuthResult<Option<crate::UserView>> {
        Err(AuthError::config(
            "The store must support native transactional user field queries",
        ))
    }
    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<crate::UserView>;
    /// Return null for a cancelled update or a missing row. Cancellation skips after hooks.
    async fn update_user_optional(
        &self,
        _id: &str,
        _update: UpdateUser,
    ) -> AuthResult<Option<crate::UserView>> {
        Err(AuthError::config(
            "The store must support nullable user updates",
        ))
    }
    /// Update a native adapter ID. Return None for cancellation or an unmatched ID.
    async fn update_user_by_id_value(
        &self,
        id: &crate::FieldValue,
        update: UpdateUser,
    ) -> AuthResult<Option<crate::UserView>> {
        self.update_user_by_field_value("id", id, update).await
    }
    /// Update the original native field selector without projecting a User ID first.
    async fn update_user_by_field_value(
        &self,
        field: &str,
        value: &crate::FieldValue,
        update: UpdateUser,
    ) -> AuthResult<Option<crate::UserView>> {
        if field != "id" {
            return Err(AuthError::config(
                "The store must support native transactional user field updates",
            ));
        }
        let id = value
            .as_str()
            .ok_or_else(|| AuthError::config("The store must support native user ID updates"))?;
        self.update_user_optional(id, update).await
    }
    async fn delete_user(&self, id: &str) -> AuthResult<()>;
    /// Delete children and the user, preserving cancellation for secondary cleanup.
    async fn delete_user_optional(
        &self,
        _id: &str,
        _delete_database_sessions: bool,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        Err(AuthError::config(
            "The store must preserve user deletion cancellation",
        ))
    }

    /// Select the representation accepted by transactional passkey creation.
    fn passkey_storage(&self) -> crate::PasskeyStorage {
        crate::PasskeyStorage::Legacy
    }
    async fn create_passkey(&self, passkey: CreatePasskey) -> AuthResult<Passkey>;
    /// Preserve a successful write whose adapter returns no row.
    async fn create_passkey_optional(&self, passkey: CreatePasskey) -> AuthResult<Option<Passkey>> {
        self.create_passkey(passkey).await.map(Some)
    }
    async fn create_user(&self, create_user: CreateUser) -> AuthResult<crate::wire::UserView>;
    async fn create_account(
        &self,
        create_account: CreateAccount,
    ) -> AuthResult<crate::wire::AccountView>;
    async fn create_session(
        &self,
        create_session: CreateSession,
    ) -> AuthResult<crate::wire::SessionView>;
    /// Defer secondary session writes until commit, after the session's database after hooks.
    /// Database-only adapters can use the ordinary transaction creation path.
    async fn create_session_with_deferred_secondary(
        &self,
        create_session: CreateSession,
    ) -> AuthResult<crate::wire::SessionView> {
        self.create_session(create_session).await
    }
    /// Preserve nullable Session readback while deferring secondary writes until commit.
    async fn create_session_with_deferred_secondary_optional(
        &self,
        create_session: CreateSession,
    ) -> AuthResult<Option<crate::wire::SessionView>> {
        self.create_session_optional(create_session).await
    }
}

#[async_trait]
pub trait UserStore<S: AuthSchema>: Send + Sync {
    /// Return whether the database adapter preserves native JSON at field-policy boundaries.
    fn supports_native_json(&self) -> bool {
        true
    }
    /// Verify an unverified user after deleting existing accounts and sessions in upstream order.
    /// Already verified users retain their accounts and sessions.
    async fn verify_user_and_revoke_unproven_access(
        &self,
        user_id: &str,
    ) -> AuthResult<Option<crate::wire::UserView>>;
    /// Preserve the native selector through cleanup, including falsy User lookup semantics.
    async fn verify_user_and_revoke_unproven_access_value(
        &self,
        user_id: &crate::FieldValue,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        let user_id = user_id.as_str().ok_or_else(|| {
            AuthError::config("The store must support native user verification selectors")
        })?;
        self.verify_user_and_revoke_unproven_access(user_id).await
    }
    async fn create_user(&self, create_user: CreateUser) -> AuthResult<crate::wire::UserView>;
    /// Return None when a before-create hook cancels the write.
    async fn create_user_optional(
        &self,
        input: CreateUser,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        self.create_user_fields_optional(input.into_user_fields()?)
            .await
    }
    /// Create a user from prepared internal-adapter fields without repeating input preparation.
    /// Run the same database hooks, adapter policies, write, and after hooks as convenience creation.
    async fn create_user_fields_optional(
        &self,
        input: crate::FieldMap,
    ) -> AuthResult<Option<crate::wire::UserView>>;
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<crate::wire::UserView>>;
    /// Query the adapter ID field without the internal adapter's falsy-ID guard.
    /// Pure secondary session creation uses this lookup before publishing its user snapshot.
    async fn get_user_by_id_field(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        self.get_user_by_id(id.typed()?).await
    }

    /// Query an ID supplied through a replacement organization schema.
    async fn get_user_by_id_value(
        &self,
        id: &crate::FieldValue,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        let id = id.as_str().ok_or_else(|| {
            crate::AuthError::config(
                "The store must support dynamic user ID queries for this schema",
            )
        })?;
        self.get_user_by_id(id).await
    }

    /// Fetch users by ID with an explicit adapter limit before output transforms.
    ///
    /// Implementations may return rows in any order. Callers must remap by id
    /// when response order matters.
    async fn list_users_by_ids(
        &self,
        ids: &[String],
        limit: f64,
    ) -> AuthResult<Vec<crate::UserView>>;
    /// Preserve native ID values in one limited query before output projection.
    async fn list_users_by_id_values(
        &self,
        ids: &[crate::FieldValue],
        limit: f64,
    ) -> AuthResult<Vec<crate::UserView>> {
        let ids = ids
            .iter()
            .map(|id| {
                id.as_str().map(str::to_owned).ok_or_else(|| {
                    AuthError::config("The store must support native user ID batch queries")
                })
            })
            .collect::<AuthResult<Vec<_>>>()?;
        self.list_users_by_ids(&ids, limit).await
    }
    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<crate::UserView>>;
    /// Read the user and the schema-selected Account relationship, preserving single-record and page results.
    async fn get_user_with_accounts(&self, _email: &str) -> AuthResult<Option<UserAccounts>> {
        Err(AuthError::config(
            "The store must support user account joins",
        ))
    }
    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<crate::UserView>>;
    /// Query a declared User field without narrowing its native runtime value.
    async fn get_user_by_field_value(
        &self,
        _field: &str,
        _value: &crate::FieldValue,
    ) -> AuthResult<Option<crate::UserView>> {
        Err(AuthError::config(
            "The store must support native user field queries",
        ))
    }
    async fn get_user_by_phone_number(
        &self,
        phone_number: &str,
    ) -> AuthResult<Option<crate::UserView>>;
    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<crate::UserView>;
    /// Return null for a cancelled update or a missing row. Cancellation skips after hooks.
    async fn update_user_optional(
        &self,
        _id: &str,
        _update: UpdateUser,
    ) -> AuthResult<Option<crate::UserView>> {
        Err(AuthError::config(
            "The store must support nullable user updates",
        ))
    }
    /// Update a native adapter ID. Return None for cancellation or an unmatched ID.
    async fn update_user_by_id_value(
        &self,
        id: &crate::FieldValue,
        update: UpdateUser,
    ) -> AuthResult<Option<crate::UserView>> {
        self.update_user_by_field_value("id", id, update).await
    }
    /// Update the original native field selector without projecting a User ID first.
    async fn update_user_by_field_value(
        &self,
        field: &str,
        value: &crate::FieldValue,
        update: UpdateUser,
    ) -> AuthResult<Option<crate::UserView>> {
        if field != "id" {
            return Err(AuthError::config(
                "The store must support native user field updates",
            ));
        }
        let id = value
            .as_str()
            .ok_or_else(|| AuthError::config("The store must support native user ID updates"))?;
        self.update_user_optional(id, update).await
    }
    async fn delete_user(&self, id: &str) -> AuthResult<()>;
    /// Delete owned records and the User with the original native selector.
    async fn delete_user_value(&self, id: &crate::FieldValue) -> AuthResult<()> {
        let id = id.as_str().ok_or_else(|| {
            AuthError::config("The store must support native user deletion selectors")
        })?;
        self.delete_user(id).await
    }
    /// Delete children and the user, preserving cancellation for secondary cleanup.
    async fn delete_user_optional(
        &self,
        _id: &str,
        _delete_database_sessions: bool,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        Err(AuthError::config(
            "The store must preserve user deletion cancellation",
        ))
    }

    /// Preserve a native deletion selector and cancellation before secondary cleanup.
    async fn delete_user_optional_value(
        &self,
        id: &crate::FieldValue,
        delete_database_sessions: bool,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        let id = id.as_str().ok_or_else(|| {
            AuthError::config("The store must support native user deletion selectors")
        })?;
        self.delete_user_optional(id, delete_database_sessions)
            .await
    }

    async fn list_users(
        &self,
        params: ListUsersParams,
    ) -> AuthResult<(Vec<crate::wire::UserView>, usize)>;
}

/// Resolve a team's capacity inside the invitation acceptance transaction.
#[async_trait]
pub trait TeamMemberLimitResolver: Send + Sync {
    async fn maximum(&self, team_id: &str) -> AuthResult<Option<usize>>;
}

/// Fixed and dynamic limits share the same atomic team reservation path.
#[derive(Clone, Copy)]
pub enum TeamMemberLimits<'a> {
    Fixed(Option<usize>),
    Resolver(&'a dyn TeamMemberLimitResolver),
}
impl TeamMemberLimits<'_> {
    pub async fn maximum(&self, team_id: &str) -> AuthResult<Option<usize>> {
        match self {
            Self::Fixed(maximum) => Ok(*maximum),
            Self::Resolver(resolver) => resolver.maximum(team_id).await,
        }
    }
}
impl From<Option<usize>> for TeamMemberLimits<'_> {
    fn from(value: Option<usize>) -> Self {
        Self::Fixed(value)
    }
}

#[async_trait]
pub trait SessionStore<S: AuthSchema>: Send + Sync {
    /// Create a session, preserving cancellation by a database before hook.
    async fn create_session_optional(
        &self,
        _input: CreateSession,
    ) -> AuthResult<Option<crate::wire::SessionView>> {
        Err(AuthError::config(
            "The store must support nullable session creation",
        ))
    }
    /// Run one Session creation lifecycle with an optional secondary write.
    async fn create_session_with_writer(
        &self,
        input: CreateSession,
        writer: Option<SessionCreateWriter>,
    ) -> AuthResult<Option<crate::wire::SessionView>> {
        if writer.is_some() {
            return Err(AuthError::config(
                "The store must support ordered secondary session creation",
            ));
        }
        self.create_session_optional(input).await
    }
    /// Run session before hooks and retain their cancellation result for cache-only creation.
    async fn before_create_runtime_session_optional(
        &self,
        input: &mut PreparedSessionCreate,
    ) -> AuthResult<bool> {
        self.before_create_runtime_session(input).await?;
        Ok(true)
    }

    /// Run one update lifecycle, with a secondary writer before the database write.
    async fn update_session_with_writer(
        &self,
        _token: &str,
        _update: database_hooks::SessionUpdate,
        _secondary: Option<SessionUpdateWriter>,
    ) -> AuthResult<Option<crate::wire::SessionView>> {
        Err(AuthError::config(
            "The store must support ordered secondary session updates",
        ))
    }

    /// Run an update using the projected token before adapter query conversion.
    async fn update_session_with_writer_by_token_value(
        &self,
        token: &crate::FieldValue,
        update: database_hooks::SessionUpdate,
        secondary: Option<SessionUpdateWriter>,
    ) -> AuthResult<Option<crate::wire::SessionView>> {
        let token = token.as_str().ok_or_else(|| {
            AuthError::config("The store must support native Session token updates")
        })?;
        self.update_session_with_writer(token, update, secondary)
            .await
    }

    /// Read a Session using its projected token before adapter query conversion.
    async fn get_session_by_token_value(
        &self,
        token: &crate::FieldValue,
    ) -> AuthResult<Option<crate::wire::SessionView>> {
        let token = token.as_str().ok_or_else(|| {
            AuthError::config("The store must support native Session token queries")
        })?;
        self.get_session(token).await
    }

    /// Apply logical fields using the projected token without narrowing the token.
    async fn update_session_fields_by_token_value(
        &self,
        token: &crate::FieldValue,
        fields: crate::FieldMap,
    ) -> AuthResult<Option<crate::wire::SessionView>> {
        let token = token.as_str().ok_or_else(|| {
            AuthError::config("The store must support native Session token updates")
        })?;
        self.update_session_fields(token, fields).await
    }

    /// Set the active team using native token and team values.
    async fn update_session_active_team_by_token_value(
        &self,
        token: &crate::FieldValue,
        team_id: Option<&crate::FieldValue>,
    ) -> AuthResult<crate::wire::SessionView> {
        self.update_session_fields_by_token_value(
            token,
            [(
                "activeTeamId".into(),
                team_id.cloned().unwrap_or(crate::FieldValue::Null),
            )]
            .into(),
        )
        .await?
        .ok_or(AuthError::SessionNotFound)
    }

    /// Set the active organization using native token and organization values.
    async fn update_session_active_organization_by_token_value(
        &self,
        token: &crate::FieldValue,
        organization_id: Option<&crate::FieldValue>,
    ) -> AuthResult<crate::wire::SessionView> {
        self.update_session_fields_by_token_value(
            token,
            [(
                "activeOrganizationId".into(),
                organization_id.cloned().unwrap_or(crate::FieldValue::Null),
            )]
            .into(),
        )
        .await?
        .ok_or(AuthError::SessionNotFound)
    }

    /// Accept an invitation without narrowing a projected Session token.
    async fn accept_invitation_with_teams_by_token_value(
        &self,
        invitation_id: &str,
        user_id: &str,
        session_token: Option<&crate::FieldValue>,
        teams_enabled: bool,
        maximum: TeamMemberLimits<'_>,
    ) -> AuthResult<(Member, Invitation, Option<crate::wire::SessionView>)> {
        let token = session_token
            .map(|token| {
                token.as_str().ok_or_else(|| {
                    AuthError::config(
                        "The store must support native Session token invitation acceptance",
                    )
                })
            })
            .transpose()?;
        self.accept_invitation_with_teams(invitation_id, user_id, token, teams_enabled, maximum)
            .await
    }

    /// None cancels cleanup. Some(0) means a completed write matched no rows.
    async fn delete_user_sessions_optional(
        &self,
        _user_id: &str,
        _preserve: bool,
    ) -> AuthResult<Option<usize>> {
        Err(AuthError::config(
            "The store must preserve batch session deletion cancellation",
        ))
    }

    /// Preserve the native User selector and batch cancellation before adapter query conversion.
    async fn delete_user_sessions_optional_value(
        &self,
        user_id: &crate::FieldValue,
        preserve: bool,
    ) -> AuthResult<Option<usize>> {
        let user_id = user_id.as_str().ok_or_else(|| {
            AuthError::config("The store must support native User selectors for Session cleanup")
        })?;
        self.delete_user_sessions_optional(user_id, preserve).await
    }

    /// Run session creation hooks when secondary storage owns the session.
    async fn before_create_runtime_session(
        &self,
        _session: &mut PreparedSessionCreate,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Run creation hooks with the captured explicit request after the session write.
    /// Keep the caller's ambient request scope when invoking each hook.
    async fn after_create_runtime_session(
        &self,
        _session: Option<&crate::wire::SessionView>,
        _request: Option<crate::hooks::RequestHookContext>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// End a live session while retaining its database row for audit.
    async fn end_session(&self, token: &str) -> AuthResult<()> {
        let now = chrono::Utc::now();
        if let Some(session) = self.get_session(token).await?
            && crate::entity::AuthSession::expires_at(&session).is_after(now)?
        {
            let _ = self.update_session_expiry(token, now).await?;
        }
        Ok(())
    }
    /// Expire preserved Sessions selected by a projected token.
    async fn end_session_by_token_value(&self, token: &crate::FieldValue) -> AuthResult<()> {
        let token = token.as_str().ok_or_else(|| {
            AuthError::config("The store must support native Session token expiry")
        })?;
        self.end_session(token).await
    }

    /// Read a session and an optional loaded relationship without discarding missing or array children.
    async fn get_session_snapshot(
        &self,
        token: &str,
    ) -> AuthResult<
        Option<(
            crate::wire::SessionView,
            Option<crate::session::SessionData<JoinValue<crate::wire::UserView>>>,
        )>,
    > {
        Ok(self
            .get_session(token)
            .await?
            .map(|session| (session, None)))
    }

    /// Read a native Session token without discarding a loaded User relationship.
    async fn get_session_snapshot_value(
        &self,
        token: &crate::FieldValue,
    ) -> AuthResult<
        Option<(
            crate::wire::SessionView,
            Option<crate::session::SessionData<JoinValue<crate::wire::UserView>>>,
        )>,
    > {
        if let Some(token) = token.as_str() {
            return self.get_session_snapshot(token).await;
        }
        Ok(self
            .get_session_by_token_value(token)
            .await?
            .map(|session| (session, None)))
    }

    /// Claim an invitation, then create its member and enabled team memberships in one transaction.
    /// If that transaction fails, restore a still-accepted invitation to pending through the adapter.
    /// Return the created member, claimed invitation, and optional single-team cookie snapshot.
    /// Capture the cookie snapshot before updating the active organization to preserve upstream write order.
    async fn accept_invitation_with_teams(
        &self,
        invitation_id: &str,
        user_id: &str,
        session_token: Option<&str>,
        teams_enabled: bool,
        maximum: TeamMemberLimits<'_>,
    ) -> AuthResult<(Member, Invitation, Option<crate::wire::SessionView>)>;
    async fn create_session(
        &self,
        create_session: CreateSession,
    ) -> AuthResult<crate::wire::SessionView>;
    async fn get_session(&self, token: &str) -> AuthResult<Option<crate::wire::SessionView>>;
    /// Read a token batch in adapter order, with the adapter limit and optional joined or cached projections.
    /// Joined projections complete adapter output policies before the batch returns.
    async fn get_session_snapshots(
        &self,
        tokens: &[String],
        only_active: bool,
    ) -> AuthResult<
        Vec<(
            crate::wire::SessionView,
            Option<crate::session::SessionData<JoinValue<crate::wire::UserView>>>,
        )>,
    >;
    /// Persist application session fields and update the modification timestamp.
    async fn update_session_fields(
        &self,
        token: &str,
        fields: crate::FieldMap,
    ) -> AuthResult<Option<crate::wire::SessionView>>;
    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<crate::wire::SessionView>>;
    /// List Sessions without narrowing the projected User ID before adapter query conversion.
    async fn get_user_sessions_value(
        &self,
        user_id: &crate::FieldValue,
    ) -> AuthResult<Vec<crate::wire::SessionView>> {
        let user_id = user_id.as_str().ok_or_else(|| {
            AuthError::config("The store must support native User selectors for Session queries")
        })?;
        self.get_user_sessions(user_id).await
    }
    /// List stored sessions with optional secondary projections that preserve absent fields.
    async fn get_user_session_snapshots(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<(crate::wire::SessionView, Option<crate::wire::SessionView>)>> {
        Ok(self
            .get_user_sessions(user_id)
            .await?
            .into_iter()
            .map(|session| (session, None))
            .collect())
    }

    async fn update_session_expiry(
        &self,
        token: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<crate::wire::SessionView>;
    async fn delete_session(&self, token: &str) -> AuthResult<()>;
    /// Delete using the projected token before the adapter applies query conversion.
    async fn delete_session_by_token_value(&self, token: &crate::FieldValue) -> AuthResult<()> {
        let token = token.as_str().ok_or_else(|| {
            AuthError::config("The store must support native Session token deletion")
        })?;
        self.delete_session(token).await
    }

    /// Delete a token list through one batch lifecycle. Do not update active-session indices.
    async fn delete_sessions(&self, _tokens: &[String]) -> AuthResult<()> {
        Err(AuthError::config(
            "The store must support token-list batch session deletion",
        ))
    }
    /// End live rows for a token list through one batch lifecycle, preserving stored rows.
    async fn end_sessions(&self, _tokens: &[String]) -> AuthResult<()> {
        Err(AuthError::config(
            "The store must support token-list batch session expiry",
        ))
    }
    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()>;
    /// Revoke Sessions without narrowing the projected User ID before adapter query conversion.
    async fn delete_user_sessions_by_user_value(
        &self,
        user_id: &crate::FieldValue,
    ) -> AuthResult<()> {
        let user_id = user_id.as_str().ok_or_else(|| {
            AuthError::config("The store must support native User selectors for Session deletion")
        })?;
        self.delete_user_sessions(user_id).await
    }
    async fn delete_expired_sessions(&self) -> AuthResult<usize>;
    async fn update_session_active_team(
        &self,
        token: &str,
        team_id: Option<&str>,
    ) -> AuthResult<crate::wire::SessionView>;
    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<crate::wire::SessionView>;
}

mod joins;
pub use joins::{
    AccountOwner, InvitationOrganization, JoinValue, MemberUser, OrganizationDetails,
    OrganizationDetailsQuery, OrganizationKey, ResolvedJoin, UserAccounts,
};

#[async_trait]
pub trait AccountStore<S: AuthSchema>: Send + Sync {
    async fn create_account(
        &self,
        create_account: CreateAccount,
    ) -> AuthResult<crate::wire::AccountView>;
    /// Create an account, returning `None` when its own before-create hook cancels the write.
    /// Hook errors, including errors from nested writes, remain errors.
    async fn create_account_optional(
        &self,
        create_account: CreateAccount,
    ) -> AuthResult<Option<crate::wire::AccountView>> {
        self.create_account(create_account).await.map(Some)
    }
    async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<crate::wire::AccountView>>;
    /// Read at most two matching accounts and their schema-selected User relationships before checking duplicate identities.
    async fn get_account_owner(
        &self,
        _provider: &str,
        _account_id: &str,
    ) -> AuthResult<Option<AccountOwner>> {
        Err(AuthError::config(
            "The store must support account owner joins",
        ))
    }
    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<crate::wire::AccountView>>;
    /// List Accounts with the native User selector before adapter query conversion.
    async fn get_user_accounts_value(
        &self,
        user_id: &crate::FieldValue,
    ) -> AuthResult<Vec<crate::wire::AccountView>> {
        let user_id = user_id.as_str().ok_or_else(|| {
            AuthError::config("The store must support native User selectors for Account queries")
        })?;
        self.get_user_accounts(user_id).await
    }
    /// Read the current user's credential account independently of list pagination.
    /// Match the stored user ID, credential provider, and account ID before output projection.
    async fn get_credential_account(
        &self,
        user_id: &str,
    ) -> AuthResult<Option<crate::wire::AccountView>>;
    /// Match the credential owner and provider with the original native User selector.
    async fn get_credential_account_value(
        &self,
        user_id: &crate::FieldValue,
    ) -> AuthResult<Option<crate::wire::AccountView>> {
        let user_id = user_id.as_str().ok_or_else(|| {
            AuthError::config("The store must support native credential Account selectors")
        })?;
        self.get_credential_account(user_id).await
    }
    async fn update_account(
        &self,
        id: &str,
        update: UpdateAccount,
    ) -> AuthResult<crate::wire::AccountView>;
    /// Update an account, returning `None` when its own before-update hook cancels the write.
    /// Stores without cancellable hooks may use the default implementation.
    async fn update_account_optional(
        &self,
        id: &str,
        update: UpdateAccount,
    ) -> AuthResult<Option<crate::wire::AccountView>> {
        self.update_account(id, update).await.map(Some)
    }
    /// Preserve the native Account ID through cancellation, conversion, and persistence.
    async fn update_account_by_id_value(
        &self,
        id: &crate::FieldValue,
        update: UpdateAccount,
    ) -> AuthResult<Option<crate::wire::AccountView>> {
        let id = id
            .as_str()
            .ok_or_else(|| AuthError::config("The store must support native Account ID updates"))?;
        self.update_account_optional(id, update).await
    }
    async fn delete_account(&self, id: &str) -> AuthResult<()>;
    /// Delete the Account batch selected by its native owner through one hook lifecycle.
    async fn delete_user_accounts_value(&self, _user_id: &crate::FieldValue) -> AuthResult<()> {
        Err(AuthError::config(
            "The store must support native Account batch deletion",
        ))
    }
    /// Delete one Account with its native selector and per-record hook lifecycle.
    async fn delete_account_value(&self, id: &crate::FieldValue) -> AuthResult<()> {
        let id = id.as_str().ok_or_else(|| {
            AuthError::config("The store must support native Account selectors for deletion")
        })?;
        self.delete_account(id).await
    }
}

#[async_trait]
pub trait VerificationStore<S: AuthSchema>: Send + Sync {
    /// Preserve cancellation and a successful adapter creation with no returned row.
    async fn create_verification_optional(
        &self,
        _verification: CreateVerification,
    ) -> AuthResult<Option<crate::wire::VerificationView>> {
        Err(AuthError::config(
            "The store must support nullable verification creation",
        ))
    }

    /// Run a verification create lifecycle, then its secondary write, then queue database after hooks.
    async fn create_verification_with_writer(
        &self,
        verification: CreateVerification,
        writer: Option<VerificationCreateWriter>,
    ) -> AuthResult<Option<crate::wire::VerificationView>> {
        if writer.is_some() {
            return Err(AuthError::config(
                "The store must support ordered verification creation",
            ));
        }
        self.create_verification_optional(verification).await
    }

    /// Update adapter fields and return the projection produced after the write.
    async fn update_verification(
        &self,
        identifier: &str,
        update: database_hooks::VerificationUpdate,
    ) -> AuthResult<Option<crate::wire::VerificationView>>;

    /// Reserve an identifier with the upstream deterministic SHA-256 primary key.
    async fn reserve_verification_value(
        &self,
        verification: CreateVerification,
    ) -> AuthResult<bool> {
        use base64::Engine;
        use sha2::{Digest, Sha256};
        let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(format!(
            "reserve:{}",
            verification.identifier.display_string()?
        )));
        self.reserve_verification(&id, verification).await
    }

    /// Run verification creation hooks when secondary storage owns the record.
    /// Run verification before hooks without converting cancellation into an error.
    async fn before_create_runtime_verification_optional(
        &self,
        verification: &mut CreateVerification,
    ) -> AuthResult<bool> {
        self.before_create_runtime_verification(verification)
            .await?;
        Ok(true)
    }

    async fn before_create_runtime_verification(
        &self,
        _verification: &mut CreateVerification,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Run creation hooks with the captured explicit request after the verification write.
    /// Keep the caller's ambient request scope when invoking each hook.
    async fn after_create_runtime_verification(
        &self,
        _verification: Option<&crate::wire::VerificationView>,
        _request: Option<crate::hooks::RequestHookContext>,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Insert a deterministic primary key. Return false when the reservation already exists.
    async fn reserve_verification(
        &self,
        id: &str,
        verification: CreateVerification,
    ) -> AuthResult<bool>;

    /// Fetch the newest record, including expired records for protocol-specific expiry errors.
    async fn get_verification_including_expired(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<crate::wire::VerificationView>>;
    /// Update every record matching an identifier without consuming the verification.
    async fn update_verification_by_identifier(
        &self,
        identifier: &str,
        value: Option<String>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> AuthResult<()>;
    /// Delete every verification record for an identifier.
    async fn delete_verification_by_identifier(&self, identifier: &str) -> AuthResult<()>;
    async fn create_verification(
        &self,
        verification: CreateVerification,
    ) -> AuthResult<crate::wire::VerificationView>;
    async fn get_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<crate::wire::VerificationView>>;
    async fn get_verification_by_value(
        &self,
        value: &str,
    ) -> AuthResult<Option<crate::wire::VerificationView>>;
    async fn get_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<crate::wire::VerificationView>>;
    async fn consume_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<crate::wire::VerificationView>>;
    /// Atomically consume the newest record and delete every record for the identifier.
    /// Expired records are consumed but return `None`; only one concurrent caller succeeds.
    async fn consume_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<crate::wire::VerificationView>>;
    /// Atomically consume the latest row and invalidate all rows for the identifier, including expired rows.
    /// Runtime storage uses the raw expiry to invalidate migrated cache entries before rejecting expired values.
    async fn consume_verification_including_expired(
        &self,
        _identifier: &str,
    ) -> AuthResult<Option<crate::wire::VerificationView>> {
        Err(crate::AuthError::config(
            "The store must support raw atomic verification consumption for runtime storage",
        ))
    }
    async fn delete_verification(&self, id: &str) -> AuthResult<()>;
    async fn delete_expired_verifications(&self) -> AuthResult<usize>;
}

/// Query parameters for listing organization members.
#[derive(Debug, Clone, Default)]
pub struct ListOrganizationMembersParams {
    /// Organization id whose members should be listed.
    pub organization_id: crate::SchemaValue<String>,
    /// Maximum number of members to return.
    pub limit: Option<f64>,
    /// Number of matching members to skip before returning rows.
    pub offset: Option<f64>,
    /// Client-visible field name used for sorting.
    pub sort_by: Option<String>,
    /// Sort direction (`asc` or `desc`).
    pub sort_direction: Option<String>,
    /// Client-visible field name used for filtering.
    pub filter_field: Option<String>,
    /// Filter value paired with `filter_field`.
    pub filter_value: Option<crate::FieldValue>,
    /// Filter operator (`eq`, `ne`, `contains`, `gt`, `gte`, `lt`, `lte`).
    pub filter_operator: Option<String>,
}

#[async_trait]
pub trait OrganizationStore: Send + Sync {
    /// Insert a complete organization record without route policies or application hooks.
    async fn insert_organization(&self, _record: Organization) -> AuthResult<Organization> {
        Err(AuthError::config(
            "The store must support inserting organization records",
        ))
    }
    /// Delete members, invitations, then the organization without an enclosing transaction.
    /// A later failure preserves preceding deletes, matching direct adapter cleanup.
    async fn delete_organization_records(&self, _id: &str) -> AuthResult<()> {
        Err(AuthError::config(
            "The store must support raw organization cleanup",
        ))
    }

    /// Register the Organization plugin's field policies before serving requests.
    /// Stores must call `OrganizationFields::into_storage` before saving the configuration.
    fn configure_organization_fields(
        &self,
        fields: crate::organization_fields::OrganizationFields,
    ) -> AuthResult<()> {
        if fields.is_empty() {
            Ok(())
        } else {
            Err(crate::AuthError::config(
                "The store does not support organization additional fields",
            ))
        }
    }
    /// Read the organization and its child pages, then load the member users.
    /// Native joins must select the organization and all child pages in one statement.
    async fn get_organization_details(
        &self,
        _query: OrganizationDetailsQuery<'_>,
    ) -> AuthResult<Option<OrganizationDetails>> {
        Err(AuthError::config(
            "The store must support full organization reads",
        ))
    }
    async fn create_organization(&self, org: CreateOrganization) -> AuthResult<Organization>;
    async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<Organization>>;
    /// Query an ID supplied through a replacement organization schema.
    async fn get_organization_by_id_value(
        &self,
        id: &crate::FieldValue,
    ) -> AuthResult<Option<Organization>> {
        let id = id.as_str().ok_or_else(|| {
            crate::AuthError::config(
                "The store must support dynamic organization ID queries for this schema",
            )
        })?;
        self.get_organization_by_id(id).await
    }

    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Organization>>;
    /// Look up a slug whose type was replaced by an application schema.
    async fn get_organization_by_slug_value(
        &self,
        slug: &crate::FieldValue,
    ) -> AuthResult<Option<Organization>> {
        let slug = slug.as_str().ok_or_else(|| {
            crate::AuthError::config(
                "The store must support organization slug values for this schema",
            )
        })?;
        self.get_organization_by_slug(slug).await
    }
    /// Fetch multiple organizations by id.
    ///
    /// Implementations may return rows in any order. Callers must remap by id
    /// when response order matters.
    async fn list_organizations_by_ids(&self, ids: &[String]) -> AuthResult<Vec<Organization>>;
    async fn update_organization(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Organization>;
    async fn update_organization_value(
        &self,
        id: &crate::FieldValue,
        update: UpdateOrganization,
    ) -> AuthResult<Organization> {
        let id = crate::SchemaValue::<String>::from_field(id.clone());
        self.update_organization(id.typed()?, update).await
    }
    async fn delete_organization(&self, id: &str) -> AuthResult<()>;
    async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<Organization>>;
    /// Query membership with the original native User ID and existing join policy.
    async fn list_user_organizations_value(
        &self,
        user_id: &crate::FieldValue,
    ) -> AuthResult<Vec<Organization>> {
        let user_id = user_id.as_str().ok_or_else(|| {
            AuthError::config("The store must support native organization membership queries")
        })?;
        self.list_user_organizations(user_id).await
    }
}

#[async_trait]
pub trait MemberStore: Send + Sync {
    /// Insert a complete member record without route policies or application hooks.
    async fn insert_member(&self, _record: Member) -> AuthResult<Member> {
        Err(AuthError::config(
            "The store must support inserting member records",
        ))
    }

    async fn create_member(&self, member: CreateMember) -> AuthResult<Member>;
    async fn get_member(&self, organization_id: &str, user_id: &str) -> AuthResult<Option<Member>>;
    /// Query member references supplied through a replacement organization schema.
    async fn get_member_value(
        &self,
        organization_id: &crate::FieldValue,
        user_id: &crate::FieldValue,
    ) -> AuthResult<Option<Member>> {
        let organization_id = organization_id.as_str().ok_or_else(|| {
            crate::AuthError::config(
                "The store must support dynamic member reference queries for this schema",
            )
        })?;
        let user_id = user_id.as_str().ok_or_else(|| {
            crate::AuthError::config(
                "The store must support dynamic member reference queries for this schema",
            )
        })?;
        self.get_member(organization_id, user_id).await
    }

    /// Read a member and its stored user, projecting the member before the user.
    async fn get_member_with_user(
        &self,
        _organization_id: &str,
        _user_id: &str,
    ) -> AuthResult<Option<MemberUser>> {
        Err(AuthError::config(
            "The store must support member user joins",
        ))
    }
    /// Query member references accepted by a replacement organization schema.
    async fn get_member_with_user_value(
        &self,
        organization_id: &crate::FieldValue,
        user_id: &crate::FieldValue,
    ) -> AuthResult<Option<MemberUser>> {
        let organization_id = organization_id.as_str().ok_or_else(|| {
            AuthError::config(
                "The store must support dynamic member reference queries for this schema",
            )
        })?;
        let user_id = user_id.as_str().ok_or_else(|| {
            AuthError::config(
                "The store must support dynamic member reference queries for this schema",
            )
        })?;
        self.get_member_with_user(organization_id, user_id).await
    }
    /// Read one member by its stored ID and project its stored user.
    /// Return an error if the selected member has no stored user.
    async fn get_member_by_id_with_user(&self, _id: &str) -> AuthResult<Option<MemberUser>> {
        Err(AuthError::config(
            "The store must support member user joins",
        ))
    }
    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<Member>>;
    async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<Member>;
    async fn delete_member(&self, member_id: &str) -> AuthResult<()>;
    /// Preserve the original membership subject when a creation hook changes the saved member.
    async fn delete_member_for_user(
        &self,
        _member_id: &str,
        _organization_id: &str,
        _user_id: &str,
    ) -> AuthResult<()> {
        Err(AuthError::config(
            "The store must support member deletion with an explicit subject",
        ))
    }
    async fn list_organization_members(&self, org_id: &str) -> AuthResult<Vec<Member>>;
    async fn list_organization_members_value(
        &self,
        org_id: &crate::FieldValue,
    ) -> AuthResult<Vec<Member>> {
        let id = crate::SchemaValue::<String>::from_field(org_id.clone());
        self.list_organization_members(id.typed()?).await
    }
    /// Query organization members with filter, sort, and pagination applied in
    /// the store when possible.
    async fn query_organization_members(
        &self,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<(Vec<Member>, usize)>;
    async fn count_organization_members(&self, org_id: &str) -> AuthResult<i64>;
    /// Count using an organization ID accepted by the configured member schema.
    async fn count_organization_members_value(
        &self,
        org_id: &crate::FieldValue,
    ) -> AuthResult<i64> {
        let id = crate::SchemaValue::<String>::from_field(org_id.clone());
        self.count_organization_members(id.typed()?).await
    }
    async fn count_organization_owners(&self, org_id: &str) -> AuthResult<i64>;
}

#[async_trait]
pub trait InvitationStore: Send + Sync {
    async fn create_invitation(&self, invitation: CreateInvitation) -> AuthResult<Invitation>;
    async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<Invitation>>;
    async fn get_pending_invitation(
        &self,
        org_id: &str,
        email: &str,
    ) -> AuthResult<Option<Invitation>>;
    async fn get_pending_invitation_value(
        &self,
        org_id: &crate::FieldValue,
        email: &str,
    ) -> AuthResult<Option<Invitation>> {
        let id = crate::SchemaValue::<String>::from_field(org_id.clone());
        self.get_pending_invitation(id.typed()?, email).await
    }
    async fn update_invitation_status(
        &self,
        id: &str,
        status: InvitationStatus,
    ) -> AuthResult<Invitation>;
    /// Renew an invitation without changing its identity, role, or inviter.
    async fn update_invitation_expiry(
        &self,
        id: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Invitation>;
    async fn list_organization_invitations(&self, org_id: &str) -> AuthResult<Vec<Invitation>>;
    async fn list_organization_invitations_value(
        &self,
        org_id: &crate::FieldValue,
    ) -> AuthResult<Vec<Invitation>> {
        let id = crate::SchemaValue::<String>::from_field(org_id.clone());
        self.list_organization_invitations(id.typed()?).await
    }
    /// Count still-pending, unexpired invitations for an organization.
    async fn count_pending_organization_invitations(&self, org_id: &str) -> AuthResult<i64>;
    async fn count_pending_organization_invitations_value(
        &self,
        org_id: &crate::FieldValue,
    ) -> AuthResult<i64> {
        let id = crate::SchemaValue::<String>::from_field(org_id.clone());
        self.count_pending_organization_invitations(id.typed()?)
            .await
    }
    /// Read the email's adapter-limited page before status filtering, with its stored organizations.
    async fn list_user_invitations(&self, email: &str) -> AuthResult<Vec<InvitationOrganization>>;
}

#[async_trait]
pub trait TwoFactorStore: Send + Sync {
    /// Create complete logical fields through the shared adapter policies.
    async fn create_two_factor_record(
        &self,
        input: crate::FieldMap,
    ) -> AuthResult<Option<crate::FieldMap>>;
    /// Read complete projected fields without narrowing native replacements.
    async fn get_two_factor_record(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<crate::FieldMap>>;
    /// Apply a logical patch through the shared adapter policies.
    async fn update_two_factor_record(
        &self,
        id: &crate::SchemaValue<String>,
        input: crate::FieldMap,
    ) -> AuthResult<Option<crate::FieldMap>>;
    /// Query the projected owner without string conversion.
    async fn get_two_factor_by_user_id_value(
        &self,
        user_id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<TwoFactor>>;
    /// Delete by the projected owner without string conversion.
    async fn delete_two_factor_by_user_id_value(
        &self,
        user_id: &crate::SchemaValue<String>,
    ) -> AuthResult<()>;
    async fn create_two_factor(&self, two_factor: CreateTwoFactor) -> AuthResult<TwoFactor>;
    async fn get_two_factor_by_user_id(&self, user_id: &str) -> AuthResult<Option<TwoFactor>> {
        self.get_two_factor_by_user_id_value(&user_id.into()).await
    }
    async fn update_two_factor_backup_codes(
        &self,
        user_id: &str,
        backup_codes: &str,
    ) -> AuthResult<TwoFactor>;
    /// Update an existing authenticator enrollment.
    async fn update_two_factor(
        &self,
        id: &crate::SchemaValue<String>,
        update: crate::types::UpdateTwoFactor,
    ) -> AuthResult<TwoFactor>;
    /// Replace backup codes only if the stored value still equals the caller's snapshot.
    async fn compare_exchange_two_factor_backup_codes(
        &self,
        id: &crate::SchemaValue<String>,
        previous: &crate::FieldValue,
        replacement: crate::FieldValue,
    ) -> AuthResult<bool>;
    /// Atomically count a failed verification, then apply the lock if the budget is spent.
    /// Invoke `locked_until` once after the increment reaches `max_attempts`, before the guarded lock update.
    async fn record_two_factor_failure(
        &self,
        id: &crate::SchemaValue<String>,
        max_attempts: i64,
        locked_until: &(dyn Fn() -> AuthResult<crate::FieldDate> + Send + Sync),
    ) -> AuthResult<()>;
    /// Reset failed verifications, optionally requiring an expired lock.
    async fn reset_two_factor_failures(
        &self,
        id: &crate::SchemaValue<String>,
        locked_before: Option<crate::FieldDate>,
    ) -> AuthResult<()>;
    async fn delete_two_factor(&self, user_id: &str) -> AuthResult<()> {
        self.delete_two_factor_by_user_id_value(&user_id.into())
            .await
    }
}

#[async_trait]
pub trait ApiKeyStore: Send + Sync {
    /// Create a complete adapter record before field policies and storage conversion.
    async fn create_api_key_record(
        &self,
        _input: crate::FieldMap,
    ) -> AuthResult<Option<crate::FieldMap>> {
        Err(AuthError::config(
            "The store must support API Key record writes",
        ))
    }

    /// Read complete projected adapter fields before constructing a typed record.
    async fn get_api_key_record(
        &self,
        _id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<crate::FieldMap>> {
        Err(AuthError::config(
            "The store must support ApiKey record reads",
        ))
    }

    /// Update declared fields without narrowing replacement values to the ordinary input types.
    async fn update_api_key_record(
        &self,
        _id: &crate::SchemaValue<String>,
        _input: crate::FieldMap,
    ) -> AuthResult<Option<crate::FieldMap>> {
        Err(AuthError::config(
            "The store must support API Key record writes",
        ))
    }

    async fn create_api_key(&self, input: CreateApiKey) -> AuthResult<ApiKey>;
    async fn get_api_key_by_id(&self, id: &str) -> AuthResult<Option<ApiKey>>;
    /// Read an internal API key ID without replacing an omitted Memory adapter ID.
    async fn get_api_key_by_id_value(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<ApiKey>> {
        self.get_api_key_by_id(id.typed()?).await
    }
    async fn get_api_key_by_hash(&self, hash: &str) -> AuthResult<Option<ApiKey>>;
    /// Read API keys with the adapter's default limit and no explicit sort.
    async fn list_api_keys_by_reference(&self, reference_id: &str) -> AuthResult<Vec<ApiKey>> {
        self.find_api_keys_by_reference(reference_id, None).await
    }
    /// Read API keys, sorting before the adapter's default limit.
    /// `sort` contains the schema field name and `asc` or `desc` direction.
    async fn find_api_keys_by_reference(
        &self,
        reference_id: &str,
        sort: Option<(&str, &str)>,
    ) -> AuthResult<Vec<ApiKey>> {
        self.find_api_keys_by_reference_value(&reference_id.into(), sort)
            .await
    }
    /// Query a native reference value through the selected field declaration.
    async fn find_api_keys_by_reference_value(
        &self,
        reference_id: &crate::FieldValue,
        sort: Option<(&str, &str)>,
    ) -> AuthResult<Vec<ApiKey>>;
    /// Count all matching API keys without applying the adapter's default limit.
    async fn count_api_keys_by_reference(&self, reference_id: &str) -> AuthResult<u64> {
        self.count_api_keys_by_reference_value(&reference_id.into())
            .await
    }
    /// Count a native reference value through the selected field declaration.
    async fn count_api_keys_by_reference_value(
        &self,
        reference_id: &crate::FieldValue,
    ) -> AuthResult<u64>;
    async fn update_api_key(
        &self,
        id: &crate::SchemaValue<String>,
        update: UpdateApiKey,
    ) -> AuthResult<ApiKey>;
    /// Update a matching key, returning `None` when no row matches.
    /// Legacy metadata repair permits a missing database row in secondary-storage mode.
    async fn update_api_key_optional(
        &self,
        id: &crate::SchemaValue<String>,
        update: UpdateApiKey,
    ) -> AuthResult<Option<ApiKey>> {
        self.update_api_key(id, update).await.map(Some)
    }
    async fn delete_api_key(&self, id: &crate::SchemaValue<String>) -> AuthResult<()>;
    async fn delete_expired_api_keys(&self) -> AuthResult<usize>;

    /// Apply one conditional usage write and return the resulting row.
    /// A failed guard returns `None`; each successful call commits independently.
    async fn write_api_key_usage(
        &self,
        id: &crate::SchemaValue<String>,
        write: ApiKeyUsageWrite,
    ) -> AuthResult<Option<ApiKey>>;

    /// Consume quota, claim a rate slot, and update the timestamp in adapter order.
    /// Earlier writes remain committed if a later write fails.
    async fn consume_api_key_usage(
        &self,
        snapshot: &ApiKey,
        global_rate_limit_enabled: bool,
    ) -> AuthResult<ConsumeApiKeyResult> {
        api_key_usage::consume(self, snapshot, global_rate_limit_enabled).await
    }
}

/// Outcome of an atomic API key usage consumption.
pub enum ConsumeApiKeyResult {
    /// The key was valid and counters were updated. Contains the updated key.
    Allowed(Box<ApiKey>),
    /// The rate limit was exceeded after consuming the request's usage quota.
    RateLimited {
        /// Milliseconds until the current rate-limit window ends.
        try_again_in: f64,
    },
    /// The quota was exhausted. Non-refillable keys at zero quota are deleted.
    UsageExhausted,
}

#[async_trait]
pub trait PasskeyStore: Send + Sync {
    /// Create a complete adapter record before field policies and storage conversion.
    async fn create_passkey_record(
        &self,
        _input: crate::FieldMap,
    ) -> AuthResult<Option<crate::FieldMap>> {
        Err(AuthError::config(
            "The store must support Passkey record writes",
        ))
    }

    /// Read complete projected adapter fields before constructing a typed record.
    async fn get_passkey_record(
        &self,
        _id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<crate::FieldMap>> {
        Err(AuthError::config(
            "The store must support Passkey record reads",
        ))
    }

    /// Update declared fields without narrowing replacement values to the ordinary input types.
    async fn update_passkey_record(
        &self,
        _id: &crate::SchemaValue<String>,
        _input: crate::FieldMap,
    ) -> AuthResult<Option<crate::FieldMap>> {
        Err(AuthError::config(
            "The store must support Passkey record writes",
        ))
    }

    /// Select the representation accepted by passkey creation and authentication updates.
    fn passkey_storage(&self) -> crate::PasskeyStorage {
        crate::PasskeyStorage::Legacy
    }
    async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<Passkey>;
    /// Preserve private passkey fields while retaining a nullable adapter result.
    async fn create_passkey_optional(&self, input: CreatePasskey) -> AuthResult<Option<Passkey>> {
        self.create_passkey(input).await.map(Some)
    }
    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<Passkey>>;
    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AuthResult<Option<Passkey>>;
    /// Query an ordinary string owner through the native-value path.
    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<Passkey>> {
        self.list_passkeys_by_user_value(&user_id.into()).await
    }
    /// Query the native owner value without string coercion.
    async fn list_passkeys_by_user_value(
        &self,
        user_id: &crate::FieldValue,
    ) -> AuthResult<Vec<Passkey>>;
    async fn update_passkey_authentication(
        &self,
        id: &crate::SchemaValue<String>,
        update: UpdatePasskeyAuthentication,
    ) -> AuthResult<Passkey>;
    /// Apply display fields and the optional counter in one adapter write.
    async fn update_passkey(
        &self,
        id: &crate::SchemaValue<String>,
        update: UpdatePasskey,
    ) -> AuthResult<Passkey>;
    /// Update a string name through the shared passkey field policies.
    async fn update_passkey_name(&self, id: &str, name: &str) -> AuthResult<Passkey> {
        self.update_passkey(
            &id.to_owned().into(),
            UpdatePasskey {
                name: Some(name.to_owned()).into(),
                ..Default::default()
            },
        )
        .await
    }
    async fn delete_passkey(&self, id: &str) -> AuthResult<()>;
}

/// Persistence for OAuth device authorization codes.
#[async_trait]
pub trait DeviceCodeStore: Send + Sync {
    /// Create a complete logical record through the shared adapter field policies.
    async fn create_device_code_record(
        &self,
        fields: crate::FieldMap,
    ) -> AuthResult<Option<crate::FieldMap>>;
    /// Read a complete logical record without narrowing native values.
    async fn get_device_code_record(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<crate::FieldMap>>;
    /// Apply a logical patch through the same policies as record creation.
    async fn update_device_code_record(
        &self,
        id: &crate::SchemaValue<String>,
        fields: crate::FieldMap,
    ) -> AuthResult<Option<crate::FieldMap>>;

    /// Persist a newly-issued device code.
    async fn create_device_code(&self, input: CreateDeviceCode) -> AuthResult<DeviceCode>;
    /// Fetch a device code by its opaque device-facing token.
    async fn get_device_code_by_device_code(
        &self,
        device_code: &str,
    ) -> AuthResult<Option<DeviceCode>>;
    /// Fetch a device code by its user-facing verification code.
    async fn get_device_code_by_user_code(&self, user_code: &str)
    -> AuthResult<Option<DeviceCode>>;
    /// Update mutable device-code state such as approval status or poll time.
    async fn update_device_code(
        &self,
        id: &crate::SchemaValue<String>,
        update: UpdateDeviceCode,
    ) -> AuthResult<DeviceCode>;
    /// Update a device code only when it still has the expected status.
    ///
    /// Returns `true` when the compare-and-swap succeeds, or `false` when the
    /// row was already moved to a different state.
    async fn update_device_code_if_status(
        &self,
        id: &crate::SchemaValue<String>,
        current_status: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<bool>;
    /// Bind a still-pending, still-unclaimed device code to a user.
    ///
    /// Returns `true` when this call performed the claim, and `false` when the
    /// row was already claimed or no longer pending. The status and
    /// unclaimed checks are part of the write so two concurrent verifiers
    /// cannot both claim the same code.
    async fn claim_device_code(
        &self,
        id: &crate::SchemaValue<String>,
        user_id: &crate::SchemaValue<String>,
    ) -> AuthResult<bool>;
    /// Consume an approved code while preserving its original identity and owner bindings.
    /// Return and project the actual consumed row, including changes to its scope or poll timestamp.
    /// Evaluate field ownership against stored values after preparation, without invoking field input callbacks.
    async fn consume_device_code(
        &self,
        expected: &DeviceCode,
        ownership: &crate::DeviceCodeOwnership,
    ) -> AuthResult<Option<DeviceCode>>;
    /// Delete a device code record.
    async fn delete_device_code(&self, id: &crate::SchemaValue<String>) -> AuthResult<()>;
    /// Delete a device code only when it still has the expected status.
    ///
    /// Returns `true` when a matching row was deleted and `false` otherwise.
    async fn delete_device_code_if_status(
        &self,
        id: &crate::SchemaValue<String>,
        status: &str,
    ) -> AuthResult<bool>;
}

#[async_trait]
pub trait TransactionStore<S: AuthSchema>: Send + Sync {
    async fn transaction_boxed(
        &self,
        work: Box<TransactionWork<S>>,
    ) -> AuthResult<BoxedTransactionValue>;
}

#[async_trait]
pub trait WalletStore: Send + Sync {
    /// Create complete wallet fields through shared adapter policies.
    async fn create_wallet_address_record(
        &self,
        input: crate::FieldMap,
    ) -> AuthResult<Option<crate::FieldMap>>;
    /// Read complete wallet fields by the adapter ID.
    async fn get_wallet_address_record(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<crate::FieldMap>>;
    /// Apply a complete logical patch to a wallet record.
    async fn update_wallet_address_record(
        &self,
        id: &crate::SchemaValue<String>,
        input: crate::FieldMap,
    ) -> AuthResult<Option<crate::FieldMap>>;
    /// Delete wallet records selected by the adapter's ID query policy.
    async fn delete_wallet_address_record(&self, id: &crate::SchemaValue<String>)
    -> AuthResult<()>;
    /// Find a wallet using native address and optional chain values.
    async fn get_wallet_address_value(
        &self,
        address: &crate::FieldValue,
        chain_id: Option<&crate::FieldValue>,
    ) -> AuthResult<Option<crate::WalletAddress>>;
    /// Find a wallet using ordinary Rust inputs.
    async fn get_wallet_address(
        &self,
        address: &str,
        chain_id: Option<i64>,
    ) -> AuthResult<Option<crate::WalletAddress>> {
        let chain_id = chain_id.map(crate::FieldValue::from);
        self.get_wallet_address_value(&address.into(), chain_id.as_ref())
            .await
    }
    /// Create a wallet using ordinary Rust inputs.
    async fn create_wallet_address(
        &self,
        wallet: crate::CreateWalletAddress,
    ) -> AuthResult<crate::WalletAddress> {
        crate::FromFieldMap::from_field_values(
            self.create_wallet_address_record(wallet.into_adapter_fields()?)
                .await?
                .ok_or_else(|| AuthError::internal("Wallet creation returned no record"))?,
        )
    }
}

/// Persistence for organization teams and team membership.
#[async_trait]
pub trait TeamStore: Send + Sync {
    async fn create_team(&self, input: crate::CreateTeam) -> AuthResult<crate::Team>;
    async fn get_team(&self, id: &str) -> AuthResult<Option<crate::Team>>;
    /// Query an ID supplied by a replacement Organization field schema.
    async fn get_team_value(&self, id: &crate::FieldValue) -> AuthResult<Option<crate::Team>> {
        match id.as_str() {
            Some(id) => self.get_team(id).await,
            None => Err(crate::AuthError::config(
                "This store does not support dynamic team IDs",
            )),
        }
    }
    async fn update_team(&self, id: &str, update: crate::UpdateTeam) -> AuthResult<crate::Team>;
    async fn delete_team(&self, id: &str) -> AuthResult<()>;
    async fn list_organization_teams(&self, organization_id: &str) -> AuthResult<Vec<crate::Team>>;
    async fn list_organization_teams_value(
        &self,
        organization_id: &crate::FieldValue,
    ) -> AuthResult<Vec<crate::Team>> {
        let id = crate::SchemaValue::<String>::from_field(organization_id.clone());
        self.list_organization_teams(id.typed()?).await
    }
    /// Count all stored teams independently of the read-page limit.
    async fn count_organization_teams(&self, organization_id: &str) -> AuthResult<u64>;
    async fn count_organization_teams_value(
        &self,
        organization_id: &crate::FieldValue,
    ) -> AuthResult<u64> {
        let id = crate::SchemaValue::<String>::from_field(organization_id.clone());
        self.count_organization_teams(id.typed()?).await
    }
    async fn list_user_teams(&self, user_id: &str) -> AuthResult<Vec<crate::Team>>;
    async fn get_team_member(
        &self,
        team_id: &str,
        user_id: &str,
    ) -> AuthResult<Option<crate::TeamMember>>;
    async fn get_team_member_value(
        &self,
        team_id: &crate::FieldValue,
        user_id: &crate::FieldValue,
    ) -> AuthResult<Option<crate::TeamMember>> {
        let team_id = crate::SchemaValue::<String>::from_field(team_id.clone());
        let user_id = crate::SchemaValue::<String>::from_field(user_id.clone());
        self.get_team_member(team_id.typed()?, user_id.typed()?)
            .await
    }
    async fn list_team_members(&self, team_id: &str) -> AuthResult<Vec<crate::TeamMember>>;
    async fn list_team_members_value(
        &self,
        team_id: &crate::FieldValue,
    ) -> AuthResult<Vec<crate::TeamMember>> {
        let id = crate::SchemaValue::<String>::from_field(team_id.clone());
        self.list_team_members(id.typed()?).await
    }
    /// Count all stored team memberships independently of the read-page limit.
    async fn count_team_members(&self, team_id: &str) -> AuthResult<u64>;
    /// Atomically return an existing membership or reserve capacity and create one.
    /// Return None when the maximum member count is reached.
    async fn add_team_member(
        &self,
        team_id: &crate::SchemaValue<String>,
        user_id: &str,
        maximum: Option<usize>,
    ) -> AuthResult<Option<crate::TeamMember>>;
    async fn remove_team_member(&self, team_id: &str, user_id: &str) -> AuthResult<()>;
}

/// A scoped point lookup for an organization role.
#[derive(Clone, Copy, Debug)]
pub enum OrganizationRoleKey<'a> {
    /// Match the stored role ID.
    Id(&'a str),
    /// Match the stored role name.
    Name(&'a str),
}

/// Persistence for organization-scoped dynamic roles.
#[async_trait]
pub trait OrganizationRoleStore: Send + Sync {
    async fn create_organization_role(
        &self,
        input: crate::CreateOrganizationRole,
    ) -> AuthResult<crate::OrganizationRole>;
    async fn get_organization_role(&self, id: &str) -> AuthResult<Option<crate::OrganizationRole>>;
    /// Find one role in its organization without applying the list-page limit.
    async fn find_organization_role(
        &self,
        organization_id: &str,
        key: OrganizationRoleKey<'_>,
    ) -> AuthResult<Option<crate::OrganizationRole>>;
    async fn find_organization_role_value(
        &self,
        organization_id: &crate::FieldValue,
        key: OrganizationRoleKey<'_>,
    ) -> AuthResult<Option<crate::OrganizationRole>> {
        let id = crate::SchemaValue::<String>::from_field(organization_id.clone());
        self.find_organization_role(id.typed()?, key).await
    }
    /// Filter stored role names before applying the adapter's default page limit.
    async fn query_organization_roles(
        &self,
        organization_id: &str,
        names: &[String],
    ) -> AuthResult<Vec<crate::OrganizationRole>>;
    async fn query_organization_roles_value(
        &self,
        organization_id: &crate::FieldValue,
        names: &[String],
    ) -> AuthResult<Vec<crate::OrganizationRole>> {
        let id = crate::SchemaValue::<String>::from_field(organization_id.clone());
        self.query_organization_roles(id.typed()?, names).await
    }
    /// Count stored roles without projecting or paginating records.
    async fn count_organization_roles(&self, organization_id: &str) -> AuthResult<u64>;
    async fn count_organization_roles_value(
        &self,
        organization_id: &crate::FieldValue,
    ) -> AuthResult<u64> {
        let id = crate::SchemaValue::<String>::from_field(organization_id.clone());
        self.count_organization_roles(id.typed()?).await
    }
    async fn list_organization_roles(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<crate::OrganizationRole>>;
    /// Query organization roles with a runtime reference from a replacement schema.
    async fn list_organization_roles_value(
        &self,
        organization_id: &crate::FieldValue,
    ) -> AuthResult<Vec<crate::OrganizationRole>> {
        let organization_id = organization_id.as_str().ok_or_else(|| {
            crate::AuthError::config(
                "The store must support dynamic organization role reference queries for this schema",
            )
        })?;
        self.list_organization_roles(organization_id).await
    }
    async fn update_organization_role(
        &self,
        id: &str,
        update: crate::UpdateOrganizationRole,
    ) -> AuthResult<crate::OrganizationRole>;
    async fn delete_organization_role(&self, id: &str) -> AuthResult<()>;
}

/// A persistent database rate-limit record. Timestamps use Unix milliseconds.
#[derive(Clone, Debug, PartialEq)]
pub struct RateLimitRecord {
    pub id: crate::SchemaValue<String>,
    pub key: String,
    pub count: f64,
    pub last_request: i64,
}

impl crate::AuthRecordFields for RateLimitRecord {
    fn field_values(&self) -> AuthResult<crate::FieldMap> {
        Ok([
            ("id".into(), self.id.field_value()),
            ("key".into(), self.key.clone().into()),
            ("count".into(), self.count.into()),
            ("lastRequest".into(), self.last_request.into()),
        ]
        .into())
    }
}

impl crate::FromFieldMap for RateLimitRecord {
    fn from_field_values(mut fields: crate::FieldMap) -> AuthResult<Self> {
        Ok(Self {
            id: crate::SchemaValue::from_field(fields.remove("id").unwrap_or_default()),
            key: fields.remove("key").unwrap_or_default().decode()?,
            count: fields.remove("count").unwrap_or_default().decode()?,
            last_request: fields.remove("lastRequest").unwrap_or_default().decode()?,
        })
    }
}

/// Atomically consume an allowance using the database adapter's comparison semantics.
#[async_trait]
pub trait RateLimitStore: Send + Sync {
    async fn consume_rate_limit(
        &self,
        key: &str,
        rule: crate::middleware::EndpointRateLimit,
        cleanup_window: f64,
    ) -> AuthResult<crate::middleware::RateLimitDecision>;
}

pub trait AuthStore<S: AuthSchema>:
    UserStore<S>
    + SessionStore<S>
    + AccountStore<S>
    + VerificationStore<S>
    + OrganizationStore
    + TeamStore
    + OrganizationRoleStore
    + MemberStore
    + InvitationStore
    + TwoFactorStore
    + ApiKeyStore
    + PasskeyStore
    + DeviceCodeStore
    + WalletStore
    + JwksStore
    + RateLimitStore
    + TransactionStore<S>
    + RuntimeStore<S>
    + Send
    + Sync
{
}

impl<S, T> AuthStore<S> for T
where
    S: AuthSchema,
    T: UserStore<S>
        + SessionStore<S>
        + AccountStore<S>
        + VerificationStore<S>
        + OrganizationStore
        + TeamStore
        + OrganizationRoleStore
        + MemberStore
        + InvitationStore
        + TwoFactorStore
        + ApiKeyStore
        + PasskeyStore
        + DeviceCodeStore
        + WalletStore
        + JwksStore
        + RateLimitStore
        + TransactionStore<S>
        + RuntimeStore<S>
        + Send
        + Sync,
{
}

/// Persistent signing keys shared by every JWT plugin instance.
#[async_trait]
pub trait JwksStore: Send + Sync {
    /// Create complete key fields through shared adapter policies.
    async fn create_jwk_record(
        &self,
        input: crate::FieldMap,
    ) -> AuthResult<Option<crate::FieldMap>>;
    /// Read complete key fields before constructing a runtime record.
    async fn get_jwk_record(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<crate::FieldMap>>;
    /// Apply a complete logical patch to a key record.
    async fn update_jwk_record(
        &self,
        id: &crate::SchemaValue<String>,
        input: crate::FieldMap,
    ) -> AuthResult<Option<crate::FieldMap>>;
    /// Delete records selected by the adapter's ID query policy.
    async fn delete_jwk_record(&self, id: &crate::SchemaValue<String>) -> AuthResult<()>;
    /// List complete key fields with the adapter's default limit and order.
    async fn list_jwk_records(&self) -> AuthResult<Vec<crate::FieldMap>>;
    /// Read one signing key by its ID without applying a find-many limit.
    async fn get_jwk(&self, id: &str) -> AuthResult<Option<crate::Jwk>> {
        self.get_jwk_record(&id.into())
            .await?
            .map(crate::FromFieldMap::from_field_values)
            .transpose()
    }
    /// List public and private key records, including expired keys retained for verification.
    async fn list_jwks(&self) -> AuthResult<Vec<crate::Jwk>> {
        self.list_jwk_records()
            .await?
            .into_iter()
            .map(crate::FromFieldMap::from_field_values)
            .collect()
    }
    /// Persist a generated signing key.
    async fn create_jwk(&self, input: crate::CreateJwk) -> AuthResult<crate::Jwk> {
        crate::FromFieldMap::from_field_values(
            self.create_jwk_record(input.into_adapter_fields()?)
                .await?
                .ok_or_else(|| AuthError::internal("JWK creation returned no record"))?,
        )
    }
}

pub async fn transaction<S, T, F>(store: &dyn AuthStore<S>, work: F) -> AuthResult<T>
where
    S: AuthSchema,
    T: Send + 'static,
    F: for<'tx> FnOnce(&'tx dyn AuthTransaction<S>) -> TypedTransactionFuture<'tx, T>
        + Send
        + 'static,
{
    let value = store
        .transaction_boxed(Box::new(move |tx| {
            Box::pin(async move { Ok(Box::new(work(tx).await?) as BoxedTransactionValue) })
        }))
        .await?;

    value
        .downcast::<T>()
        .map(|boxed| *boxed)
        .map_err(|_| AuthError::internal("store returned an invalid transaction payload"))
}
