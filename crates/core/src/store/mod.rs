mod api_key_usage;
pub use api_key_usage::ApiKeyUsageWrite;

use async_trait::async_trait;
use std::any::Any;
use std::future::Future;
use std::pin::Pin;

pub mod cache;
mod capabilities;
mod runtime;
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
    UpdateOrganization, UpdatePasskeyAuthentication, UpdateUser,
};

pub use cache::{CacheAdapter, MemoryCacheAdapter, SecondaryStorage};

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
    Box<dyn FnOnce(crate::wire::VerificationView) -> TypedTransactionFuture<'static, ()> + Send>;

#[async_trait]
pub trait AuthTransaction<S: AuthSchema>: JwksStore + Send + Sync {
    /// Queue an effect in write order. Run it after commit, discard it on rollback,
    /// and stop later effects if it fails. Preserve the current request hook context.
    fn queue_after_commit(&self, effect: TypedTransactionFuture<'static, ()>) -> AuthResult<()>;

    /// Run verification creation hooks for secondary-only values in this transaction.
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
    /// Run a verification create lifecycle, then its secondary write, then queue database after hooks.
    async fn create_verification_with_writer(
        &self,
        verification: CreateVerification,
        writer: Option<VerificationCreateWriter>,
    ) -> AuthResult<crate::wire::VerificationView> {
        if writer.is_some() {
            return Err(AuthError::config(
                "The store must support ordered verification creation",
            ));
        }
        self.create_verification(verification).await
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
    /// Delete expired verification records inside the active transaction.
    async fn delete_expired_verifications(&self) -> AuthResult<usize>;
    /// Run session creation hooks before creating a session outside the database.
    async fn before_create_runtime_session(&self, _session: &mut CreateSession) -> AuthResult<()> {
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

    async fn create_passkey(&self, passkey: CreatePasskey) -> AuthResult<Passkey>;
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
}

/// Persistent records invalidated when an unverified user proves email ownership.
#[derive(Debug, Clone, Copy)]
pub enum VerificationCleanup {
    /// Remove accounts; the runtime owns session revocation.
    Accounts,
    /// Remove accounts and database sessions.
    AccountsAndSessions,
}

/// Revoke external sessions while the user verification transaction remains uncommitted.
#[async_trait]
pub trait VerificationSessionCleanup: Send + Sync {
    /// Revoke the captured sessions. An error must abort the verification transaction.
    async fn revoke(&self) -> AuthResult<()>;
}

#[async_trait]
pub trait UserStore<S: AuthSchema>: Send + Sync {
    /// Return whether the database adapter preserves native JSON at field-policy boundaries.
    fn supports_native_json(&self) -> bool {
        true
    }
    /// Verify ownership after revoking accounts and the selected session storage.
    /// Run external cleanup only for the unverified user while holding the verification lock.
    /// Complete cleanup before commit; roll back database changes if cleanup fails.
    async fn verify_user_with_cleanup(
        &self,
        _user_id: &str,
        _cleanup: VerificationCleanup,
        _sessions: Option<&dyn VerificationSessionCleanup>,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        Err(AuthError::config(
            "The store must support pre-commit session cleanup during user verification",
        ))
    }
    /// Atomically verify an unverified user after deleting every existing account and session.
    /// Already verified users retain their accounts and sessions.
    async fn verify_user_and_revoke_unproven_access(
        &self,
        user_id: &str,
    ) -> AuthResult<Option<crate::wire::UserView>>;
    async fn create_user(&self, create_user: CreateUser) -> AuthResult<crate::wire::UserView>;
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
        id: &serde_json::Value,
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
    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<crate::UserView>>;
    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<crate::UserView>>;
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

    /// Run session creation hooks when secondary storage owns the session.
    async fn before_create_runtime_session(&self, _session: &mut CreateSession) -> AuthResult<()> {
        Ok(())
    }
    /// Run creation hooks after secondary storage contains the committed session.
    async fn after_create_runtime_session(
        &self,
        _session: &crate::wire::SessionView,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// End a live session while retaining its database row for audit.
    async fn end_session(&self, token: &str) -> AuthResult<()> {
        let now = chrono::Utc::now();
        if let Some(session) = self.get_session(token).await?
            && crate::entity::AuthSession::expires_at(&session) > now
        {
            let _ = self.update_session_expiry(token, now).await?;
        }
        Ok(())
    }
    /// Read a session and an optional cached user projection in one storage operation.
    async fn get_session_snapshot(
        &self,
        token: &str,
    ) -> AuthResult<
        Option<(
            crate::wire::SessionView,
            Option<crate::session::SessionData>,
        )>,
    > {
        Ok(self
            .get_session(token)
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
    /// Persist application session fields and update the modification timestamp.
    async fn update_session_fields(
        &self,
        token: &str,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> AuthResult<Option<crate::wire::SessionView>>;
    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<crate::wire::SessionView>>;
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
    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<crate::wire::AccountView>>;
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
    async fn delete_account(&self, id: &str) -> AuthResult<()>;
}

#[async_trait]
pub trait VerificationStore<S: AuthSchema>: Send + Sync {
    /// Run a verification create lifecycle, then its secondary write, then queue database after hooks.
    async fn create_verification_with_writer(
        &self,
        verification: CreateVerification,
        writer: Option<VerificationCreateWriter>,
    ) -> AuthResult<crate::wire::VerificationView> {
        if writer.is_some() {
            return Err(AuthError::config(
                "The store must support ordered verification creation",
            ));
        }
        self.create_verification(verification).await
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
    async fn before_create_runtime_verification(
        &self,
        _verification: &mut CreateVerification,
    ) -> AuthResult<()> {
        Ok(())
    }
    /// Run creation hooks after secondary storage contains the verification.
    async fn after_create_runtime_verification(
        &self,
        _verification: &crate::wire::VerificationView,
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
    pub organization_id: String,
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
    pub filter_value: Option<serde_json::Value>,
    /// Filter operator (`eq`, `ne`, `contains`, `gt`, `gte`, `lt`, `lte`).
    pub filter_operator: Option<String>,
}

#[async_trait]
pub trait OrganizationStore: Send + Sync {
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
    async fn create_organization(&self, org: CreateOrganization) -> AuthResult<Organization>;
    async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<Organization>>;
    /// Query an ID supplied through a replacement organization schema.
    async fn get_organization_by_id_value(
        &self,
        id: &serde_json::Value,
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
        slug: &serde_json::Value,
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
    async fn delete_organization(&self, id: &str) -> AuthResult<()>;
    async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<Organization>>;
}

#[async_trait]
pub trait MemberStore: Send + Sync {
    async fn create_member(&self, member: CreateMember) -> AuthResult<Member>;
    async fn get_member(&self, organization_id: &str, user_id: &str) -> AuthResult<Option<Member>>;
    /// Query member references supplied through a replacement organization schema.
    async fn get_member_value(
        &self,
        organization_id: &serde_json::Value,
        user_id: &serde_json::Value,
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

    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<Member>>;
    async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<Member>;
    async fn delete_member(&self, member_id: &str) -> AuthResult<()>;
    async fn list_organization_members(&self, org_id: &str) -> AuthResult<Vec<Member>>;
    /// Query organization members with filter, sort, and pagination applied in
    /// the store when possible.
    async fn query_organization_members(
        &self,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<(Vec<Member>, usize)>;
    async fn count_organization_members(&self, org_id: &str) -> AuthResult<i64>;
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
    /// Count still-pending, unexpired invitations for an organization.
    async fn count_pending_organization_invitations(&self, org_id: &str) -> AuthResult<i64>;
    async fn list_user_invitations(&self, email: &str) -> AuthResult<Vec<Invitation>>;
}

#[async_trait]
pub trait TwoFactorStore: Send + Sync {
    async fn create_two_factor(&self, two_factor: CreateTwoFactor) -> AuthResult<TwoFactor>;
    async fn get_two_factor_by_user_id(&self, user_id: &str) -> AuthResult<Option<TwoFactor>>;
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
        previous: &str,
        replacement: &str,
    ) -> AuthResult<bool>;
    /// Atomically count a failed verification and lock the account once the budget is spent.
    async fn record_two_factor_failure(
        &self,
        id: &crate::SchemaValue<String>,
        max_attempts: i64,
        locked_until: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<()>;
    /// Reset failed verifications, optionally requiring an expired lock.
    async fn reset_two_factor_failures(
        &self,
        id: &crate::SchemaValue<String>,
        locked_before: Option<chrono::DateTime<chrono::Utc>>,
    ) -> AuthResult<()>;
    async fn delete_two_factor(&self, user_id: &str) -> AuthResult<()>;
}

#[async_trait]
pub trait ApiKeyStore: Send + Sync {
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
    ) -> AuthResult<Vec<ApiKey>>;
    /// Count all matching API keys without applying the adapter's default limit.
    async fn count_api_keys_by_reference(&self, reference_id: &str) -> AuthResult<u64>;
    async fn update_api_key(
        &self,
        id: &crate::SchemaValue<String>,
        update: UpdateApiKey,
    ) -> AuthResult<ApiKey>;
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
    async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<Passkey>;
    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<Passkey>>;
    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AuthResult<Option<Passkey>>;
    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<Passkey>>;
    async fn update_passkey_authentication(
        &self,
        id: &crate::SchemaValue<String>,
        update: UpdatePasskeyAuthentication,
    ) -> AuthResult<Passkey>;
    async fn update_passkey_name(&self, id: &str, name: &str) -> AuthResult<Passkey>;
    async fn delete_passkey(&self, id: &str) -> AuthResult<()>;
}

/// Persistence for OAuth device authorization codes.
#[async_trait]
pub trait DeviceCodeStore: Send + Sync {
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
        user_id: &str,
    ) -> AuthResult<bool>;
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
    async fn get_wallet_address(
        &self,
        address: &str,
        chain_id: Option<i64>,
    ) -> AuthResult<Option<crate::types::WalletAddress>>;
    async fn create_wallet_address(
        &self,
        wallet: crate::types::CreateWalletAddress,
    ) -> AuthResult<crate::types::WalletAddress>;
}

/// Persistence for organization teams and team membership.
#[async_trait]
pub trait TeamStore: Send + Sync {
    async fn create_team(&self, input: crate::CreateTeam) -> AuthResult<crate::Team>;
    async fn get_team(&self, id: &str) -> AuthResult<Option<crate::Team>>;
    /// Query an ID supplied by a replacement Organization field schema.
    async fn get_team_value(&self, id: &serde_json::Value) -> AuthResult<Option<crate::Team>> {
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
    async fn list_user_teams(&self, user_id: &str) -> AuthResult<Vec<crate::Team>>;
    async fn get_team_member(
        &self,
        team_id: &str,
        user_id: &str,
    ) -> AuthResult<Option<crate::TeamMember>>;
    async fn list_team_members(&self, team_id: &str) -> AuthResult<Vec<crate::TeamMember>>;
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

/// Persistence for organization-scoped dynamic roles.
#[async_trait]
pub trait OrganizationRoleStore: Send + Sync {
    async fn create_organization_role(
        &self,
        input: crate::CreateOrganizationRole,
    ) -> AuthResult<crate::OrganizationRole>;
    async fn get_organization_role(&self, id: &str) -> AuthResult<Option<crate::OrganizationRole>>;
    async fn list_organization_roles(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<crate::OrganizationRole>>;
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
    /// Read one signing key by its ID without applying a find-many limit.
    async fn get_jwk(&self, id: &str) -> AuthResult<Option<crate::Jwk>>;
    /// List public and private key records, including expired keys retained for verification.
    async fn list_jwks(&self) -> AuthResult<Vec<crate::Jwk>>;
    /// Persist a generated signing key.
    async fn create_jwk(&self, input: crate::CreateJwk) -> AuthResult<crate::Jwk>;
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
