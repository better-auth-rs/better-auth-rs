use super::{
    lifecycle::{Case, observe},
    lifecycle_models::Schema,
    trace::Trace,
};
use better_auth_core::{
    AuthError, AuthResult, CreateVerification, FieldMap,
    store::database_hooks::{
        DatabaseHookContext, DatabaseHookControl, DatabaseHookUpdate, DatabaseHooks,
    },
    wire::{SessionView, UserView, VerificationView},
};
use serde_json::json;

pub(super) struct Plugin {
    pub(super) trace: Trace,
    pub(super) case: Case,
    pub(super) patch: FieldMap,
}

impl Plugin {
    fn before(&self, fields: FieldMap) -> AuthResult<()> {
        self.trace
            .callback(json!({"phase": "before:plugin", "data": observe(Some(fields))?}));
        Ok(())
    }

    fn after(&self, fields: Option<FieldMap>) -> AuthResult<()> {
        self.trace
            .callback(json!({"phase": "after:plugin", "data": observe(fields)?}));
        if self.case.after_error {
            Err(AuthError::internal("creation-after-null-error"))
        } else {
            Ok(())
        }
    }
}

#[better_auth::database_hooks()]
impl DatabaseHooks<Schema> for Plugin {
    async fn before_create_user(
        &self,
        input: &mut FieldMap,
        _: &DatabaseHookContext<'_, Schema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.before(input.clone())?;
        Ok(if self.case.cancel {
            DatabaseHookUpdate::Cancel
        } else {
            DatabaseHookUpdate::Patch(self.patch.clone())
        })
    }

    async fn after_create_user(
        &self,
        input: Option<&UserView>,
        _: &DatabaseHookContext<'_, Schema>,
    ) -> AuthResult<()> {
        assert!(
            input.is_none(),
            "the trigger makes User primary-ID readback return null"
        );
        self.after(None)
    }

    async fn before_create_session(
        &self,
        input: &mut FieldMap,
        _: &DatabaseHookContext<'_, Schema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.before(input.clone())?;
        Ok(if self.case.cancel {
            DatabaseHookUpdate::Cancel
        } else {
            DatabaseHookUpdate::Patch(self.patch.clone())
        })
    }

    async fn after_create_session(
        &self,
        input: Option<&SessionView>,
        _: &DatabaseHookContext<'_, Schema>,
    ) -> AuthResult<()> {
        self.after(input.cloned().map(FieldMap::from))
    }

    async fn before_create_verification(
        &self,
        input: &mut CreateVerification,
        _: &DatabaseHookContext<'_, Schema>,
    ) -> AuthResult<DatabaseHookControl> {
        self.before(input.fields()?)?;
        if self.case.cancel {
            return Ok(DatabaseHookControl::Cancel);
        }
        input.id = better_auth_core::SchemaValue::from_field(self.patch["id"].clone());
        input.identifier =
            better_auth_core::SchemaValue::from_field(self.patch["identifier"].clone());
        input.value = better_auth_core::SchemaValue::from_field(self.patch["value"].clone());
        input.expires_at =
            better_auth_core::SchemaValue::from_field(self.patch["expiresAt"].clone());
        Ok(DatabaseHookControl::Continue)
    }

    async fn after_create_verification(
        &self,
        input: Option<&VerificationView>,
        _: &DatabaseHookContext<'_, Schema>,
    ) -> AuthResult<()> {
        self.after(input.map(VerificationView::fields).transpose()?)
    }
}

pub(super) struct Application(pub(super) Trace);

impl Application {
    fn after(&self, fields: Option<FieldMap>) -> AuthResult<()> {
        self.0
            .callback(json!({"phase": "after:application", "data": observe(fields)?}));
        Ok(())
    }
}

#[better_auth::database_hooks()]
impl DatabaseHooks<Schema> for Application {
    async fn after_create_user(
        &self,
        input: Option<&UserView>,
        _: &DatabaseHookContext<'_, Schema>,
    ) -> AuthResult<()> {
        assert!(
            input.is_none(),
            "User after hook must retain the nullable adapter result"
        );
        self.after(None)
    }
    async fn after_create_session(
        &self,
        input: Option<&SessionView>,
        _: &DatabaseHookContext<'_, Schema>,
    ) -> AuthResult<()> {
        self.after(input.cloned().map(FieldMap::from))
    }
    async fn after_create_verification(
        &self,
        input: Option<&VerificationView>,
        _: &DatabaseHookContext<'_, Schema>,
    ) -> AuthResult<()> {
        self.after(input.map(VerificationView::fields).transpose()?)
    }
}
