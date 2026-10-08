use super::{
    lifecycle::{Case, observe},
    lifecycle_models::Schema,
    trace::Trace,
    values,
};
use better_auth_core::{
    AuthError, AuthResult, CreateUser, CreateVerification, FieldMap, FieldValue,
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
        input: &mut CreateUser,
        _: &DatabaseHookContext<'_, Schema>,
    ) -> AuthResult<DatabaseHookControl> {
        // CreateUser exposes typed values but does not retain JavaScript property insertion order.
        let fields = user_values(input)?;
        self.trace.callback(json!({"phase": "before:plugin", "data": {"fields": values::observe(&FieldValue::from(fields))?}}));
        if self.case.cancel {
            return Ok(DatabaseHookControl::Cancel);
        }
        input.id = Some(self.patch["id"].decode()?);
        input.name = better_auth_core::SchemaValue::from_field(self.patch["name"].clone());
        Ok(DatabaseHookControl::Continue)
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

pub(super) fn user_values(input: &CreateUser) -> AuthResult<FieldMap> {
    let CreateUser {
        created_at,
        updated_at,
        additional_fields,
        id,
        email,
        name,
        image,
        email_verified,
        username,
        display_username,
        is_anonymous,
        phone_number,
        phone_number_verified,
        role,
        banned,
        ban_reason,
        ban_expires,
        metadata,
    } = input;
    assert!(additional_fields.is_empty());
    assert_eq!(username, &None);
    assert_eq!(display_username, &None);
    assert_eq!(is_anonymous, &None);
    assert_eq!(phone_number, &None);
    assert_eq!(phone_number_verified, &None);
    assert_eq!(role, &None);
    assert_eq!(banned, &None);
    assert_eq!(ban_reason, &None);
    assert_eq!(ban_expires, &None);
    assert_eq!(metadata, &None);
    Ok(FieldMap::from([
        (
            "createdAt".into(),
            created_at.clone().expect("seeded createdAt").into(),
        ),
        (
            "updatedAt".into(),
            updated_at.clone().expect("seeded updatedAt").into(),
        ),
        ("id".into(), id.clone().expect("seeded ID").into()),
        ("email".into(), email.clone().expect("seeded email").into()),
        ("name".into(), name.field_value()),
        ("image".into(), image.field_value()),
        (
            "emailVerified".into(),
            email_verified.expect("seeded emailVerified").into(),
        ),
    ]))
}
