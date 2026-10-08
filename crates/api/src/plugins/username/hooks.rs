use better_auth_core::plugin_runtime::PluginRuntime;
use better_auth_core::store::database_hooks::{
    DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks,
};
use better_auth_core::{AuthResult, AuthSchema, FieldMap, FieldValue};

use super::config::{UsernameConfig, error};

pub(super) struct UsernameHooks<S: AuthSchema> {
    pub(super) config: UsernameConfig,
    pub(super) runtime: PluginRuntime<S>,
}

impl<S: AuthSchema> UsernameHooks<S> {
    async fn validate(
        &self,
        username: &FieldValue,
        display: Option<&FieldValue>,
        current_user_id: Option<&FieldValue>,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        if let Some((code, message)) = self.config.validate_input(username).await? {
            return Err(error(400, code, message));
        }
        let normalized = self.config.normalize(username)?;
        let existing = if let Some(transaction) = context.transaction {
            transaction
                .get_user_by_field_value("username", &normalized)
                .await?
        } else {
            self.runtime
                .context()?
                .database
                .get_user_by_field_value("username", &normalized)
                .await?
        };
        if let Some(user) = existing
            && current_user_id
                .is_none_or(|id| !id.is_truthy() || !id.strict_equals(&user.id.field_value()))
        {
            return Err(error(
                400,
                "USERNAME_IS_ALREADY_TAKEN",
                "Username is already taken. Please try another.",
            ));
        }
        if let Some(display) = display.filter(|value| value.is_truthy()) {
            self.config.validate_display(display).await?;
        }
        Ok(())
    }
}

fn endpoint_validated<S: AuthSchema>(context: &DatabaseHookContext<'_, S>) -> bool {
    context.request.as_ref().is_some_and(|request| {
        matches!(
            request.path.as_deref(),
            Some("/sign-up/email" | "/update-user")
        )
    })
}

#[better_auth_core::database_hooks("plugin:username")]
impl<S: AuthSchema> DatabaseHooks<S> for UsernameHooks<S> {
    async fn before_create_user(
        &self,
        user: &mut FieldMap,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        let username = user.get("username").filter(|value| value.is_truthy());
        let display = user
            .get("displayUsername")
            .filter(|value| value.is_truthy());
        let mut patch = user.clone();
        if let Some(username) = username {
            if !endpoint_validated(context) {
                self.validate(username, display, None, context).await?;
            }
            let _ = patch.insert("username".into(), self.config.normalize(username)?);
            if self.config.display_username {
                let display = match display {
                    Some(display) => self.config.normalize_display(display)?,
                    None => username.clone(),
                };
                let _ = patch.insert("displayUsername".into(), display);
            }
        } else if self.config.display_username
            && let Some(display) = display
        {
            let _ = patch.insert(
                "displayUsername".into(),
                self.config.normalize_display(display)?,
            );
        }
        Ok(DatabaseHookUpdate::Patch(patch))
    }

    async fn before_update_user(
        &self,
        user: &mut FieldMap,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        let username = user.get("username").filter(|value| value.is_truthy());
        let display = user
            .get("displayUsername")
            .filter(|value| value.is_truthy());
        let mut patch = user.clone();
        if let Some(username) = username {
            if !endpoint_validated(context) {
                let session_id = context
                    .request
                    .as_ref()
                    .map(|request| request.request.server_context("auth.current-user-id"))
                    .transpose()?
                    .flatten();
                let current_id = session_id
                    .as_ref()
                    .filter(|value| value.is_truthy())
                    .or_else(|| user.get("id"));
                self.validate(username, display, current_id, context)
                    .await?;
            }
            let _ = patch.insert("username".into(), self.config.normalize(username)?);
        }
        if self.config.display_username
            && let Some(display) = display
        {
            let _ = patch.insert(
                "displayUsername".into(),
                self.config.normalize_display(display)?,
            );
        }
        Ok(DatabaseHookUpdate::Patch(patch))
    }
}
