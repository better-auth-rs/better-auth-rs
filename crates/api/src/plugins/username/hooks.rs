use better_auth_core::plugin_runtime::PluginRuntime;
use better_auth_core::store::database_hooks::{
    DatabaseHookContext, DatabaseHookControl, DatabaseHookUpdate, DatabaseHooks,
};
use better_auth_core::{AuthResult, AuthSchema, CreateUser, UpdateUser};

use super::config::{UsernameConfig, error};

pub(super) struct UsernameHooks<S: AuthSchema> {
    pub(super) config: UsernameConfig,
    pub(super) runtime: PluginRuntime<S>,
}

impl<S: AuthSchema> UsernameHooks<S> {
    async fn validate(
        &self,
        username: &str,
        display: Option<&str>,
        current_user_id: Option<&str>,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        if let Some((code, message)) = self.config.validate_input(username).await? {
            return Err(error(400, code, message));
        }
        let normalized = self.config.normalize(username)?;
        let existing = if let Some(transaction) = context.transaction {
            transaction.get_user_by_username(&normalized).await?
        } else {
            self.runtime
                .context()?
                .database
                .get_user_by_username(&normalized)
                .await?
        };
        if let Some(user) = existing
            && current_user_id != user.id.as_str()
        {
            return Err(error(
                400,
                "USERNAME_IS_ALREADY_TAKEN",
                "Username is already taken. Please try another.",
            ));
        }
        if let Some(display) = display.filter(|value| !value.is_empty()) {
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
        user: &mut CreateUser,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        let username = user
            .username
            .as_ref()
            .and_then(Option::as_deref)
            .filter(|value| !value.is_empty());
        let display = user
            .display_username
            .as_ref()
            .and_then(Option::as_deref)
            .filter(|value| !value.is_empty());
        if let Some(username) = username {
            if !endpoint_validated(context) {
                self.validate(username, display, None, context).await?;
            }
            let normalized = self.config.normalize(username)?;
            let display = if self.config.display_username {
                Some(Some(match display {
                    Some(display) => self.config.normalize_display(display)?,
                    None => username.to_owned(),
                }))
            } else {
                None
            };
            user.username = Some(Some(normalized));
            if display.is_some() {
                user.display_username = display;
            }
        } else if self.config.display_username
            && let Some(display) = display
        {
            user.display_username = Some(Some(self.config.normalize_display(display)?));
        }
        Ok(DatabaseHookControl::Continue)
    }

    async fn before_update_user(
        &self,
        user: &UpdateUser,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<UpdateUser>> {
        let mut patch = UpdateUser::default();
        let username = user
            .username
            .as_ref()
            .and_then(Option::as_deref)
            .filter(|value| !value.is_empty());
        let display = user
            .display_username
            .as_ref()
            .and_then(Option::as_deref)
            .filter(|value| !value.is_empty());
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
                    .and_then(serde_json::Value::as_str)
                    .or_else(|| {
                        user.additional_fields
                            .get("id")
                            .and_then(serde_json::Value::as_str)
                    });
                self.validate(username, display, current_id, context)
                    .await?;
            }
            patch.username = Some(Some(self.config.normalize(username)?));
        }
        if self.config.display_username
            && let Some(display) = display
        {
            patch.display_username = Some(Some(self.config.normalize_display(display)?));
        }
        Ok(DatabaseHookUpdate::Patch(patch))
    }
}
