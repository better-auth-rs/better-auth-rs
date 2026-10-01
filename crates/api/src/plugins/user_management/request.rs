use super::types::{ChangeEmailRequest, DeleteUserRequest};
use better_auth_core::{AuthRequest, AuthResult, endpoint_input::ValidatedBody};
use serde_json::Value;

fn change_input(req: &AuthRequest) -> AuthResult<(ChangeEmailRequest, Value)> {
    crate::plugins::json_body::email_input(req, "newEmail", "callbackURL")
}
fn delete_input(req: &AuthRequest) -> AuthResult<(DeleteUserRequest, Value)> {
    crate::plugins::json_body::string_input(
        req,
        &[
            ("callbackURL", false),
            ("password", false),
            ("token", false),
        ],
    )
}
pub(super) fn change_email_body(req: &AuthRequest) -> AuthResult<ValidatedBody> {
    let (typed, projection) = change_input(req)?;
    Ok(ValidatedBody::new(Some(projection), typed))
}
pub(super) fn delete_user_body(req: &AuthRequest) -> AuthResult<ValidatedBody> {
    let (typed, projection) = delete_input(req)?;
    Ok(ValidatedBody::new(Some(projection), typed))
}
pub(super) fn change_email(req: &AuthRequest) -> AuthResult<ChangeEmailRequest> {
    match req.validated_body::<ChangeEmailRequest>() {
        Some(body) => Ok(body.clone()),
        None => change_input(req).map(|(body, _)| body),
    }
}
pub(super) fn delete_user(req: &AuthRequest) -> AuthResult<DeleteUserRequest> {
    match req.validated_body::<DeleteUserRequest>() {
        Some(body) => Ok(body.clone()),
        None => delete_input(req).map(|(body, _)| body),
    }
}
