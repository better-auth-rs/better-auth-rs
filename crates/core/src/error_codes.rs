//! Upstream error-code vocabulary.
//!
//! better-auth 1.5 replaced message-derived codes with explicit constants
//! (`defineErrorCodes` in `@better-auth/core` and each plugin), so the wire
//! `code` is no longer a function of the message. This mirrors every table
//! upstream defines, keyed by message.
//!
//! Regenerate against a new better-auth release by collecting the
//! `defineErrorCodes({ ... })` entries from `better-auth` and `@better-auth/*`.
//! Messages are unique across upstream tables, so one map is unambiguous.
//!
//! Includes the codes upstream attaches inline via `APIError.from(status,
//! { message, code })`, which live outside any `defineErrorCodes` table.

/// The explicit code upstream attaches to `message`, if any.
///
/// Messages outside every table carry no `code` on the wire at all, which is
/// why this returns an `Option` rather than falling back to a derivation.
pub(crate) fn upstream_code(message: &str) -> Option<&'static str> {
    let code = match message {
        "Access denied" => "ACCESS_DENIED",
        "Account not found" => "ACCOUNT_NOT_FOUND",
        "Too many failed verification attempts. Your account is temporarily locked. Please try again later." => {
            "ACCOUNT_TEMPORARILY_LOCKED"
        }
        "Anonymous users cannot sign in again anonymously" => {
            "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY"
        }
        "Async validation is not supported" => "ASYNC_VALIDATION_NOT_SUPPORTED",
        "Auth cancelled" => "AUTH_CANCELLED",
        "Authentication failed" => "AUTHENTICATION_FAILED",
        "Authentication required" => "AUTHENTICATION_REQUIRED",
        "Authorization pending" => "AUTHORIZATION_PENDING",
        "Backup codes aren't enabled" => "BACKUP_CODES_NOT_ENABLED",
        "You have been banned from this application" => "BANNED_USER",
        "Body must be an object" => "BODY_MUST_BE_AN_OBJECT",
        "callbackURL is required" => "CALLBACK_URL_REQUIRED",
        "Cannot delete a pre-defined role" => "CANNOT_DELETE_A_PRE_DEFINED_ROLE",
        "Challenge not found" => "CHALLENGE_NOT_FOUND",
        "Change email is disabled" => "CHANGE_EMAIL_DISABLED",
        "Could not create session" => "COULD_NOT_CREATE_SESSION",
        "Credential account not found" => "CREDENTIAL_ACCOUNT_NOT_FOUND",
        "Cross-site navigation login blocked. This request appears to be a CSRF attack." => {
            "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED"
        }
        "Deleting anonymous users is disabled" => "DELETE_ANONYMOUS_USER_DISABLED",
        "Device code already processed" => "DEVICE_CODE_ALREADY_PROCESSED",
        "Device code has not been claimed by a verifying session; call `GET /device` with the `user_code` while signed in before approving or denying" => {
            "DEVICE_CODE_NOT_CLAIMED"
        }
        "Email is already verified" => "EMAIL_ALREADY_VERIFIED",
        "Email can not be updated" => "EMAIL_CAN_NOT_BE_UPDATED",
        "Email mismatch" => "EMAIL_MISMATCH",
        "Email not verified" => "EMAIL_NOT_VERIFIED",
        "Email verification required before accepting or rejecting invitation" => {
            "EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION"
        }
        "Email verification required to view or list invitations for the session email" => {
            "EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION"
        }
        "Device code has expired" => "EXPIRED_DEVICE_CODE",
        "User code has expired" => "EXPIRED_USER_CODE",
        "The expiresIn is larger than the predefined maximum value." => "EXPIRES_IN_IS_TOO_LARGE",
        "The expiresIn is smaller than the predefined minimum value." => "EXPIRES_IN_IS_TOO_SMALL",
        "Failed to create session" => "FAILED_TO_CREATE_SESSION",
        "Failed to create user" => "FAILED_TO_CREATE_USER",
        "Unable to create verification" => "FAILED_TO_CREATE_VERIFICATION",
        "Failed to delete anonymous user" => "FAILED_TO_DELETE_ANONYMOUS_USER",
        "Failed to delete anonymous user sessions" => "FAILED_TO_DELETE_ANONYMOUS_USER_SESSIONS",
        "Failed to get session" => "FAILED_TO_GET_SESSION",
        "Failed to get user info" => "FAILED_TO_GET_USER_INFO",
        "Failed to retrieve invitation" => "FAILED_TO_RETRIEVE_INVITATION",
        "You can't unlink your last account" => "FAILED_TO_UNLINK_LAST_ACCOUNT",
        "Failed to update API key" => "FAILED_TO_UPDATE_API_KEY",
        "Failed to update passkey" => "FAILED_TO_UPDATE_PASSKEY",
        "Failed to update user" => "FAILED_TO_UPDATE_USER",
        "Failed to verify registration" => "FAILED_TO_VERIFY_REGISTRATION",
        "Field not allowed to be set" => "FIELD_NOT_ALLOWED",
        "id_token not supported" => "ID_TOKEN_NOT_SUPPORTED",
        "You do not have permission to perform this action on organization API keys." => {
            "INSUFFICIENT_API_KEY_PERMISSIONS"
        }
        "Invalid API key." => "INVALID_API_KEY",
        "API Key getter returned an invalid key type. Expected string." => {
            "INVALID_API_KEY_GETTER_RETURN_TYPE"
        }
        "Invalid backup code" => "INVALID_BACKUP_CODE",
        "Invalid callbackURL" => "INVALID_CALLBACK_URL",
        "Invalid code" => "INVALID_CODE",
        "Invalid device code" => "INVALID_DEVICE_CODE",
        "Invalid device code status" => "INVALID_DEVICE_CODE_STATUS",
        "Display username is invalid" => "INVALID_DISPLAY_USERNAME",
        "Invalid email" => "INVALID_EMAIL",
        "Email was not generated in a valid format" => "INVALID_EMAIL_FORMAT",
        "Invalid email or password" => "INVALID_EMAIL_OR_PASSWORD",
        "Invalid errorCallbackURL" => "INVALID_ERROR_CALLBACK_URL",
        "metadata must be an object or undefined" => "INVALID_METADATA_TYPE",
        "The name length is either too large or too small." => "INVALID_NAME_LENGTH",
        "Invalid newUserCallbackURL" => "INVALID_NEW_USER_CALLBACK_URL",
        "Invalid OAuth configuration." => "INVALID_OAUTH_CONFIG",
        "Invalid OAuth configuration" => "INVALID_OAUTH_CONFIGURATION",
        "Invalid origin" => "INVALID_ORIGIN",
        "Invalid OTP" => "INVALID_OTP",
        "Invalid password" => "INVALID_PASSWORD",
        "Invalid phone number" => "INVALID_PHONE_NUMBER",
        "Invalid phone number or password" => "INVALID_PHONE_NUMBER_OR_PASSWORD",
        "The prefix length is either too large or too small." => "INVALID_PREFIX_LENGTH",
        "Invalid redirectURL" => "INVALID_REDIRECT_URL",
        "The reference id from the API key is invalid." => "INVALID_REFERENCE_ID_FROM_API_KEY",
        "The remaining count is either too large or too small." => "INVALID_REMAINING",
        "The provided permission includes an invalid resource" => "INVALID_RESOURCE",
        "Invalid role type" => "INVALID_ROLE_TYPE",
        "Team id contains a reserved character" => "INVALID_TEAM_ID",
        "Invalid token" => "INVALID_TOKEN",
        "Invalid two factor cookie" => "INVALID_TWO_FACTOR_COOKIE",
        "Invalid user" => "INVALID_USER",
        "Invalid user code" => "INVALID_USER_CODE",
        "The user id from the API key is invalid." => "INVALID_USER_ID_FROM_API_KEY",
        "Username is invalid" => "INVALID_USERNAME",
        "Invalid username or password" => "INVALID_USERNAME_OR_PASSWORD",
        "Invitation limit reached" => "INVITATION_LIMIT_REACHED",
        "Invitation not found" => "INVITATION_NOT_FOUND",
        "Inviter is no longer a member of the organization" => {
            "INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION"
        }
        "OAuth issuer mismatch. The authorization server issuer does not match the expected value (RFC 9207)." => {
            "ISSUER_MISMATCH"
        }
        "OAuth issuer parameter missing. The authorization server did not include the required iss parameter (RFC 9207)." => {
            "ISSUER_MISSING"
        }
        "API Key is disabled" => "KEY_DISABLED",
        "Custom key expiration values are disabled." => "KEY_DISABLED_EXPIRATION",
        "API Key has expired" => "KEY_EXPIRED",
        "API Key not found" => "KEY_NOT_FOUND",
        "API Key is not recoverable" => "KEY_NOT_RECOVERABLE",
        "Linked account already exists" => "LINKED_ACCOUNT_ALREADY_EXISTS",
        "Member not found" => "MEMBER_NOT_FOUND",
        "Metadata is disabled." => "METADATA_DISABLED",
        "POST method requires deferSessionRefresh to be enabled in session config" => {
            "METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED"
        }
        "Dynamic Access Control requires a pre-defined ac instance on the server auth plugin. Read server logs for more information" => {
            "MISSING_AC_INSTANCE"
        }
        "Field is required" => "MISSING_FIELD",
        "Missing or null Origin" => "MISSING_OR_NULL_ORIGIN",
        "Missing CAPTCHA response" => "MISSING_RESPONSE",
        "Missing secret key" => "MISSING_SECRET_KEY",
        "API Key name is required." => "NAME_REQUIRED",
        "No active organization" => "NO_ACTIVE_ORGANIZATION",
        "No data to update" => "NO_DATA_TO_UPDATE",
        "No default api-key configuration found." => "NO_DEFAULT_API_KEY_CONFIGURATION_FOUND",
        "No values to update." => "NO_VALUES_TO_UPDATE",
        "Organization already exists" => "ORGANIZATION_ALREADY_EXISTS",
        "Organization ID is required for organization-owned API keys." => {
            "ORGANIZATION_ID_REQUIRED"
        }
        "Organization membership limit reached" => "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED",
        "Organization not found" => "ORGANIZATION_NOT_FOUND",
        "Organization plugin is required for organization-owned API keys. Please install and configure the organization plugin." => {
            "ORGANIZATION_PLUGIN_REQUIRED"
        }
        "Organization slug already taken" => "ORGANIZATION_SLUG_ALREADY_TAKEN",
        "OTP expired" => "OTP_EXPIRED",
        "OTP has expired" => "OTP_HAS_EXPIRED",
        "OTP not enabled" => "OTP_NOT_ENABLED",
        "OTP not found" => "OTP_NOT_FOUND",
        "Passkey not found" => "PASSKEY_NOT_FOUND",
        "User already has a password set" => "PASSWORD_ALREADY_SET",
        "Password cannot be updated through update-user. Use the set-user-password endpoint instead" => {
            "PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER"
        }
        "Password too long" => "PASSWORD_TOO_LONG",
        "Password too short" => "PASSWORD_TOO_SHORT",
        "Phone number cannot be updated" => "PHONE_NUMBER_CANNOT_BE_UPDATED",
        "Phone number already exists" => "PHONE_NUMBER_EXIST",
        "phone number isn't registered" => "PHONE_NUMBER_NOT_EXIST",
        "Phone number not verified" => "PHONE_NUMBER_NOT_VERIFIED",
        "Polling too frequently" => "POLLING_TOO_FREQUENTLY",
        "Sign-in popup was blocked by the browser" => "POPUP_BLOCKED",
        "Sign-in popup was closed before completing" => "POPUP_CLOSED",
        "Popup sign-in failed" => "POPUP_SIGN_IN_FAILED",
        "Sign-in popup timed out" => "POPUP_TIMEOUT",
        "Previously registered" => "PREVIOUSLY_REGISTERED",
        "No config found for provider" => "PROVIDER_CONFIG_NOT_FOUND",
        "Provider ID is required" => "PROVIDER_ID_REQUIRED",
        "Provider not found" => "PROVIDER_NOT_FOUND",
        "Rate limit exceeded." => "RATE_LIMIT_EXCEEDED",
        "refillAmount is required when refillInterval is provided" => {
            "REFILL_AMOUNT_AND_INTERVAL_REQUIRED"
        }
        "refillInterval is required when refillAmount is provided" => {
            "REFILL_INTERVAL_AND_AMOUNT_REQUIRED"
        }
        "Registration cancelled" => "REGISTRATION_CANCELLED",
        "Passkey registration requires either an authenticated session or a resolveUser callback when requireSession is false" => {
            "RESOLVE_USER_REQUIRED"
        }
        "Resolved user is invalid" => "RESOLVED_USER_INVALID",
        "Cannot delete a role that is assigned to members. Please reassign the members to a different role first" => {
            "ROLE_IS_ASSIGNED_TO_MEMBERS"
        }
        "That role name is already taken" => "ROLE_NAME_IS_ALREADY_TAKEN",
        "Role not found" => "ROLE_NOT_FOUND",
        "sendOTP not implemented" => "SEND_OTP_NOT_IMPLEMENTED",
        "The property you're trying to set can only be set from the server auth instance only." => {
            "SERVER_ONLY_PROPERTY"
        }
        "CAPTCHA service unavailable" => "SERVICE_UNAVAILABLE",
        "Session expired. Re-authenticate to perform this action." => "SESSION_EXPIRED",
        "Session is not fresh" => "SESSION_NOT_FRESH",
        "Passkey registration requires an authenticated session" => "SESSION_REQUIRED",
        "Session is required" => "SESSION_REQUIRED",
        "Social account already linked" => "SOCIAL_ACCOUNT_ALREADY_LINKED",
        "Team already exists" => "TEAM_ALREADY_EXISTS",
        "Team member limit reached" => "TEAM_MEMBER_LIMIT_REACHED",
        "Team not found" => "TEAM_NOT_FOUND",
        "Token expired" => "TOKEN_EXPIRED",
        "Invalid OAuth configuration. Token URL not found." => "TOKEN_URL_NOT_FOUND",
        "Too many attempts" => "TOO_MANY_ATTEMPTS",
        "Too many attempts. Please request a new code." => "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE",
        "This organization has too many roles" => "TOO_MANY_ROLES",
        "TOTP not enabled" => "TOTP_NOT_ENABLED",
        "Two factor isn't enabled" => "TWO_FACTOR_NOT_ENABLED",
        "Unable to create session" => "UNABLE_TO_CREATE_SESSION",
        "Unable to remove last team" => "UNABLE_TO_REMOVE_LAST_TEAM",
        "Unauthorized or invalid session" => "UNAUTHORIZED_SESSION",
        "Unexpected error" => "UNEXPECTED_ERROR",
        "Something went wrong" => "UNKNOWN_ERROR",
        "Unknown error" => "UNKNOWN_ERROR",
        "API Key has reached its usage limit" => "USAGE_EXCEEDED",
        "User already exists." => "USER_ALREADY_EXISTS",
        "User already exists. Use another email." => "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
        "User already has a password. Provide that to delete the account." => {
            "USER_ALREADY_HAS_PASSWORD"
        }
        "User is banned" => "USER_BANNED",
        "User email not found" => "USER_EMAIL_NOT_FOUND",
        "User is already a member of this organization" => {
            "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION"
        }
        "User is already invited to this organization" => {
            "USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION"
        }
        "User is not a member of the organization" => "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
        "User is not a member of the team" => "USER_IS_NOT_A_MEMBER_OF_THE_TEAM",
        "User is not anonymous" => "USER_IS_NOT_ANONYMOUS",
        "User not found" => "USER_NOT_FOUND",
        "You are not a member of the organization that owns this API key." => {
            "USER_NOT_MEMBER_OF_ORGANIZATION"
        }
        "Username is already taken. Please try another." => "USERNAME_IS_ALREADY_TAKEN",
        "Username is too long" => "USERNAME_TOO_LONG",
        "Username is too short" => "USERNAME_TOO_SHORT",
        "Validation Error" => "VALIDATION_ERROR",
        "Verification email isn't enabled" => "VERIFICATION_EMAIL_NOT_ENABLED",
        "Captcha verification failed" => "VERIFICATION_FAILED",
        "You are not a member of this organization" => "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
        "You are not allowed to access this organization as an owner" => {
            "YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION"
        }
        "You are not allowed to ban users" => "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS",
        "You are not allowed to cancel this invitation" => {
            "YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION"
        }
        "You are not allowed to change users role" => "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE",
        "You are not allowed to create a new organization" => {
            "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION"
        }
        "You are not allowed to create a new team" => "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM",
        "You are not allowed to create a new member" => {
            "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER"
        }
        "You are not allowed to create a role" => "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE",
        "You are not allowed to create teams in this organization" => {
            "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION"
        }
        "You are not allowed to create users" => "YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS",
        "You are not allowed to delete a role" => "YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE",
        "You are not allowed to delete teams in this organization" => {
            "YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS_IN_THIS_ORGANIZATION"
        }
        "You are not allowed to delete this member" => "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER",
        "You are not allowed to delete this organization" => {
            "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION"
        }
        "You are not allowed to delete this team" => "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM",
        "You are not allowed to delete users" => "YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS",
        "You are not allowed to get a role" => "YOU_ARE_NOT_ALLOWED_TO_GET_A_ROLE",
        "You are not allowed to get user" => "YOU_ARE_NOT_ALLOWED_TO_GET_USER",
        "You are not allowed to impersonate users" => "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS",
        "You are not allowed to invite a user with this role" => {
            "YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE"
        }
        "You are not allowed to invite users to this organization" => {
            "YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION"
        }
        "You are not allowed to list a role" => "YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE",
        "You are not allowed to list users" => "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS",
        "You are not allowed to list users sessions" => {
            "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS"
        }
        "You are not allowed to read a role" => "YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE",
        "You are not allowed to register this passkey" => {
            "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY"
        }
        "You are not allowed to remove a team member" => {
            "YOU_ARE_NOT_ALLOWED_TO_REMOVE_A_TEAM_MEMBER"
        }
        "You are not allowed to revoke users sessions" => {
            "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS"
        }
        "You are not allowed to set a non-existent role value" => {
            "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE"
        }
        "You are not allowed to update users email" => "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_EMAIL",
        "You are not allowed to set users password" => "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD",
        "You are not allowed to update a role" => "YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE",
        "You are not allowed to update this member" => "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER",
        "You are not allowed to update this organization" => {
            "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION"
        }
        "You are not allowed to update this team" => "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM",
        "You are not allowed to update users" => "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS",
        "You are not the recipient of the invitation" => {
            "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION"
        }
        "You are not allowed to list the members of this team" => {
            "YOU_CAN_NOT_ACCESS_THE_MEMBERS_OF_THIS_TEAM"
        }
        "You cannot ban yourself" => "YOU_CANNOT_BAN_YOURSELF",
        "You cannot impersonate admins" => "YOU_CANNOT_IMPERSONATE_ADMINS",
        "You cannot leave the organization as the only owner" => {
            "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER"
        }
        "You cannot leave the organization without an owner" => {
            "YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER"
        }
        "You cannot remove yourself" => "YOU_CANNOT_REMOVE_YOURSELF",
        "You do not have an active team" => "YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM",
        "You have reached the maximum number of organizations" => {
            "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS"
        }
        "You have reached the maximum number of teams" => {
            "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS"
        }
        "You must be in an organization to create a role" => {
            "YOU_MUST_BE_IN_AN_ORGANIZATION_TO_CREATE_A_ROLE"
        }
        "Access token not found" => "ACCESS_TOKEN_NOT_FOUND",
        "Multiple accounts share this account ID. Pass a providerId to disambiguate." => {
            "AMBIGUOUS_ACCOUNT"
        }
        "Email and password is not enabled" => "EMAIL_PASSWORD_DISABLED",
        "Email and password sign up is not enabled" => "EMAIL_PASSWORD_SIGN_UP_DISABLED",
        "failed to create session" => "FAILED_TO_CREATE_SESSION",
        "Failed to get a valid access token" => "FAILED_TO_GET_ACCESS_TOKEN",
        "Failed to refresh access token" => "FAILED_TO_REFRESH_ACCESS_TOKEN",
        "Internal Server Error" => "INTERNAL_SERVER_ERROR",
        "Invitation not found!" => "INVITATION_NOT_FOUND",
        "Account not linked - different emails not allowed" => {
            "LINKING_DIFFERENT_EMAILS_NOT_ALLOWED"
        }
        "Account not linked - unable to create account" => "LINKING_FAILED",
        "Account not linked - linking not allowed" => "LINKING_NOT_ALLOWED",
        "Not found" => "NOT_FOUND",
        "Organization deletion is disabled" => "ORGANIZATION_DELETION_DISABLED",
        "otp isn't configured" => "OTP_NOT_CONFIGURED",
        "Account is not associated with a configured social provider." => "PROVIDER_NOT_CONFIGURED",
        "Refresh token not found" => "REFRESH_TOKEN_NOT_FOUND",
        "Reset password isn't enabled" => "RESET_PASSWORD_DISABLED",
        "totp isn't configured" => "TOTP_NOT_CONFIGURED",
        "Unauthorized" => "UNAUTHORIZED",
        "Either userId or session is required" => "USER_ID_OR_SESSION_REQUIRED",
        _ => return None,
    };
    Some(code)
}
