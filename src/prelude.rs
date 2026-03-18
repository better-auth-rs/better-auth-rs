//! Common traits and data types used by handlers, tests, hooks, and direct dispatch.

pub use crate::{
    AuthAccountModel, AuthBuilder, AuthConfig, AuthEntity, AuthError, AuthResult, AuthSchema,
    AuthSessionModel, AuthUserModel, AuthVerificationModel, BetterAuth,
};
pub use better_auth_core::entity::{
    AuthAccount, AuthApiKey, AuthInvitation, AuthMember, AuthOrganization, AuthPasskey,
    AuthSession, AuthTwoFactor, AuthUser, AuthVerification, MemberUserView,
};
pub use better_auth_core::types::{
    Account, ApiKey, AuthRequest, AuthResponse, CreateAccount, CreateApiKey, CreateInvitation,
    CreateMember, CreateOrganization, CreatePasskey, CreateSession, CreateTwoFactor, CreateUser,
    CreateVerification, Headers, HttpMethod, Invitation, InvitationStatus, ListUsersParams, Member,
    Organization, Passkey, RequestMeta, Session, TwoFactor, UpdateAccount, UpdateApiKey,
    UpdateOrganization, UpdatePasskey, UpdateUser, UpdateUserRequest, UpdateUserResponse, User,
    Verification,
};
pub use better_auth_core::wire::{AccountView, SessionView, UserView, VerificationView};
