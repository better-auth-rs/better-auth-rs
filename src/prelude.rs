//! Common traits and data types used by handlers, tests, hooks, and direct dispatch.

pub use crate::{AuthBuilder, AuthConfig, AuthError, AuthResult, AuthSchema, BetterAuth};
pub use better_auth_core::entity::{
    AuthAccount, AuthApiKey, AuthInvitation, AuthMember, AuthOrganization, AuthPasskey,
    AuthSession, AuthTwoFactor, AuthUser, AuthVerification, MemberUserView,
};
pub use better_auth_core::types::{
    ApiKey, AuthRequest, AuthResponse, CreateAccount, CreateApiKey, CreateDeviceCode,
    CreateInvitation, CreateMember, CreateOrganization, CreatePasskey, CreateSession,
    CreateTwoFactor, CreateUser, CreateVerification, DeviceCode, Headers, HttpMethod, Invitation,
    InvitationStatus, ListUsersParams, Member, Organization, Passkey, RequestMeta, TwoFactor,
    UpdateAccount, UpdateApiKey, UpdateDeviceCode, UpdateOrganization, UpdatePasskey, UpdateUser,
    UpdateUserRequest, UpdateUserResponse,
};
pub use better_auth_core::wire::{AccountView, SessionView, UserView, VerificationView};
