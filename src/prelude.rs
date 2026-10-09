//! Common traits and data types used by handlers, tests, hooks, and direct dispatch.

pub use crate::{
    ApiKeyStart, Argon2PasswordHasher, AuthBuilder, AuthConfig, AuthError, AuthResult, AuthSchema,
    BetterAuth, ResponseBlob, ResponseBody, SchemaValue, ScryptPasswordHasher,
};
pub use better_auth_core::PasswordHasher;
pub use better_auth_core::entity::{
    AuthAccount, AuthApiKey, AuthInvitation, AuthMember, AuthOrganization, AuthPasskey,
    AuthSession, AuthTwoFactor, AuthUser, AuthVerification, MemberUserView,
};
pub use better_auth_core::types::{
    ApiKey, AuthRequest, AuthResponse, CreateAccount, CreateApiKey, CreateDeviceCode,
    CreateInvitation, CreateMember, CreateOrganization, CreatePasskey, CreateSession,
    CreateTwoFactor, CreateUser, CreateVerification, CreateWalletAddress, DeviceCode,
    DeviceCodeOwnership, DeviceCodeWhere, Headers, HttpMethod, Invitation, InvitationStatus,
    ListUsersParams, Member, NativeResponseStatus, Organization, Passkey, PasskeyCredentialState,
    PasskeyStorage, RequestMeta, TwoFactor, TwoFactorStorage, UpdateAccount, UpdateApiKey,
    UpdateDeviceCode, UpdateOrganization, UpdatePasskey, UpdateTwoFactor, UpdateUser,
    UpdateUserRequest, UpdateUserResponse, WhereMode, WhereOperator,
};
pub use better_auth_core::wire::{AccountView, SessionView, UserView, VerificationView};

pub use better_auth_core::{
    CreateJwk, CreateOrganizationRole, CreateTeam, Jwk, OrganizationRole, Team, TeamMember,
    UpdateOrganizationRole, UpdatePasskeyAuthentication, WalletAddress,
};
