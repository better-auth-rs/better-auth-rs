#![cfg(feature = "derive")]

// Import entity traits for method calls
use better_auth_core::entity::{
    AuthAccount as AuthAccountTrait, AuthMember as AuthMemberTrait,
    AuthPasskey as AuthPasskeyTrait, AuthSession as AuthSessionTrait,
    AuthTwoFactor as AuthTwoFactorTrait, AuthUser as AuthUserTrait,
    AuthVerification as AuthVerificationTrait,
};

// Import derive macros (re-exported from better_auth_core when `derive` feature is on)
use better_auth_core::{
    AuthAccount, AuthMember, AuthPasskey, AuthSession, AuthTwoFactor, AuthUser, AuthVerification,
};

use chrono::{DateTime, Utc};
use serde::Serialize;

// --- Custom User ---

#[derive(Clone, Debug, Serialize, AuthUser)]
struct MyUser {
    id: String,
    email: Option<String>,
    #[auth(field = "name")]
    display_name: Option<String>,
    email_verified: bool,
    image: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    username: Option<String>,
    display_username: Option<String>,
    two_factor_enabled: bool,
    role: Option<String>,
    banned: bool,
    ban_reason: Option<String>,
    ban_expires: Option<DateTime<Utc>>,
    metadata: serde_json::Value,
    // Extra field — should be ignored by the derive macro
    extra_field: String,
}

// --- Custom Session ---

#[derive(Clone, Debug, Serialize, AuthSession)]
struct MySession {
    id: String,
    expires_at: DateTime<Utc>,
    token: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    user_id: String,
    impersonated_by: Option<String>,
    active_organization_id: Option<String>,
    active: bool,
}

// --- Custom Account ---

#[derive(Clone, Debug, Serialize, AuthAccount)]
struct MyAccount {
    id: String,
    account_id: String,
    provider_id: String,
    user_id: String,
    access_token: Option<String>,
    refresh_token: Option<String>,
    id_token: Option<String>,
    access_token_expires_at: Option<DateTime<Utc>>,
    refresh_token_expires_at: Option<DateTime<Utc>>,
    scope: Option<String>,
    password: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

// --- Custom Member ---

#[derive(Clone, Debug, Serialize, AuthMember)]
struct MyMember {
    id: String,
    organization_id: String,
    user_id: String,
    role: String,
    created_at: DateTime<Utc>,
}

// --- Custom Verification ---

#[derive(Clone, Debug, Serialize, AuthVerification)]
struct MyVerification {
    id: String,
    identifier: String,
    value: String,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

// --- Custom TwoFactor ---

#[derive(Clone, Debug, Serialize, AuthTwoFactor)]
struct MyTwoFactor {
    id: String,
    secret: String,
    backup_codes: Option<String>,
    user_id: String,
}

// --- Custom Passkey ---

#[derive(Clone, Debug, Serialize, AuthPasskey)]
struct MyPasskey {
    id: String,
    name: String,
    public_key: String,
    user_id: String,
    credential_id: String,
    counter: u64,
    device_type: String,
    backed_up: bool,
}

#[test]
fn test_derive_auth_user() {
    let now = Utc::now();
    let user = MyUser {
        id: "user_1".into(),
        email: Some("test@example.com".into()),
        display_name: Some("Test User".into()),
        email_verified: true,
        image: None,
        created_at: now,
        updated_at: now,
        username: Some("testuser".into()),
        display_username: None,
        two_factor_enabled: false,
        role: Some("admin".into()),
        banned: false,
        ban_reason: None,
        ban_expires: None,
        metadata: serde_json::json!({}),
        extra_field: "ignored".into(),
    };

    assert_eq!(AuthUserTrait::id(&user), "user_1");
    assert_eq!(AuthUserTrait::email(&user), Some("test@example.com"));
    assert_eq!(AuthUserTrait::name(&user), Some("Test User")); // mapped via #[auth(field = "name")]
    assert!(user.email_verified());
    assert_eq!(user.image(), None);
    assert_eq!(user.username(), Some("testuser"));
    assert_eq!(user.role(), Some("admin"));
    assert!(!user.banned());
    assert_eq!(user.metadata(), &serde_json::json!({}));
}

#[test]
fn test_derive_auth_session() {
    let now = Utc::now();
    let session = MySession {
        id: "sess_1".into(),
        expires_at: now,
        token: "token_abc".into(),
        created_at: now,
        updated_at: now,
        ip_address: Some("127.0.0.1".into()),
        user_agent: None,
        user_id: "user_1".into(),
        impersonated_by: None,
        active_organization_id: Some("org_1".into()),
        active: true,
    };

    assert_eq!(AuthSessionTrait::id(&session), "sess_1");
    assert_eq!(session.token(), "token_abc");
    assert_eq!(session.user_id(), "user_1");
    assert!(session.active());
    assert_eq!(session.ip_address(), Some("127.0.0.1"));
    assert_eq!(session.active_organization_id(), Some("org_1"));
}

#[test]
fn test_derive_auth_account() {
    let now = Utc::now();
    let account = MyAccount {
        id: "acc_1".into(),
        account_id: "google_123".into(),
        provider_id: "google".into(),
        user_id: "user_1".into(),
        access_token: Some("at_xyz".into()),
        refresh_token: None,
        id_token: None,
        access_token_expires_at: None,
        refresh_token_expires_at: None,
        scope: Some("openid email".into()),
        password: None,
        created_at: now,
        updated_at: now,
    };

    assert_eq!(AuthAccountTrait::id(&account), "acc_1");
    assert_eq!(account.provider_id(), "google");
    assert_eq!(account.access_token(), Some("at_xyz"));
    assert_eq!(account.scope(), Some("openid email"));
}

#[test]
fn test_derive_auth_member() {
    let now = Utc::now();
    let member = MyMember {
        id: "mem_1".into(),
        organization_id: "org_1".into(),
        user_id: "user_1".into(),
        role: "admin".into(),
        created_at: now,
    };

    assert_eq!(AuthMemberTrait::id(&member), "mem_1");
    assert_eq!(member.organization_id(), "org_1");
    assert_eq!(member.role(), "admin");
}

#[test]
fn test_derive_auth_verification() {
    let now = Utc::now();
    let verification = MyVerification {
        id: "ver_1".into(),
        identifier: "test@example.com".into(),
        value: "verify_token_abc".into(),
        expires_at: now,
        created_at: now,
        updated_at: now,
    };

    assert_eq!(AuthVerificationTrait::id(&verification), "ver_1");
    assert_eq!(verification.identifier(), "test@example.com");
    assert_eq!(verification.value(), "verify_token_abc");
}

#[test]
fn test_derive_auth_two_factor() {
    let tf = MyTwoFactor {
        id: "tf_1".into(),
        secret: "JBSWY3DPEHPK3PXP".into(),
        backup_codes: Some("code1,code2".into()),
        user_id: "user_1".into(),
    };

    assert_eq!(AuthTwoFactorTrait::id(&tf), "tf_1");
    assert_eq!(tf.secret(), "JBSWY3DPEHPK3PXP");
    assert_eq!(tf.backup_codes(), Some("code1,code2"));
}

#[test]
fn test_derive_auth_passkey() {
    let pk = MyPasskey {
        id: "pk_1".into(),
        name: "My Security Key".into(),
        public_key: "pk_data".into(),
        user_id: "user_1".into(),
        credential_id: "cred_abc".into(),
        counter: 42,
        device_type: "usb".into(),
        backed_up: true,
    };

    assert_eq!(AuthPasskeyTrait::id(&pk), "pk_1");
    assert_eq!(pk.name(), "My Security Key");
    assert_eq!(pk.counter(), 42);
    assert!(pk.backed_up());
    assert_eq!(pk.credential_id(), "cred_abc");
}
