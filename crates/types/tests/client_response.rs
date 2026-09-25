use better_auth_types::{
    AccountView, ApiKeyView, InvitationStatus, InvitationView, MemberUserView, OrganizationView,
    PasskeyView, SessionView, UserView, VerificationView,
};
use serde::Deserialize;

// These envelopes belong to the client application. Only the shared entity
// views are imported, so this target also compiles without the server crates.
#[derive(Deserialize)]
struct SignUpResponse {
    token: String,
    user: UserView,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResponseViews {
    account: AccountView,
    verification: VerificationView,
    organization: OrganizationView,
    invitation: InvitationView,
    passkey: PasskeyView,
    api_key: ApiKeyView,
    member_user: MemberUserView,
}

#[test]
fn client_deserializes_remaining_response_views() -> Result<(), serde_json::Error> {
    let mut views: ResponseViews =
        serde_json::from_str(include_str!("fixtures/response_views.json"))?;
    assert_eq!(views.account.provider_id, "github");
    assert_eq!(views.account.user_id, views.member_user.id);
    assert_eq!(
        views.account.access_token_expires_at,
        Some(views.verification.expires_at)
    );
    assert!(views.account.password.is_none());
    views.account.password = Some("fixture-password-hash".to_owned());
    assert!(
        serde_json::to_value(&views.account)?
            .get("password")
            .is_none()
    );

    assert_eq!(views.verification.value, "fixture-verification-token");
    assert_eq!(views.verification.identifier, "fixture@example.com");
    assert_eq!(views.organization.slug, "fixture-org");
    assert_eq!(
        views.organization.metadata,
        Some(serde_json::json!(r#"{"plan":"free"}"#))
    );
    // Preserve the existing wire serializer's JSON-string representation.
    views.organization.metadata = Some(serde_json::json!({"plan": "free"}));
    assert_eq!(
        serde_json::to_value(&views.organization)?["metadata"],
        r#"{"plan":"free"}"#
    );
    views.organization.metadata = None;
    assert!(
        serde_json::to_value(&views.organization)?
            .get("metadata")
            .is_none()
    );

    assert_eq!(views.invitation.organization_id, views.organization.id);
    assert_eq!(views.invitation.status, InvitationStatus::Pending);
    assert_eq!(
        views.invitation.expires_at - views.invitation.created_at,
        chrono::Duration::days(7)
    );
    for (wire, status) in [
        ("pending", InvitationStatus::Pending),
        ("accepted", InvitationStatus::Accepted),
        ("rejected", InvitationStatus::Rejected),
        ("canceled", InvitationStatus::Canceled),
    ] {
        assert_eq!(
            serde_json::from_value::<InvitationStatus>(serde_json::json!(wire))?,
            status
        );
        assert_eq!(serde_json::to_value(status)?, wire);
    }

    assert_eq!(views.passkey.credential_id, "fixture-credential-id");
    assert!(views.passkey.backed_up);
    let passkey = serde_json::to_value(&views.passkey)?;
    assert_eq!(passkey["credentialID"], "fixture-credential-id");
    for omitted in ["name", "transports", "aaguid", "credential"] {
        assert!(passkey.get(omitted).is_none());
    }

    assert_eq!(views.api_key.reference_id, views.member_user.id);
    assert_eq!(views.api_key.config_id, "default");
    assert_eq!(views.api_key.remaining, Some(10));
    assert!(views.api_key.expires_at.is_none());
    let api_key = serde_json::to_value(&views.api_key)?;
    assert_eq!(
        api_key["permissions"]["documents"],
        serde_json::json!(["read"])
    );
    assert_eq!(api_key["metadata"]["plan"], "free");
    for omitted in ["key_hash", "keyHash", "key"] {
        assert!(api_key.get(omitted).is_none());
    }
    assert_eq!(
        views.member_user.email.as_deref(),
        Some("fixture@example.com")
    );
    assert!(views.member_user.image.is_none());
    Ok(())
}

#[derive(Deserialize)]
struct SessionResponse {
    session: SessionView,
    user: UserView,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeCapture {
    version: String,
    signup: SignUpResponse,
    get_session: SessionResponse,
    unauthenticated_get_session: Option<SessionResponse>,
}

#[test]
fn client_deserializes_typescript_auth_responses() -> Result<(), serde_json::Error> {
    let captures: Vec<RuntimeCapture> =
        serde_json::from_str(include_str!("fixtures/core_auth_responses.json"))?;
    assert_eq!(captures.len(), 2);

    for capture in captures {
        let user = capture.get_session.user;
        let session = capture.get_session.session;
        assert_eq!(capture.signup.user, user, "{}", capture.version);
        assert_eq!(capture.signup.token, session.token);
        assert_eq!(session.user_id, user.id);
        assert_eq!(user.email.as_deref(), Some("types-fixture@example.com"));
        assert_eq!(user.name.as_deref(), Some("Types Fixture"));
        assert!(!user.email_verified);
        assert!(user.image.is_none());
        assert!(user.username.is_none());
        assert!(!user.two_factor_enabled);
        assert!(!user.banned);
        assert!(session.impersonated_by.is_none());
        assert!(session.active_organization_id.is_none());
        assert_eq!(session.ip_address.as_deref(), Some(""));
        assert_eq!(
            session.expires_at - session.created_at,
            chrono::Duration::days(7)
        );
        assert!(session.created_at >= user.created_at);
        assert!(capture.unauthenticated_get_session.is_none());

        // A client can tolerate additional plugin fields while internal-only
        // values stay out of the shared response representation.
        let mut user_json = serde_json::to_value(&user)?;
        user_json["customPluginField"] = serde_json::json!({"enabled": true});
        user_json["metadata"] = serde_json::json!({"internal": true});
        let parsed_user: UserView = serde_json::from_value(user_json)?;
        assert_eq!(parsed_user, user);
        assert!(serde_json::to_value(parsed_user)?.get("metadata").is_none());

        let mut session_json = serde_json::to_value(&session)?;
        session_json["customPluginField"] = serde_json::json!("extra");
        session_json["active"] = serde_json::json!(true);
        let parsed_session: SessionView = serde_json::from_value(session_json)?;
        assert_eq!(parsed_session, session);
        assert!(
            serde_json::to_value(parsed_session)?
                .get("active")
                .is_none()
        );
    }
    Ok(())
}
