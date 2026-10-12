#![expect(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "Fixture indexing must fail when an expected record or property is missing. Assertions report exact contract mismatches while Result propagates fixture errors."
)]

use super::*;
use crate::store::TeamMemberLimits;
use crate::user_fields::UserFieldType;

fn status_store(
    expected: &JsonValue,
    trace: &Events,
    fail_member: bool,
) -> AuthResult<EphemeralStore> {
    let kind = match required(expected["type"].as_str())? {
        "json" => "json",
        "string" => "string",
        "boolean" => "boolean",
        "nan" => "nan",
        _ => return Err(AuthError::internal("Unknown Invitation status declaration")),
    };
    let store = EphemeralStore::new(Arc::new(AuthConfig::default()));
    seed(&store, &expected["steps"][0]["before"])?;
    let mut fields = OrganizationFields::default();
    let input_trace = trace.clone();
    let output_trace = trace.clone();
    let _ = fields.invitation.fields_mut().insert(
        "status".into(),
        UserFieldConfig {
            field_type: match kind {
                "json" => UserFieldType::Json,
                "boolean" => UserFieldType::Boolean,
                _ => UserFieldType::String,
            },
            field_name: Some("stored_status".into()),
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    record(
                        &input_trace,
                        json!(["input", "invitation.status", value_observation(&value)?]),
                    )?;
                    let accepted = value.strict_equals(&"accepted".into());
                    Ok(match kind {
                        "boolean" => accepted.into(),
                        "nan" if accepted => f64::NAN.into(),
                        "string" if accepted => "claimed".into(),
                        _ => value,
                    })
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    record(
                        &output_trace,
                        json!(["output", "invitation.status", value_observation(&value)?]),
                    )?;
                    Ok(value)
                })),
            }),
            ..Default::default()
        },
    );
    if fail_member {
        let mut role =
            required(fields.schema_for(EntityRole::Member)?.fields().get("role"))?.clone();
        role.transform = Some(FieldTransforms {
            input: Some(UserFieldTransform::new(|_| {
                Err(AuthError::internal("membership-failed"))
            })),
            ..Default::default()
        });
        let _ = fields.member.fields_mut().insert("role".into(), role);
    }
    store.configure_organization_fields(fields)?;
    Ok(store)
}

async fn verify_status_case(expected: &JsonValue, fail_member: bool) -> AuthResult<()> {
    let trace = Events::default();
    let store = status_store(expected, &trace, fail_member)?;
    let step = &expected["steps"][0];
    assert_eq!(memory(&store)?, step["before"]);
    assert_eq!(step["returned"], true);
    assert_eq!(
        step["input"],
        json!({"invitationId":"invitation","status":"accepted","fromStatus":"pending"})
    );
    let result = store
        .accept_invitation_with_teams_values(
            &"invitation".into(),
            &"recipient".into(),
            None,
            false,
            TeamMemberLimits::Fixed(None),
        )
        .await;
    if step["result"].is_null() {
        let error = required(result.err())?;
        assert_eq!(error.status_value()?, Value::from("BAD_REQUEST"));
        assert_eq!(
            error.body_value()?.json()?,
            Some(json!({"message":"Invitation not found","code":"INVITATION_NOT_FOUND"}))
        );
        assert_eq!(json!(events(&trace)?), step["events"]);
        assert_eq!(memory(&store)?, step["after"]);
    } else if fail_member {
        let error = required(result.err())?;
        assert!(matches!(error, AuthError::Internal(message) if message == "membership-failed"));
        let restore = &expected["steps"][1];
        assert_eq!(restore["returned"], true);
        assert_eq!(restore["result"], JsonValue::Null);
        assert_eq!(
            restore["input"],
            json!({"invitationId":"invitation","status":"pending","fromStatus":"accepted"})
        );
        let mut expected_events = required(step["events"].as_array())?.clone();
        expected_events.extend(required(restore["events"].as_array())?.iter().cloned());
        assert_eq!(events(&trace)?, expected_events);
        assert_eq!(memory(&store)?, restore["after"]);
    } else {
        let (member, invitation, session) = result?;
        let returned = Value::from(invitation.field_values()?);
        assert_eq!(value_observation(&returned)?, step["result"]);
        assert_eq!(json!(key_order(&returned, Vec::new())?), step["keyOrder"]);
        assert_eq!(json!(events(&trace)?), step["events"]);
        assert_eq!(member.organization_id, "parent");
        assert_eq!(member.user_id, "recipient");
        assert_eq!(member.role, "member");
        assert!(session.is_none());
        // Aggregate acceptance adds a Member after the source helper's atomic Invitation update.
        let mut after = required(step["after"].as_object())?.clone();
        let _ = after.insert(
            "member".into(),
            json!([observe(member.field_values()?, false)?]),
        );
        assert_eq!(memory(&store)?, JsonValue::Object(after));
    }
    Ok(())
}

#[tokio::test]
async fn invitation_claim_status_policies_preserve_commit_and_compensation() -> AuthResult<()> {
    let fixture: JsonValue = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/invitation-claim-status-1.7.6.json"
    )))?;
    assert_eq!(fixture["version"], "1.7.6");
    assert_eq!(fixture["backend"], "memory");
    let cases = required(fixture["cases"].as_array())?;
    assert_eq!(
        cases
            .iter()
            .map(|case| required(case["scenario"].as_str()))
            .collect::<AuthResult<Vec<_>>>()?,
        [
            "invitation-claim-status-json",
            "invitation-claim-status-string",
            "invitation-claim-status-boolean",
            "invitation-claim-status-nan",
        ]
    );
    for case in cases {
        verify_status_case(case, false).await?;
        if !case["steps"][0]["result"].is_null() {
            verify_status_case(case, true).await?;
        }
    }
    Ok(())
}
