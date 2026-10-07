use super::*;
use crate::CreateTeam;
use crate::organization_fields::OrganizationFields;
use crate::store::{TeamMemberLimits, TeamStore};
use crate::user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Notify;

#[tokio::test]
async fn serial_team_membership_binds_owner_queries_and_isolates_removal() -> AuthResult<()> {
    for native in [false, true] {
        let mut config = AuthConfig::default();
        config.advanced.database.generate_id = Some(crate::id::IdGeneration::Serial);
        config.advanced.database.joins = Some(native);
        let store = EphemeralStore::new(Arc::new(config));
        let first = store
            .create_team(CreateTeam {
                name: "First".into(),
                organization_id: "001".into(),
                ..Default::default()
            })
            .await?;
        let second = store
            .create_team(CreateTeam {
                name: "Second".into(),
                organization_id: "001".into(),
                ..Default::default()
            })
            .await?;
        let owner = required(store.add_team_member(&first.id, "001", Some(2)).await?)?;
        assert_eq!(owner.user_id.field_value(), Value::from("1"));
        assert_eq!(
            required(store.add_team_member(&first.id, "1", Some(2)).await?)?,
            owner
        );
        let other = required(store.add_team_member(&first.id, "002", Some(2)).await?)?;
        assert!(
            store
                .add_team_member(&first.id, "003", Some(2))
                .await?
                .is_none()
        );
        let elsewhere = required(store.add_team_member(&second.id, "001", Some(1)).await?)?;
        assert_eq!(
            required(store.get_team_member("001", "0001").await?)?,
            owner
        );
        assert_eq!(
            store.list_team_members("001").await?,
            vec![owner, other.clone()]
        );
        assert_eq!(
            store
                .list_user_teams("0001")
                .await?
                .into_iter()
                .map(|team| team.id)
                .collect::<Vec<_>>(),
            vec![first.id, second.id]
        );
        assert_eq!(
            store
                .lock()?
                .team_members
                .snapshot()?
                .into_iter()
                .map(|member| member.user_id.field_value())
                .collect::<Vec<_>>(),
            vec![Value::Number(1.0), Value::Number(2.0), Value::Number(1.0)]
        );
        store.remove_team_member("001", "0001").await?;
        assert!(store.get_team_member("1", "1").await?.is_none());
        assert_eq!(store.list_team_members("001").await?, vec![other]);
        assert_eq!(store.list_team_members("002").await?, vec![elsewhere]);
        assert_eq!(store.count_team_members("001").await?, 1);
        assert_eq!(store.count_team_members("002").await?, 1);
        let invalid = required(
            store
                .add_team_member(&"001".into(), "not-a-number", None)
                .await?,
        )?;
        assert_eq!(invalid.user_id, "NaN");
        assert!(
            store
                .get_team_member("001", "not-a-number")
                .await?
                .is_none()
        );
        store.remove_team_member("001", "0002").await?;
        assert_eq!(store.list_team_members("001").await?, vec![invalid]);
        let state = store.lock()?;
        assert!(matches!(
            required(state.team_members.snapshot()?.iter().find(|row| {
                row.team_id.field_value().strict_equals(&Value::Number(1.0))
            }))?
            .user_id
            .field_value(),
            Value::Number(value) if value.is_nan()
        ));
        for team in state.teams.snapshot()? {
            assert_eq!(
                team.additional_fields.get("memberCount"),
                Some(&Value::Number(1.0))
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn serial_invitation_reuses_existing_numeric_team_owner_at_capacity() -> AuthResult<()> {
    let store = serial_store();
    let team = store
        .create_team(CreateTeam {
            name: "Team".into(),
            organization_id: "001".into(),
            ..Default::default()
        })
        .await?;
    let existing = required(store.add_team_member(&team.id, "001", Some(1)).await?)?;
    let mut input = organization::invitation();
    input.team_id = Some("001".into());
    let invitation = store.create_invitation(input).await?;
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let mut fields = OrganizationFields::default();
    let _ = fields.team.fields_mut().insert(
        "memberCount".into(),
        UserFieldConfig {
            field_type: UserFieldType::Number,
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    let _ = counted.fetch_add(1, Ordering::SeqCst);
                    Ok(value)
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    store.configure_organization_fields(fields)?;
    let (member, accepted, _) = store
        .accept_invitation_with_teams(
            invitation.id.typed()?,
            "0001",
            None,
            true,
            TeamMemberLimits::Fixed(Some(1)),
        )
        .await?;
    assert_eq!(member.user_id.field_value(), Value::from("1"));
    assert_eq!(accepted.status, InvitationStatus::Accepted);
    assert_eq!(store.list_team_members("001").await?, vec![existing]);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        required(store.lock()?.team_members.snapshot()?.first())?
            .user_id
            .field_value(),
        Value::Number(1.0)
    );
    Ok(())
}

#[tokio::test]
async fn serial_invitation_rejects_same_owner_added_during_output_callback() -> AuthResult<()> {
    let store = serial_store();
    let team = store
        .create_team(CreateTeam {
            name: "Team".into(),
            organization_id: "001".into(),
            ..Default::default()
        })
        .await?;
    let mut input = organization::invitation();
    input.team_id = Some("1".into());
    let invitation = store.create_invitation(input).await?;
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let mut fields = OrganizationFields::default();
    let _ = fields.member.fields_mut().insert(
        "role".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new_async({
                    let started = started.clone();
                    let release = release.clone();
                    let calls = calls.clone();
                    move |value| {
                        let started = started.clone();
                        let release = release.clone();
                        let calls = calls.clone();
                        async move {
                            let _ = calls.fetch_add(1, Ordering::SeqCst);
                            started.notify_one();
                            release.notified().await;
                            Ok(value)
                        }
                    }
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    store.configure_organization_fields(fields)?;
    let acceptance = tokio::spawn({
        let store = store.clone();
        let id = invitation.id.typed()?.clone();
        async move {
            store
                .accept_invitation_with_teams(
                    &id,
                    "001",
                    None,
                    true,
                    TeamMemberLimits::Fixed(Some(1)),
                )
                .await
        }
    });
    started.notified().await;
    let concurrent = required(store.add_team_member(&team.id, "0001", Some(1)).await?)?;
    release.notify_one();
    let result = acceptance
        .await
        .map_err(|error| AuthError::internal(format!("Invitation task failed: {error}")))?;
    assert!(matches!(result, Err(AuthError::Conflict(_))));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.list_team_members("001").await?, vec![concurrent]);
    assert!(required(store.get_invitation_by_id("001").await?)?.is_pending());
    let state = store.lock()?;
    assert_eq!(state.members.len(), 0);
    assert_eq!(state.team_members.len(), 1);
    assert_eq!(state.sessions.len(), 0);
    assert_eq!(
        required(state.team_members.snapshot()?.first())?
            .user_id
            .field_value(),
        Value::Number(1.0)
    );
    assert_eq!(
        required(state.teams.snapshot()?.first())?
            .additional_fields
            .get("memberCount"),
        Some(&Value::Number(1.0))
    );
    Ok(())
}
