use super::*;
use std::collections::BTreeMap;

pub(super) type Snapshot = BTreeMap<String, Vec<FieldMap>>;

pub(super) async fn seed<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    case: Case,
) -> AuthResult<String> {
    for id in ["user-a", "user-b"] {
        let _ = store
            .create_user(CreateUser {
                id: Some(id.into()),
                created_at: Some(date(0)),
                updated_at: Some(date(0)),
                image: None.into(),
                ..CreateUser::new()
                    .with_name(id)
                    .with_email(format!("{id}@team-member-fields.test"))
                    .with_email_verified(true)
            })
            .await?;
    }
    let _ = store
        .insert_organization(Organization {
            id: "organization".into(),
            name: "Organization".into(),
            slug: "organization".into(),
            logo: None.into(),
            metadata: Some(FieldValue::from("{}")).into(),
            created_at: date(0).into(),
            additional_fields: Default::default(),
        })
        .await?;
    for (id, name) in [("team-a", "Team A"), ("team-b", "Team B")] {
        let _ = store
            .create_team(CreateTeam {
                id: Some(id.into()),
                name: name.into(),
                organization_id: "organization".into(),
                created_at: Some(date(0)),
                updated_at: Some(date(0)),
                ..Default::default()
            })
            .await?;
    }
    let _ = store
        .insert_member(Member {
            field_order: Default::default(),
            additional_fields: Default::default(),
            id: "owner-member".into(),
            organization_id: "organization".into(),
            user_id: "user-a".into(),
            role: "owner".into(),
            created_at: date(0).into(),
        })
        .await?;
    let _ = store
        .create_invitation(CreateInvitation {
            id: Some("invitation-a".into()),
            created_at: Some(date(0)),
            ..CreateInvitation::new(
                "organization",
                "user-b@team-member-fields.test",
                "member",
                "user-a",
                date(30),
            )
        })
        .await?;
    let session = store
        .create_session(CreateSession {
            inherited_fields: Default::default(),
            additional_fields: [("activeTeamId".into(), FieldValue::Null)].into(),
            user_id: case.actor().into(),
            expires_at: date(300),
            active_organization_id: None,
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
        })
        .await?;
    Ok(session.token.typed()?.clone())
}

pub(super) async fn snapshot(storage: &Storage) -> AuthResult<Snapshot> {
    let mut result = Snapshot::new();
    for (model, table, role) in [
        ("user", "users", EntityRole::User),
        ("session", "sessions", EntityRole::Session),
        ("account", "accounts", EntityRole::Account),
        ("verification", "verifications", EntityRole::Verification),
        ("organization", "organization", EntityRole::Organization),
        ("member", "member", EntityRole::Member),
        ("invitation", "invitation", EntityRole::Invitation),
        ("team", "team", EntityRole::Team),
        ("teamMember", "team_member", EntityRole::TeamMember),
    ] {
        let mut rows = match storage {
            Storage::Memory(store) => store.storage_rows(role)?,
            Storage::Sqlite(database) => {
                let columns = database
                    .query_all_raw(Statement::from_string(
                        DbBackend::Sqlite,
                        format!("PRAGMA table_info(\"{table}\")"),
                    ))
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                let columns = columns
                    .iter()
                    .map(|row| {
                        row.try_get::<String>("", "name")
                            .map_err(|error| AuthError::internal(error.to_string()))
                    })
                    .collect::<AuthResult<Vec<_>>>()?;
                let fields = columns
                    .iter()
                    .map(|name| {
                        format!(
                            "'{}', \"{}\"",
                            name.replace('\'', "''"),
                            name.replace('"', "\"\"")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                let rows = database
                    .query_all_raw(Statement::from_string(
                        DbBackend::Sqlite,
                        format!(
                            "SELECT json_object({fields}) AS record FROM \"{table}\" ORDER BY id"
                        ),
                    ))
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                rows.into_iter()
                    .map(|row| {
                        let json = row
                            .try_get::<String>("", "record")
                            .map_err(|error| AuthError::internal(error.to_string()))?;
                        FieldMap::from_json(serde_json::from_str(&json)?)
                    })
                    .collect::<AuthResult<Vec<_>>>()?
            }
        };
        rows.sort_by(|left, right| {
            left.get("id")
                .and_then(FieldValue::as_str)
                .cmp(&right.get("id").and_then(FieldValue::as_str))
        });
        let _ = result.insert(model.into(), rows);
    }
    Ok(result)
}

pub(super) fn update_expected(
    storage: &Storage,
    case: Case,
    snapshot: &mut Snapshot,
) -> AuthResult<()> {
    if matches!(case, Case::Accept | Case::Reject | Case::Cancel) {
        let rows = snapshot
            .get_mut("invitation")
            .ok_or_else(|| AuthError::internal("Missing Invitation snapshot"))?;
        assert_eq!(rows.len(), 1);
        let _ = rows[0].insert("status".into(), case.status().into());
    }
    if case == Case::Accept {
        let sql = matches!(storage, Storage::Sqlite(_));
        let member: FieldMap = [
            ("id".into(), "member-a".into()),
            (
                if sql {
                    "organization_id"
                } else {
                    "organizationId"
                }
                .into(),
                "organization".into(),
            ),
            (
                if sql { "user_id" } else { "userId" }.into(),
                "user-b".into(),
            ),
            ("role".into(), "member".into()),
            (
                if sql { "created_at" } else { "createdAt" }.into(),
                storage.stored_date(0),
            ),
        ]
        .into();
        snapshot
            .get_mut("member")
            .ok_or_else(|| AuthError::internal("Missing Member snapshot"))?
            .insert(0, member);
        let sessions = snapshot
            .get_mut("session")
            .ok_or_else(|| AuthError::internal("Missing Session snapshot"))?;
        assert_eq!(sessions.len(), 1);
        let _ = sessions[0].insert(
            if sql {
                "active_organization_id"
            } else {
                "activeOrganizationId"
            }
            .into(),
            "organization".into(),
        );
        let _ = sessions[0].insert(
            if sql { "updated_at" } else { "updatedAt" }.into(),
            storage.stored_date(0),
        );
    }
    Ok(())
}
