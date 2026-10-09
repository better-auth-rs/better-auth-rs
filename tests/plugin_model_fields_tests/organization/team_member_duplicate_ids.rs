use super::details::{member_events, member_fields, parent_fields};
use super::*;
use better_auth_seaorm::sea_orm::SqlErr;

#[tokio::test]
async fn sqlite_duplicate_parent_ids_retain_the_primary_key_constraint() -> AuthResult<()> {
    for joins in [false, true] {
        let (raw, storage) = sqlite_fixture().await?;
        let Storage::Sqlite(database) = &storage else {
            return Err(AuthError::internal("Expected SQLite storage"));
        };
        for (team_id, duplicate) in [("team-a", false), ("team-b", true)] {
            let result = database.execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "INSERT INTO team_member (id, team_id, user_id, membership_key, created_at) VALUES (?, ?, ?, ?, ?)",
                ["member-a".into(), team_id.into(), "user-a".into(), key(team_id, "user-a")?.into(), "2030-01-01T00:00:00.000Z".into()],
            )).await;
            if duplicate {
                let error = required(result.err(), "Expected the duplicate primary-key error")?;
                assert!(
                    matches!(error.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))),
                    "{error}"
                );
            } else {
                let _ = result.map_err(|error| AuthError::internal(error.to_string()))?;
            }
        }
        let events = Events::default();
        let auth = reader(
            raw,
            member_fields(&events, "id", false, false),
            Some(parent_fields(&events, false)),
            false,
            joins,
            "unused",
        )
        .await?;
        let rows = auth.store().list_user_teams("user-a").await?;
        assert_eq!(
            rows.iter()
                .map(AuthRecordFields::field_values)
                .collect::<AuthResult<Vec<_>>>()?,
            vec![team("team-a", "Team A", None)]
        );
        let mut expected_events = member_events(&storage, "team-a", "user-a")?;
        expected_events.push(event("team.name", "output", "Team A".into()));
        assert_eq!(events.take()?, expected_events);
        storage
            .assert_rows(
                vec![physical(
                    "member-a",
                    "team-a",
                    "user-a",
                    &key("team-a", "user-a")?,
                    0,
                )],
                [0, 0],
            )
            .await?;
    }
    Ok(())
}
