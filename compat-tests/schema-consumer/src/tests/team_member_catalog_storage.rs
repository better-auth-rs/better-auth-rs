use super::server_catalog_support::TestResult;
use better_auth::{
    AuthConfig, AuthSchema,
    prelude::{CreateOrganization, CreateTeam, CreateUser},
    seaorm::{
        __private_chrono as chrono, DatabaseConnection, SeaOrmAccountModel,
        SeaOrmOrganizationModel, SeaOrmOrganizationSchema, SeaOrmSessionModel, SeaOrmStore,
        SeaOrmUserModel, SeaOrmVerificationModel,
        sea_orm::{
            ConnectionTrait, DbBackend, DbErr, EntityName, Iden, SqlErr, Statement,
            Value as SqlValue,
        },
    },
    store::AuthStore,
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Input {
    seed_at: String,
    users: [String; 2],
    organization: String,
    teams: [String; 2],
}

fn quote(backend: DbBackend, name: &str) -> String {
    if backend == DbBackend::MySql {
        format!("`{}`", name.replace('`', "``"))
    } else {
        format!("\"{}\"", name.replace('"', "\"\""))
    }
}

fn parameter(backend: DbBackend, index: usize) -> String {
    if backend == DbBackend::Postgres {
        format!("${index}")
    } else {
        "?".into()
    }
}

fn column<M: SeaOrmOrganizationModel>(backend: DbBackend, field: &str) -> TestResult<String> {
    Ok(quote(backend, &M::column(field)?.to_string()))
}

async fn insert<M: SeaOrmOrganizationModel>(
    database: &DatabaseConnection,
    id: &str,
    team: &str,
    user: &str,
    key: Option<&str>,
    omit_date: bool,
) -> TestResult<Result<(), DbErr>> {
    let backend = database.get_database_backend();
    let table = quote(backend, M::Entity::default().table_name());
    let mut fields = vec!["id", "team_id", "user_id", "membership_key"];
    let mut values: Vec<SqlValue> = vec![id.into(), team.into(), user.into(), key.into()];
    if !omit_date {
        fields.push("created_at");
        values.push(Option::<chrono::DateTime<chrono::Utc>>::None.into());
    }
    let columns = fields
        .into_iter()
        .map(|field| column::<M>(backend, field))
        .collect::<TestResult<Vec<_>>>()?
        .join(", ");
    let parameters = (1..=values.len())
        .map(|index| parameter(backend, index))
        .collect::<Vec<_>>()
        .join(", ");
    Ok(database
        .execute_raw(Statement::from_sql_and_values(
            backend,
            format!("INSERT INTO {table} ({columns}) VALUES ({parameters})"),
            values,
        ))
        .await
        .map(|result| assert_eq!(result.rows_affected(), 1)))
}

async fn rows<M: SeaOrmOrganizationModel>(database: &DatabaseConnection) -> TestResult<Vec<Value>> {
    let backend = database.get_database_backend();
    let table = quote(backend, M::Entity::default().table_name());
    let columns = [
        ("id", "id"),
        ("team_id", "teamId"),
        ("user_id", "userId"),
        ("membership_key", "membershipKey"),
        ("created_at", "createdAt"),
    ]
    .into_iter()
    .map(|(field, alias)| {
        Ok(format!(
            "{} AS {}",
            column::<M>(backend, field)?,
            quote(backend, alias)
        ))
    })
    .collect::<TestResult<Vec<_>>>()?
    .join(", ");
    let id = column::<M>(backend, "id")?;
    let mut values = Vec::new();
    for row in database
        .query_all_raw(Statement::from_string(
            backend,
            format!("SELECT {columns} FROM {table} ORDER BY {id}"),
        ))
        .await?
    {
        let created_at = if backend == DbBackend::Sqlite {
            row.try_get::<Option<String>>("", "createdAt")?
        } else {
            row.try_get::<Option<chrono::DateTime<chrono::Utc>>>("", "createdAt")?
                .map(|date| date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        };
        assert!(
            created_at.is_none(),
            "Nullable TeamMember dates must remain SQL NULL"
        );
        values.push(json!({
            "id": row.try_get::<String>("", "id")?,
            "teamId": row.try_get::<String>("", "teamId")?,
            "userId": row.try_get::<String>("", "userId")?,
            "membershipKey": row.try_get::<Option<String>>("", "membershipKey")?,
            "createdAt": created_at,
        }));
    }
    Ok(values)
}

async fn delete(database: &DatabaseConnection, table: &str, id: &str) -> TestResult {
    let backend = database.get_database_backend();
    let table = quote(backend, table);
    let id_column = quote(backend, "id");
    let parameter = parameter(backend, 1);
    let result = database
        .execute_raw(Statement::from_sql_and_values(
            backend,
            format!("DELETE FROM {table} WHERE {id_column} = {parameter}"),
            [id.into()],
        ))
        .await?;
    assert_eq!(result.rows_affected(), 1);
    Ok(())
}

pub(super) async fn observe<S: AuthSchema, O: SeaOrmOrganizationSchema>(
    database: &DatabaseConnection,
    input: &Input,
) -> TestResult<Value>
where
    S::User: SeaOrmUserModel,
    S::Session: SeaOrmSessionModel,
    S::Account: SeaOrmAccountModel,
    S::Verification: SeaOrmVerificationModel,
{
    let backend = database.get_database_backend();
    assert_eq!(input.users, ["user-a", "user-b"]);
    assert_eq!(input.organization, "org");
    assert_eq!(input.teams, ["team-a", "team-b"]);
    assert_eq!(input.seed_at, "2030-01-02T03:04:05.123Z");
    let date = input.seed_at.parse::<chrono::DateTime<chrono::Utc>>()?;
    let store = SeaOrmStore::<S>::new(AuthConfig::default(), database.clone())
        .with_organization_schema::<O>();
    let store: &dyn AuthStore<S> = &store;
    for id in &input.users {
        let mut user = CreateUser::new()
            .with_name(id)
            .with_email(format!("{id}@team-member-catalog.test"))
            .with_email_verified(false);
        user.id = Some(id.clone().into());
        user.created_at = Some(date.into());
        user.updated_at = Some(date.into());
        assert_eq!(store.create_user(user).await?.id.typed()?, id);
    }
    let mut organization = CreateOrganization::new(&input.organization, &input.organization);
    organization.id = Some(input.organization.clone());
    assert_eq!(
        store.create_organization(organization).await?.id.typed()?,
        &input.organization
    );
    for id in &input.teams {
        let team = store
            .create_team(CreateTeam {
                id: Some(id.clone()),
                created_at: Some(date.into()),
                updated_at: Some(date.into()),
                name: id.clone().into(),
                organization_id: input.organization.clone().into(),
                ..Default::default()
            })
            .await?;
        assert_eq!(team.id.typed()?, id);
    }
    assert!(rows::<O::TeamMember>(database).await?.is_empty());
    let mut inserted = Vec::new();
    for (id, key, omit_date) in [("member-a", "key-a", true), ("member-b", "key-b", false)] {
        insert::<O::TeamMember>(database, id, "team-a", "user-a", Some(key), omit_date).await??;
        inserted.push(rows::<O::TeamMember>(database).await?);
    }
    let mut baseline = inserted
        .last()
        .ok_or("Missing TeamMember insertion")?
        .clone();
    assert_eq!(baseline.len(), 2);
    let mut rejected = Vec::new();
    let mut accepted = Vec::new();
    for (name, kind, id, team, user, key) in [
        (
            "duplicateKey",
            "unique",
            "member-key-duplicate",
            "team-b",
            "user-b",
            "key-a",
        ),
        (
            "duplicateId",
            "unique",
            "member-a",
            "team-b",
            "user-b",
            "key-c",
        ),
        (
            "missingTeam",
            "foreign-key",
            "member-invalid-team",
            "missing",
            "user-b",
            "key-c",
        ),
        (
            "missingUser",
            "foreign-key",
            "member-invalid-user",
            "team-b",
            "missing",
            "key-d",
        ),
    ] {
        let result = insert::<O::TeamMember>(database, id, team, user, Some(key), true).await?;
        if backend == DbBackend::MySql && kind == "foreign-key" {
            result?;
            baseline.push(json!({
                "id": id, "teamId": team, "userId": user,
                "membershipKey": key, "createdAt": null,
            }));
            baseline.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
            let retained = rows::<O::TeamMember>(database).await?;
            assert_eq!(retained, baseline, "{name}");
            accepted.push(json!({"name": name, "kind": kind, "rows": retained}));
            continue;
        }
        let error = result.expect_err("The database must enforce TeamMember constraints");
        let actual_kind = match error.sql_err() {
            Some(SqlErr::UniqueConstraintViolation(_)) => "unique",
            Some(SqlErr::ForeignKeyConstraintViolation(_)) => "foreign-key",
            _ => return Err(error.into()),
        };
        assert_eq!(actual_kind, kind, "{name}: {error}");
        let retained = rows::<O::TeamMember>(database).await?;
        assert_eq!(retained, baseline, "{name}");
        rejected.push(json!({"name": name, "kind": actual_kind, "rows": retained}));
    }
    for id in ["member-c", "member-d"] {
        insert::<O::TeamMember>(database, id, "team-b", "user-b", None, false).await??;
    }
    let after_null_keys = rows::<O::TeamMember>(database).await?;
    assert_eq!(
        after_null_keys.len(),
        if backend == DbBackend::MySql { 6 } else { 4 }
    );
    delete(
        database,
        <O::Team as SeaOrmOrganizationModel>::Entity::default().table_name(),
        "team-a",
    )
    .await?;
    let after_team_delete = rows::<O::TeamMember>(database).await?;
    if backend == DbBackend::MySql {
        assert_eq!(after_team_delete, after_null_keys);
    } else {
        assert_eq!(after_team_delete, after_null_keys[2..]);
    }
    delete(
        database,
        <S::User as SeaOrmUserModel>::Entity::default().table_name(),
        "user-b",
    )
    .await?;
    let after_user_delete = rows::<O::TeamMember>(database).await?;
    if backend == DbBackend::MySql {
        assert_eq!(after_user_delete, after_null_keys);
    } else {
        assert!(after_user_delete.is_empty());
    }
    let mut observation = json!({
        "inserted": inserted, "rejected": rejected, "afterNullKeys": after_null_keys,
        "afterTeamDelete": after_team_delete, "afterUserDelete": after_user_delete,
    });
    if backend == DbBackend::MySql {
        observation["accepted"] = json!(accepted);
    }
    Ok(observation)
}
