use super::{
    organization_server_schema::{
        mysql as invitation_mysql_default, mysql as team_mysql_default,
        postgres as invitation_postgres_default, postgres as team_postgres_default,
    },
    server_catalog::{self, TestResult},
};
use axum::{Router, body::Body, http::Request};
use better_auth::{
    AuthConfig, AuthSchema, BetterAuth,
    integrations::axum::AxumIntegration,
    plugins::organization::{OrganizationConfig, OrganizationPlugin, OrganizationTeamsConfig},
    prelude::{AuthUser, CreateUser},
    seaorm::{
        __private_chrono as chrono, DatabaseConnection, SeaOrmAccountModel,
        SeaOrmOrganizationModel, SeaOrmOrganizationSchema, SeaOrmSessionModel, SeaOrmStore,
        SeaOrmUserModel, SeaOrmVerificationModel,
        sea_orm::{ConnectionTrait, DbBackend, EntityName, Iden, Statement},
    },
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

const ORIGIN: &str = "http://catalog.example.test";
const SECRET: &str = "ordinary-server-catalog-secret-at-least-32-characters";

mod team_postgres_custom {
    include!(env!("BETTER_AUTH_TEAM_SERVER_POSTGRES_CUSTOM_SCHEMA"));
}
mod team_mysql_custom {
    include!(env!("BETTER_AUTH_TEAM_SERVER_MYSQL_CUSTOM_SCHEMA"));
}
mod invitation_postgres_custom {
    include!(env!("BETTER_AUTH_INVITATION_SERVER_POSTGRES_CUSTOM_SCHEMA"));
}
mod invitation_mysql_custom {
    include!(env!("BETTER_AUTH_INVITATION_SERVER_MYSQL_CUSTOM_SCHEMA"));
}

fn cases(backend: &str) -> TestResult<Vec<Value>> {
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(format!(
        "{}/../../tests/fixtures/team-invitation-{backend}-server-1.7.6.json",
        env!("CARGO_MANIFEST_DIR"),
    ))?)?;
    assert_eq!(fixture.get("version"), Some(&json!("1.7.6")));
    assert_eq!(fixture.get("database"), Some(&json!(backend)));
    assert_eq!(
        fixture.get("teams"),
        Some(&json!({"enabled":true,"defaultTeam":{"enabled":false}}))
    );
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("Missing Team/Invitation cases")?;
    assert_eq!(
        cases
            .iter()
            .map(|case| (
                case.get("model").and_then(Value::as_str),
                case.get("name").and_then(Value::as_str)
            ))
            .collect::<Vec<_>>(),
        vec![
            (Some("team"), Some("default")),
            (Some("team"), Some("custom")),
            (Some("invitation"), Some("default")),
            (Some("invitation"), Some("custom"))
        ]
    );
    for case in cases {
        let model = case
            .get("model")
            .and_then(Value::as_str)
            .ok_or("Missing model")?;
        let source = match model {
            "team" => include_str!("../../team-catalog-config.json"),
            "invitation" => include_str!("../../invitation-catalog-config.json"),
            _ => return Err("Unsupported catalog model".into()),
        };
        let source: Value = serde_json::from_str(source)?;
        let name = case
            .get("name")
            .and_then(Value::as_str)
            .ok_or("Missing case name")?;
        let source = source.get(name).ok_or("Missing catalog configuration")?;
        let configuration = Value::Object(
            ["user", "organization", model]
                .into_iter()
                .filter_map(|key| source.get(key).map(|value| (key.to_owned(), value.clone())))
                .collect(),
        );
        assert_eq!(case.get("configuration"), Some(&configuration));
    }
    Ok(cases.clone())
}

async fn call(router: &Router, cookie: &str, path: &str, body: Option<Value>) -> TestResult<Value> {
    let mut request = Request::builder()
        .uri(format!("/api/auth/organization/{path}"))
        .header("cookie", cookie)
        .header("origin", ORIGIN)
        .header("accept", "application/json");
    let body = if let Some(body) = body {
        request = request
            .method("POST")
            .header("content-type", "application/json");
        Body::from(serde_json::to_vec(&body)?)
    } else {
        Body::empty()
    };
    let response = router.clone().oneshot(request.body(body)?).await?;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
    let value: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(status, axum::http::StatusCode::OK, "{path}: {value}");
    Ok(value)
}

async fn read_team(
    router: &Router,
    cookie: &str,
    organization: &str,
    id: &str,
) -> TestResult<Value> {
    let rows = call(
        router,
        cookie,
        &format!("list-teams?organizationId={organization}"),
        None,
    )
    .await?;
    let rows = rows.as_array().ok_or("Expected public Team list")?;
    assert_eq!(rows.len(), 1);
    let team = rows.first().ok_or("Missing public Team")?;
    assert_eq!(team.get("id"), Some(&json!(id)));
    Ok(team.clone())
}

fn quote(backend: DbBackend, name: &str) -> String {
    match backend {
        DbBackend::Postgres => format!("\"{}\"", name.replace('"', "\"\"")),
        _ => format!("`{}`", name.replace('`', "``")),
    }
}

async fn stored_count<M: SeaOrmOrganizationModel>(
    database: &DatabaseConnection,
    id: &str,
) -> TestResult<i32> {
    let backend = database.get_database_backend();
    let table = quote(backend, M::Entity::default().table_name());
    let column = quote(backend, &M::column("member_count")?.to_string());
    let parameter = if backend == DbBackend::Postgres {
        "$1"
    } else {
        "?"
    };
    let rows = database
        .query_all_raw(Statement::from_sql_and_values(
            backend,
            format!("SELECT {column} AS count FROM {table} WHERE id = {parameter}"),
            [id.into()],
        ))
        .await?;
    assert_eq!(rows.len(), 1);
    Ok(rows
        .first()
        .ok_or("Missing stored Team")?
        .try_get("", "count")?)
}

fn timestamp(value: &Value) -> TestResult<i64> {
    Ok(
        chrono::DateTime::parse_from_rfc3339(value.as_str().ok_or("Missing timestamp")?)?
            .timestamp_millis(),
    )
}

struct TeamIdentity<'a> {
    id: &'a str,
    organization: &'a str,
    created_at: &'a Value,
    updated_at: i64,
    added_finished: i64,
}

fn visible(mut team: Value, identity: &TeamIdentity<'_>) -> TestResult<Value> {
    assert_eq!(team.get("id"), Some(&json!(identity.id)));
    assert_eq!(
        team.get("organizationId"),
        Some(&json!(identity.organization))
    );
    assert_eq!(team.get("createdAt"), Some(identity.created_at));
    let updated_at = timestamp(team.get("updatedAt").ok_or("Missing updatedAt")?)?;
    assert!(identity.updated_at <= updated_at && updated_at <= identity.added_finished);
    team["id"] = json!("<team-id>");
    team["organizationId"] = json!("<organization-id>");
    team["createdAt"] = json!("<created-at>");
    team["updatedAt"] = json!("<updated-at>");
    Ok(team)
}

async fn observe_team<S, O>(database: &DatabaseConnection) -> TestResult<Value>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
    S::Session: SeaOrmSessionModel,
    S::Account: SeaOrmAccountModel,
    S::Verification: SeaOrmVerificationModel,
    O: SeaOrmOrganizationSchema,
{
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    let store =
        SeaOrmStore::<S>::new(config.clone(), database.clone()).with_organization_schema::<O>();
    let auth = Arc::new(
        BetterAuth::<S>::new(config)
            .store(store)
            .plugin(OrganizationPlugin::with_config(OrganizationConfig {
                teams: OrganizationTeamsConfig {
                    enabled: true,
                    default_team: false,
                    ..Default::default()
                },
                ..Default::default()
            }))
            .build()
            .await?,
    );
    let owner = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_name("Team catalog owner")
                .with_email("owner@team-catalog.test"),
        )
        .await?;
    let owner_id = owner.id().display_string()?;
    let login = auth
        .context()
        .session_manager()
        .create_session(&owner, None, None)
        .await?;
    let cookie = format!(
        "better-auth.session_token={}",
        better_auth::__private_core::utils::cookie_utils::sign_cookie_value(
            &login.token,
            auth.config().signing_secret()
        )
    );
    let router = Router::new()
        .nest("/api/auth", auth.clone().axum_router())
        .with_state(auth.clone());
    let parent = call(
        &router,
        &cookie,
        "create",
        Some(json!({"name":"Team catalog", "slug":"team-catalog"})),
    )
    .await?;
    let organization = parent
        .get("id")
        .and_then(Value::as_str)
        .ok_or("Missing organization ID")?;
    let membership = auth
        .store()
        .get_member(organization, &owner_id)
        .await?
        .ok_or("Missing owner member")?;
    assert_eq!(membership.role.typed()?, "owner");
    let started = chrono::Utc::now().timestamp_millis();
    let created = call(
        &router,
        &cookie,
        "create-team",
        Some(json!({"organizationId":organization,"name":"Catalog team"})),
    )
    .await?;
    let created_finished = chrono::Utc::now().timestamp_millis();
    let id = created
        .get("id")
        .and_then(Value::as_str)
        .ok_or("Missing Team ID")?;
    assert!(!id.is_empty());
    for name in ["createdAt", "updatedAt"] {
        let time = timestamp(created.get(name).ok_or("Missing Team timestamp")?)?;
        assert!(started <= time && time <= created_finished);
    }
    let read = read_team(&router, &cookie, organization, id).await?;
    assert_eq!(read.get("updatedAt"), created.get("updatedAt"));
    let before = stored_count::<O::Team>(database, id).await?;
    assert_eq!(before, 0);
    let added_started = chrono::Utc::now().timestamp_millis();
    let mut member = call(
        &router,
        &cookie,
        "add-team-member",
        Some(json!({
            "organizationId":organization,"teamId":id,"userId":owner_id,
        })),
    )
    .await?;
    let added_finished = chrono::Utc::now().timestamp_millis();
    assert_eq!(member.get("teamId"), Some(&json!(id)));
    assert_eq!(member.get("userId"), Some(&json!(owner_id)));
    assert!(
        !member
            .get("id")
            .and_then(Value::as_str)
            .ok_or("Missing member ID")?
            .is_empty()
    );
    let time = timestamp(member.get("createdAt").ok_or("Missing member createdAt")?)?;
    assert!(added_started <= time && time <= added_finished);
    let reread = read_team(&router, &cookie, organization, id).await?;
    let after = stored_count::<O::Team>(database, id).await?;
    assert_eq!(after, 1);
    let identity = TeamIdentity {
        id,
        organization,
        created_at: created.get("createdAt").ok_or("Missing createdAt")?,
        updated_at: timestamp(created.get("updatedAt").ok_or("Missing updatedAt")?)?,
        added_finished,
    };
    member["id"] = json!("<member-id>");
    member["teamId"] = json!("<team-id>");
    member["userId"] = json!("<owner-id>");
    member["createdAt"] = json!("<member-created-at>");
    Ok(
        json!({"created":visible(created.clone(), &identity)?, "read":visible(read, &identity)?,
        "reread":visible(reread, &identity)?, "member":member, "before":before, "after":after}),
    )
}

async fn check(database: &DatabaseConnection, backend: DbBackend, case: &Value) -> TestResult {
    let model = case
        .get("model")
        .and_then(Value::as_str)
        .ok_or("Missing model")?;
    let name = case
        .get("name")
        .and_then(Value::as_str)
        .ok_or("Missing case name")?;
    macro_rules! team {
        ($module:ident) => {{
            $module::create_auth_tables(database).await?;
            let columns = server_catalog::observe(
                database,
                backend,
                [$module::team::Entity.table_name().to_owned()],
            )
            .await?;
            let observed =
                observe_team::<$module::AppAuthSchema, $module::AppOrganizationSchema>(database)
                    .await?;
            assert_eq!(
                Some(&observed),
                case.get("observation"),
                "{backend:?}/{model}/{name} rows"
            );
            columns
        }};
    }
    macro_rules! invitation {
        ($module:ident) => {{
            let _schema = $module::AppAuthSchema;
            let _organization = std::marker::PhantomData::<$module::AppOrganizationSchema>;
            $module::create_auth_tables(database).await?;
            assert!(case.get("observation").is_none());
            server_catalog::observe(
                database,
                backend,
                [$module::invitation::Entity.table_name().to_owned()],
            )
            .await?
        }};
    }
    let columns = match (backend, model, name) {
        (DbBackend::Postgres, "team", "default") => team!(team_postgres_default),
        (DbBackend::Postgres, "team", "custom") => team!(team_postgres_custom),
        (DbBackend::MySql, "team", "default") => team!(team_mysql_default),
        (DbBackend::MySql, "team", "custom") => team!(team_mysql_custom),
        (DbBackend::Postgres, "invitation", "default") => invitation!(invitation_postgres_default),
        (DbBackend::Postgres, "invitation", "custom") => invitation!(invitation_postgres_custom),
        (DbBackend::MySql, "invitation", "default") => invitation!(invitation_mysql_default),
        (DbBackend::MySql, "invitation", "custom") => invitation!(invitation_mysql_custom),
        _ => return Err(format!("Unsupported catalog {backend:?}/{model}/{name}").into()),
    };
    assert_eq!(
        &columns,
        case.get("columns").ok_or("Missing upstream columns")?,
        "{backend:?}/{model}/{name} columns"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and the CI upstream fixture"]
async fn live_postgres_team_invitation_storage_matches_upstream() -> TestResult {
    for case in cases("postgres")? {
        server_catalog::in_postgres_catalog(|database| async move {
            check(&database, DbBackend::Postgres, &case).await
        })
        .await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL and the CI upstream fixture"]
async fn live_mysql_team_invitation_storage_matches_upstream() -> TestResult {
    for case in cases("mysql")? {
        server_catalog::in_mysql_catalog(|database| async move {
            check(&database, DbBackend::MySql, &case).await
        })
        .await?;
    }
    Ok(())
}
