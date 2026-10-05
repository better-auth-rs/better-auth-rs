use super::{
    organization_server_schema::{mysql as mysql_default, postgres as postgres_default},
    server_catalog::{self, TestResult},
};
use axum::{Router, body::Body, http::Request};
use better_auth::{
    AuthConfig, AuthSchema, BetterAuth,
    integrations::axum::AxumIntegration,
    plugins::organization::{OrganizationConfig, OrganizationPlugin},
    prelude::{AuthUser, CreateUser},
    seaorm::{
        __private_chrono as chrono, DatabaseConnection, SeaOrmAccountModel,
        SeaOrmOrganizationModel, SeaOrmOrganizationSchema, SeaOrmSessionModel, SeaOrmStore,
        SeaOrmUserModel, SeaOrmVerificationModel,
        sea_orm::{ConnectionTrait, DbBackend, EntityName, Iden, Statement},
    },
};
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};
use tower::ServiceExt;

const ORIGIN: &str = "http://catalog.example.test";
const SECRET: &str = "ordinary-server-catalog-secret-at-least-32-characters";

mod postgres_custom {
    include!(env!(
        "BETTER_AUTH_ORGANIZATION_ROLE_SERVER_POSTGRES_CUSTOM_SCHEMA"
    ));
}
mod mysql_custom {
    include!(env!(
        "BETTER_AUTH_ORGANIZATION_ROLE_SERVER_MYSQL_CUSTOM_SCHEMA"
    ));
}

fn cases(backend: &str) -> TestResult<Vec<Value>> {
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(format!(
        "{}/../../tests/fixtures/organization-role-{backend}-server-1.7.6.json",
        env!("CARGO_MANIFEST_DIR"),
    ))?)?;
    assert_eq!(fixture.get("version"), Some(&json!("1.7.6")));
    assert_eq!(fixture.get("database"), Some(&json!(backend)));
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("Missing OrganizationRole cases")?;
    assert_eq!(
        cases
            .iter()
            .map(|case| case.get("name").and_then(Value::as_str))
            .collect::<Vec<_>>(),
        vec![Some("default"), Some("custom")]
    );
    let configurations: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/member-organization-role-catalog-config.json"
    )))?;
    for case in cases {
        let name = case
            .get("name")
            .and_then(Value::as_str)
            .ok_or("Missing case name")?;
        let source = configurations
            .get(name)
            .ok_or("Missing catalog configuration")?;
        let configuration = Value::Object(
            ["user", "organization", "member", "organizationRole"]
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

fn quote(backend: DbBackend, name: &str) -> String {
    match backend {
        DbBackend::Postgres => format!("\"{}\"", name.replace('"', "\"\"")),
        _ => format!("`{}`", name.replace('`', "``")),
    }
}

async fn stored<M: SeaOrmOrganizationModel>(
    database: &DatabaseConnection,
    id: &str,
) -> TestResult<String> {
    let backend = database.get_database_backend();
    let table = quote(backend, M::Entity::default().table_name());
    let permission = quote(backend, &M::column("permission")?.to_string());
    let parameter = if backend == DbBackend::Postgres {
        "$1"
    } else {
        "?"
    };
    let rows = database
        .query_all_raw(Statement::from_sql_and_values(
            backend,
            format!("SELECT {permission} AS permission FROM {table} WHERE id = {parameter}"),
            [id.into()],
        ))
        .await?;
    assert_eq!(rows.len(), 1);
    Ok(rows[0].try_get("", "permission")?)
}

struct RoleIdentity {
    id: String,
    organization_id: String,
    created_at: String,
    update_started: i64,
    update_finished: i64,
}

fn timestamp(value: &Value) -> TestResult<i64> {
    Ok(
        chrono::DateTime::parse_from_rfc3339(value.as_str().ok_or("Missing role timestamp")?)?
            .timestamp_millis(),
    )
}

fn visible(mut role: Value, identity: &RoleIdentity) -> TestResult<Value> {
    assert_eq!(role.get("id"), Some(&json!(identity.id)));
    assert_eq!(
        role.get("organizationId"),
        Some(&json!(identity.organization_id))
    );
    assert_eq!(role.get("createdAt"), Some(&json!(identity.created_at)));
    role["id"] = json!("<role-id>");
    role["organizationId"] = json!("<organization-id>");
    role["createdAt"] = json!("<created-at>");
    if let Some(value) = role.get("updatedAt").filter(|value| !value.is_null()) {
        let value = timestamp(value)?;
        assert!(identity.update_started <= value && value <= identity.update_finished);
        role["updatedAt"] = json!("<updated-at>");
    }
    Ok(role)
}

async fn observe<S, O>(database: &DatabaseConnection) -> TestResult<Value>
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
                dynamic_access_control: true,
                ac: Some(HashMap::from([
                    (
                        "organization".into(),
                        vec!["update".into(), "delete".into()],
                    ),
                    (
                        "member".into(),
                        vec!["create".into(), "update".into(), "delete".into()],
                    ),
                ])),
                ..Default::default()
            }))
            .build()
            .await?,
    );
    let owner = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_name("Role catalog owner")
                .with_email("owner@role-catalog.test"),
        )
        .await?;
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
        Some(json!({"name":"Role catalog", "slug":"role-catalog"})),
    )
    .await?;
    let organization_id = parent
        .get("id")
        .and_then(Value::as_str)
        .ok_or("Missing organization ID")?;
    let owner_id = owner.id().display_string()?;
    let member = auth
        .store()
        .get_member(organization_id, &owner_id)
        .await?
        .ok_or("Missing owner member")?;
    assert_eq!(member.role.typed()?, "owner");
    let created_permission = json!({"organization":["update"], "member":["create"]});
    let updated_permission =
        json!({"member":["update","delete"], "organization":["delete","update"]});
    let started = chrono::Utc::now().timestamp_millis();
    let created = call(&router, &cookie, "create-role", Some(json!({
        "organizationId":organization_id, "role":"catalog-editor", "permission":created_permission,
    }))).await?;
    let created_finished = chrono::Utc::now().timestamp_millis();
    assert_eq!(created.get("success"), Some(&json!(true)));
    assert_eq!(created.get("statements"), Some(&created_permission));
    let role = created.get("roleData").ok_or("Missing created role")?;
    let id = role
        .get("id")
        .and_then(Value::as_str)
        .ok_or("Missing role ID")?;
    assert!(!id.is_empty());
    let created_at = role.get("createdAt").ok_or("Missing createdAt")?;
    assert!(started <= timestamp(created_at)? && timestamp(created_at)? <= created_finished);
    let stored_created = stored::<O::OrganizationRole>(database, id).await?;
    assert_eq!(
        serde_json::from_str::<Value>(&stored_created)?,
        created_permission
    );
    let path = format!("get-role?organizationId={organization_id}&roleId={id}");
    let read = call(&router, &cookie, &path, None).await?;
    let update_started = chrono::Utc::now().timestamp_millis();
    let updated = call(
        &router,
        &cookie,
        "update-role",
        Some(json!({
            "organizationId":organization_id, "roleId":id,
            "data":{"roleName":"catalog-maintainer", "permission":updated_permission},
        })),
    )
    .await?;
    let update_finished = chrono::Utc::now().timestamp_millis();
    assert_eq!(updated.get("success"), Some(&json!(true)));
    let stored_updated = stored::<O::OrganizationRole>(database, id).await?;
    assert_eq!(
        serde_json::from_str::<Value>(&stored_updated)?,
        updated_permission
    );
    let reread = call(&router, &cookie, &path, None).await?;
    let identity = RoleIdentity {
        id: id.to_owned(),
        organization_id: organization_id.to_owned(),
        created_at: created_at.as_str().ok_or("Invalid createdAt")?.to_owned(),
        update_started,
        update_finished,
    };
    Ok(json!({
        "created":visible(role.clone(), &identity)?, "read":visible(read, &identity)?,
        "updated":visible(updated.get("roleData").ok_or("Missing updated role")?.clone(), &identity)?,
        "reread":visible(reread, &identity)?, "storedCreated":stored_created, "storedUpdated":stored_updated,
    }))
}

async fn check(database: &DatabaseConnection, backend: DbBackend, case: &Value) -> TestResult {
    let name = case
        .get("name")
        .and_then(Value::as_str)
        .ok_or("Missing case name")?;
    macro_rules! generated {
        ($module:ident) => {{
            $module::create_auth_tables(database).await?;
            let columns = server_catalog::observe(
                database,
                backend,
                [$module::organization_role::Entity.table_name().to_owned()],
            )
            .await?;
            let rows =
                observe::<$module::AppAuthSchema, $module::AppOrganizationSchema>(database).await?;
            (columns, rows)
        }};
    }
    let (columns, observation) = match (backend, name) {
        (DbBackend::Postgres, "default") => generated!(postgres_default),
        (DbBackend::Postgres, "custom") => generated!(postgres_custom),
        (DbBackend::MySql, "default") => generated!(mysql_default),
        (DbBackend::MySql, "custom") => generated!(mysql_custom),
        _ => return Err(format!("Unsupported OrganizationRole catalog {backend:?}/{name}").into()),
    };
    assert_eq!(
        &columns,
        case.get("columns").ok_or("Missing upstream columns")?,
        "{backend:?}/{name} columns"
    );
    assert_eq!(
        &observation,
        case.get("observation")
            .ok_or("Missing upstream role observation")?,
        "{backend:?}/{name} role storage"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and the CI upstream fixture"]
async fn live_postgres_organization_role_storage_matches_upstream() -> TestResult {
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
async fn live_mysql_organization_role_storage_matches_upstream() -> TestResult {
    for case in cases("mysql")? {
        server_catalog::in_mysql_catalog(|database| async move {
            check(&database, DbBackend::MySql, &case).await
        })
        .await?;
    }
    Ok(())
}
