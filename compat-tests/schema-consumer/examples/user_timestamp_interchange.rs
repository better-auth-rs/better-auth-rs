use better_auth::{
    __private_core::store::UserStore,
    AuthConfig,
    prelude::CreateUser,
    seaorm::{Database, DatabaseConnection, SeaOrmStore, sea_orm::prelude::DateTimeUtc},
    wire::UserView,
};
use serde_json::{Map, Value, json};

mod generated {
    include!(env!("BETTER_AUTH_USER_ACCOUNT_CATALOG_DEFAULT_SCHEMA"));
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn timestamps(user: UserView) -> Result<Value> {
    let public = serde_json::to_value(user)?;
    let mut values = Map::new();
    for name in ["createdAt", "updatedAt"] {
        let value = public
            .get(name)
            .ok_or_else(|| format!("the User response requires {name}"))?;
        let _ = values.insert(name.into(), value.clone());
    }
    Ok(Value::Object(values))
}

async fn operate(database: &DatabaseConnection, ids: Option<&[String]>) -> Result<Value> {
    let _schema = generated::AppAuthSchema;
    let store = SeaOrmStore::<generated::AppAuthSchema>::new(
        AuthConfig::new("ordinary-user-timestamp-interchange-secret-at-least-32-characters")
            .base_url("http://user-timestamp-interchange.test"),
        database.clone(),
    );
    if let Some(ids) = ids {
        let mut observations = Vec::new();
        for id in ids {
            let user = store
                .get_user_by_id(id)
                .await?
                .ok_or("the generated store must find the created User row")?;
            observations.push(timestamps(user)?);
        }
        Ok(json!(observations))
    } else {
        generated::create_auth_tables(database).await?;
        let mut input = CreateUser::new()
            .with_name("Timestamp Rust")
            .with_email("rust@user-timestamp-interchange.test")
            .with_email_verified(false);
        input.id = Some("timestamp-rust".into());
        input.created_at = Some("2030-01-02T03:04:05.000Z".parse::<DateTimeUtc>()?.into());
        input.updated_at = Some("2030-01-02T03:04:06.123Z".parse::<DateTimeUtc>()?.into());
        let user = store.create_user(input).await?;
        Ok(json!({"id": user.id.typed()?}))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let (path, mode, ids) = match arguments.as_slice() {
        [command, path] if command == "init-write" => (path, "rwc", None),
        [command, path, ids] if command == "read" => {
            (path, "rw", Some(serde_json::from_str::<Vec<String>>(ids)?))
        }
        _ => return Err("expected init-write <database> or read <database> <ids-json>".into()),
    };
    let database = Database::connect(format!("sqlite://{path}?mode={mode}")).await?;
    let result = operate(&database, ids.as_deref()).await;
    let closed = database.close().await;
    let observation = match (result, closed) {
        (Ok(observation), Ok(())) => observation,
        (Err(error), Ok(())) => return Err(error),
        (Ok(_), Err(error)) => return Err(error.into()),
        (Err(operation), Err(close)) => {
            return Err(format!(
                "User timestamp operation failed: {operation}; database close failed: {close}"
            )
            .into());
        }
    };
    println!("{}", serde_json::to_string(&observation)?);
    Ok(())
}
