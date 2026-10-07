use super::*;

fn database_error(error: better_auth_seaorm::sea_orm::DbErr) -> AuthError {
    AuthError::internal(format!("Account/User fixture database failed: {error}"))
}

pub(super) async fn sqlite() -> AuthResult<DatabaseConnection> {
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(database_error)?;
    let schema = Schema::new(database.get_database_backend());
    for statement in [
        schema.create_table_from_entity(entities::user::Entity),
        schema.create_table_from_entity(entities::session::Entity),
        schema.create_table_from_entity(entities::account::Entity),
        schema.create_table_from_entity(entities::verification::Entity),
    ] {
        let _ = database.execute(&statement).await.map_err(database_error)?;
    }
    Ok(database)
}

pub(super) async fn seed<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    scenario: &Scenario,
) -> AuthResult<()> {
    let date: FieldDate = "2030-01-02T03:04:05Z"
        .parse::<chrono::DateTime<chrono::Utc>>()
        .map_err(|error| {
            AuthError::internal(format!("Invalid Account/User fixture date: {error}"))
        })?
        .into();
    for suffix in ["a", "b", "c"] {
        let image = if scenario.reverse {
            if scenario.missing_child || scenario.reverse_unique && suffix == "c" {
                None
            } else {
                Some(
                    if suffix == "a" {
                        "account-b"
                    } else {
                        "account-a"
                    }
                    .to_owned(),
                )
            }
        } else {
            Some(format!("image-{suffix}"))
        };
        let _ = store
            .create_user(CreateUser {
                id: Some(format!("user-{suffix}")),
                name: Some(format!("User {suffix}")).into(),
                email: Some(format!("{suffix}@account-user-selected-relations.test")),
                email_verified: Some(true),
                image: image.into(),
                created_at: Some(date.clone()),
                updated_at: Some(date.clone()),
                ..Default::default()
            })
            .await?;
    }
    for suffix in ["a", "b"] {
        let _ = store
            .create_account(CreateAccount {
                id: format!("account-{suffix}").into(),
                account_id: if suffix == "a" || scenario.duplicate_identity {
                    "external-owner"
                } else {
                    "external-decoy"
                }
                .into(),
                provider_id: "provider".into(),
                user_id: format!("user-{suffix}").into(),
                access_token: Some(if scenario.image_reference {
                    format!("image-{suffix}")
                } else {
                    if suffix == "a" { "user-b" } else { "user-a" }.to_owned()
                })
                .into(),
                refresh_token: None::<String>.into(),
                id_token: None::<String>.into(),
                access_token_expires_at: None::<FieldDate>.into(),
                refresh_token_expires_at: None::<FieldDate>.into(),
                scope: None::<String>.into(),
                password: None::<String>.into(),
                created_at: date.clone().into(),
                updated_at: date.clone().into(),
                ..Default::default()
            })
            .await?;
    }
    Ok(())
}

async fn memory_snapshot<S: AuthSchema>(store: &dyn AuthStore<S>) -> AuthResult<Value> {
    let (users, count) = store
        .list_users(ListUsersParams {
            limit: Some(100.0),
            sort_by: Some("id".into()),
            sort_direction: Some("asc".into()),
            ..Default::default()
        })
        .await?;
    assert_eq!(users.len(), count);
    let mut accounts = Vec::new();
    let mut sessions = Vec::new();
    for user in &users {
        accounts.extend(store.get_user_accounts(user.id.typed()?).await?);
        sessions.extend(store.get_user_sessions(user.id.typed()?).await?);
    }
    Ok(json!({
        "userCount": count,
        "user": users.iter().map(|user| values::observe(&FieldMap::from(user.clone()).into())).collect::<AuthResult<Vec<_>>>()?,
        "account": accounts.iter().map(|account| values::observe(&account.field_values()?.into())).collect::<AuthResult<Vec<_>>>()?,
        "session": sessions.iter().map(|session| values::observe(&FieldMap::from(session.clone()).into())).collect::<AuthResult<Vec<_>>>()?,
    }))
}

async fn sqlite_snapshot(database: &DatabaseConnection) -> AuthResult<Value> {
    Ok(json!({
        "user": entities::user::Entity::find().order_by_asc(entities::user::Column::Id).into_json().all(database).await.map_err(database_error)?,
        "session": entities::session::Entity::find().order_by_asc(entities::session::Column::Id).into_json().all(database).await.map_err(database_error)?,
        "account": entities::account::Entity::find().order_by_asc(entities::account::Column::Id).into_json().all(database).await.map_err(database_error)?,
        "verification": entities::verification::Entity::find().order_by_asc(entities::verification::Column::Id).into_json().all(database).await.map_err(database_error)?,
    }))
}

pub(super) async fn snapshot<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    database: Option<&DatabaseConnection>,
) -> AuthResult<Value> {
    match database {
        Some(database) => sqlite_snapshot(database).await,
        None => memory_snapshot(store).await,
    }
}
