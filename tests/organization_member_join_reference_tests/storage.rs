use super::*;

fn database_error(error: better_auth_seaorm::sea_orm::DbErr) -> AuthError {
    AuthError::internal(format!("Member join fixture database failed: {error}"))
}

pub(super) async fn sqlite() -> AuthResult<DatabaseConnection> {
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(database_error)?;
    let schema = Schema::new(database.get_database_backend());
    for statement in [
        schema.create_table_from_entity(models::user::Entity),
        schema.create_table_from_entity(entities::session::Entity),
        schema.create_table_from_entity(entities::account::Entity),
        schema.create_table_from_entity(entities::verification::Entity),
        schema.create_table_from_entity(entities::organization::Entity),
        schema.create_table_from_entity(models::member::Entity),
        schema.create_table_from_entity(entities::invitation::Entity),
    ] {
        let _ = database.execute(&statement).await.map_err(database_error)?;
    }
    Ok(database)
}

pub(super) async fn seed<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    scenario: &Scenario,
) -> AuthResult<()> {
    let date = "2030-01-02T03:04:05Z"
        .parse::<chrono::DateTime<chrono::Utc>>()
        .map_err(|error| AuthError::internal(format!("Invalid fixture date: {error}")))?;
    for suffix in ["a", "b", "c"] {
        let matches = !scenario.missing_child && (suffix == "b" || suffix == "c" && scenario.many);
        let mut additional_fields = FieldMap::from([(
            "memberRef".into(),
            if matches {
                "member-a".into()
            } else {
                FieldValue::Null
            },
        )]);
        if let Some(extra) = scenario.user_seeds.get(suffix) {
            let fields = extra
                .as_object()
                .ok_or_else(|| AuthError::internal("Expected User seed fields"))?;
            additional_fields.extend(
                fields
                    .iter()
                    .map(|(name, value)| Ok((name.clone(), values::revive(value)?)))
                    .collect::<AuthResult<FieldMap>>()?,
            );
        }
        let _ = store
            .create_user(CreateUser {
                id: Some(format!("user-{suffix}")),
                name: Some(format!("User {suffix}")).into(),
                email: Some(format!("{suffix}@member-join-reference.test")),
                email_verified: Some(true),
                image: Some(format!("image-{suffix}")).into(),
                created_at: Some(date.into()),
                updated_at: Some(date.into()),
                additional_fields,
                ..Default::default()
            })
            .await?;
    }
    let _ = store
        .insert_organization(Organization {
            id: "organization-a".into(),
            name: "Join organization".into(),
            slug: "join-organization".into(),
            logo: None::<String>.into(),
            metadata: None::<FieldValue>.into(),
            created_at: date.into(),
            additional_fields: FieldMap::new(),
        })
        .await?;
    let mut additional_fields = FieldMap::from([
        (
            "ownerRef".into(),
            if scenario.missing_child {
                "missing-user"
            } else {
                "user-b"
            }
            .into(),
        ),
        ("label".into(), "Member label".into()),
        ("detail".into(), "Member detail".into()),
    ]);
    additional_fields.extend(
        scenario
            .member_seed
            .iter()
            .map(|(name, value)| Ok((name.clone(), values::revive(value)?)))
            .collect::<AuthResult<FieldMap>>()?,
    );
    let _ = store
        .insert_member(Member {
            field_order: Default::default(),
            id: "member-a".into(),
            organization_id: "organization-a".into(),
            user_id: "user-a".into(),
            role: "member".into(),
            created_at: date.into(),
            additional_fields,
        })
        .await?;
    Ok(())
}

fn record(row: &impl AuthRecordFields) -> AuthResult<Value> {
    values::observe(&FieldValue::from(row.field_values()?))
}

async fn memory_snapshot<S: AuthSchema>(store: &dyn AuthStore<S>) -> AuthResult<Value> {
    let (users, count) = store
        .list_users(ListUsersParams {
            limit: Some(100.0),
            ..Default::default()
        })
        .await?;
    let users = users.iter().map(record).collect::<AuthResult<Vec<_>>>()?;
    assert_eq!(users.len(), count);
    let members = store.list_organization_members("organization-a").await?;
    let invitations = store
        .list_organization_invitations("organization-a")
        .await?;
    let organization = store.get_organization_by_id("organization-a").await?;
    Ok(json!({
        "userCount": count,
        "user": users,
        "member": members.iter().map(record).collect::<AuthResult<Vec<_>>>()?,
        "organization": organization.as_ref().map(record).transpose()?,
        "invitation": invitations.iter().map(record).collect::<AuthResult<Vec<_>>>()?,
    }))
}

async fn sqlite_snapshot(database: &DatabaseConnection) -> AuthResult<Value> {
    Ok(json!({
        "user": models::user::Entity::find().order_by_asc(models::user::Column::Id).into_json().all(database).await.map_err(database_error)?,
        "session": entities::session::Entity::find().order_by_asc(entities::session::Column::Id).into_json().all(database).await.map_err(database_error)?,
        "account": entities::account::Entity::find().order_by_asc(entities::account::Column::Id).into_json().all(database).await.map_err(database_error)?,
        "verification": entities::verification::Entity::find().order_by_asc(entities::verification::Column::Id).into_json().all(database).await.map_err(database_error)?,
        "organization": entities::organization::Entity::find().order_by_asc(entities::organization::Column::Id).into_json().all(database).await.map_err(database_error)?,
        "member": models::member::Entity::find().order_by_asc(models::member::Column::Id).into_json().all(database).await.map_err(database_error)?,
        "invitation": entities::invitation::Entity::find().order_by_asc(entities::invitation::Column::Id).into_json().all(database).await.map_err(database_error)?,
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
