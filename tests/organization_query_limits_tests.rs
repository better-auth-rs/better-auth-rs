#![cfg(feature = "seaorm2")]

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use better_auth::plugins::organization::{OrganizationConfig, OrganizationPlugin};
use better_auth::server_api::EndpointInput;
use better_auth::{AuthConfig, AuthError, AuthResult, AuthSchema, BetterAuth};
use better_auth_core::store::{
    EphemeralStore, InvitationStore, MemberStore, MemoryCacheAdapter, OrganizationStore,
    secondary::SecondaryStore,
};
use better_auth_core::{
    AuthStore, AuthUser, CreateMember, CreateOrganization, CreateSession, CreateUser, FieldValue,
    HttpMethod, Utf16String,
    id::IdGeneration,
    organization_fields::OrganizationFields,
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
};
use better_auth_seaorm::store::__private_test_support::{bundled_schema::BundledSchema, migrator};
use better_auth_seaorm::{SeaOrmStore, sea_orm::Database};
use chrono::{Duration, Utc};
use serde_json::{Value, json};

async fn check<S: AuthSchema>(
    auth: BetterAuth<S>,
    membership_limit: Option<usize>,
    database_limit: Option<f64>,
) -> AuthResult<()> {
    let store = auth.store();
    let mut users = Vec::new();
    for name in ["Second", "First"] {
        users.push(
            store
                .create_user(
                    CreateUser::new()
                        .with_name(name)
                        .with_email(format!("{name}@example.test")),
                )
                .await?,
        );
    }
    let organization = store
        .create_organization(CreateOrganization::new("Organization", "organization"))
        .await?;
    for user in users.iter().rev() {
        let _ = store
            .create_member(CreateMember::new(
                organization.id.typed()?,
                user.id.typed()?,
                "owner",
            ))
            .await?;
    }
    let first = users
        .last()
        .ok_or_else(|| AuthError::internal("fixture requires two users"))?;
    let session = store
        .create_session(CreateSession {
            inherited_fields: Default::default(),
            additional_fields: Default::default(),
            user_id: first.id().into_owned(),
            expires_at: (Utc::now() + Duration::hours(1)).into(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?;
    let cookie = format!(
        "better-auth.session_token={}",
        better_auth_core::utils::cookie_utils::sign_cookie_value(
            session.token.typed()?,
            &auth.config().secret
        )
    );
    let headers = HashMap::from([("cookie".to_owned(), cookie)]);
    let call = |path, query| {
        auth.call_endpoint(
            HttpMethod::Get,
            path,
            EndpointInput {
                headers: Some(headers.clone()),
                query: Some(query),
                ..Default::default()
            },
        )
    };
    let response = call(
        "/organization/list-members",
        json!({"organizationId":organization.id,"limit":2}),
    )
    .await?;
    let body: Value = serde_json::from_slice(&response.body.bytes()?)?;
    assert_eq!(body["total"], 2);
    assert_eq!(body["members"].as_array().map(Vec::len), Some(2));
    let response = call(
        "/organization/list-members",
        json!({"organizationId":organization.id,"limit":0}),
    )
    .await?;
    let body: Value = serde_json::from_slice(&response.body.bytes()?)?;
    assert_eq!(body["total"], 2);
    assert_eq!(
        body["members"].as_array().map(Vec::len),
        Some(membership_limit.unwrap_or(2))
    );

    let full = call(
        "/organization/get-full-organization",
        json!({"organizationId":organization.id}),
    )
    .await;
    if database_limit == Some(0.0) {
        let body: Value = serde_json::from_slice(&full?.body.bytes()?)?;
        assert_eq!(body["members"], json!([]));
    } else if membership_limit == Some(1) {
        let Err(error) = full else {
            return Err(AuthError::internal(
                "full organization accepted a missing member user",
            ));
        };
        assert_eq!(
            error.instrumentation_message(),
            "Unexpected error: User not found for member"
        );
    } else {
        let body: Value = serde_json::from_slice(&full?.body.bytes()?)?;
        assert_eq!(body["members"].as_array().map(Vec::len), Some(2));
    }
    Ok(())
}

#[tokio::test]
async fn organization_user_pages_and_missing_users_match_upstream() -> AuthResult<()> {
    for sqlite in [false, true] {
        for (membership_limit, database_limit) in [(None, None), (Some(1), None), (None, Some(0.0))]
        {
            let mut config =
                AuthConfig::new("organization-query-limits-secret-at-least-32-characters")
                    .base_url("http://organization.test");
            config.logger.disabled = Some(true);
            config.advanced.database.default_find_many_limit = database_limit;
            let plugin = OrganizationPlugin::with_config(OrganizationConfig {
                membership_limit,
                ..Default::default()
            });
            if sqlite {
                let database = Database::connect("sqlite::memory:")
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                migrator::run_migrations(&database)
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                let auth = BetterAuth::<BundledSchema>::new(config.clone())
                    .store(SeaOrmStore::<BundledSchema>::new(config, database))
                    .plugin(plugin)
                    .build()
                    .await?;
                check(auth, membership_limit, database_limit).await?;
            } else {
                let auth = BetterAuth::new(config)
                    .store(EphemeralStore::default())
                    .plugin(plugin)
                    .build()
                    .await?;
                check(auth, membership_limit, database_limit).await?;
            }
        }
    }
    Ok(())
}

type Events = Arc<Mutex<Vec<String>>>;

fn take(events: &Events) -> AuthResult<Vec<String>> {
    Ok(std::mem::take(
        &mut *events
            .lock()
            .map_err(|error| AuthError::internal(error.to_string()))?,
    ))
}

fn output_field(events: &Events, kind: &'static str) -> UserFieldConfig {
    let events = events.clone();
    UserFieldConfig {
        transform: Some(FieldTransforms {
            output: Some(UserFieldTransform::new(move |value| {
                events
                    .lock()
                    .map_err(|error| AuthError::internal(error.to_string()))?
                    .push(format!("{kind}:{}", value.as_str().unwrap_or("undefined")));
                Ok(value)
            })),
            ..Default::default()
        }),
        ..Default::default()
    }
}

async fn check_native_organization_lists<S: AuthSchema>(
    inner: Arc<dyn AuthStore<S>>,
    config: AuthConfig,
    sqlite: bool,
    serial: bool,
    secondary: bool,
) -> AuthResult<()> {
    for id in ["0", "1"] {
        let _ = inner
            .create_user(CreateUser {
                id: Some(id.into()),
                email: Some(format!("{id}@native-organization.test")),
                name: Some(format!("User {id}")).into(),
                ..Default::default()
            })
            .await?;
    }
    for name in ["first", "second"] {
        let organization = inner
            .create_organization(CreateOrganization::new(name, name))
            .await?;
        for id in ["0", "1"] {
            let _ = inner
                .create_member(CreateMember::new(organization.id.typed()?, id, "owner"))
                .await?;
        }
    }
    let events = Events::default();
    let mut fields = OrganizationFields::default();
    let _ = fields
        .member
        .fields_mut()
        .insert("role".into(), output_field(&events, "member"));
    let _ = fields
        .organization
        .fields_mut()
        .insert("name".into(), output_field(&events, "organization"));
    inner.configure_organization_fields(fields)?;
    let config = Arc::new(config);
    let inner = inner.with_runtime(config.clone(), vec![], Default::default())?;
    let store: Arc<dyn AuthStore<S>> = if secondary {
        Arc::new(SecondaryStore::new(
            inner,
            Arc::new(MemoryCacheAdapter::new()),
            config,
            Default::default(),
        )?)
    } else {
        inner
    };
    for (selector, matches) in [
        (FieldValue::from("1"), true),
        (
            FieldValue::Utf16String(Utf16String::from_units(vec![49])),
            true,
        ),
        (FieldValue::Number(1.0), sqlite || serial),
        (FieldValue::Bool(true), sqlite || serial),
        (FieldValue::Bool(false), sqlite || serial),
        (FieldValue::Null, serial),
        (FieldValue::Undefined, false),
    ] {
        let rows = store.list_user_organizations_value(&selector).await?;
        assert_eq!(rows.len(), usize::from(matches), "selector: {selector:?}");
        let observed = take(&events)?;
        if let Some(row) = rows.first() {
            assert_eq!(
                observed,
                [
                    "member:owner".to_owned(),
                    format!("organization:{}", row.name.typed()?)
                ]
            );
        } else {
            assert!(observed.is_empty());
        }
    }
    Ok(())
}

#[tokio::test]
async fn native_organization_owners_keep_join_limits_and_output_order() -> AuthResult<()> {
    for secondary in [false, true] {
        for joins in [false, true] {
            for serial in [false, true] {
                let mut config = AuthConfig::default();
                config.advanced.database.default_find_many_limit = Some(1.0);
                config.advanced.database.joins = Some(joins);
                if serial {
                    config.advanced.database.generate_id = Some(IdGeneration::Serial);
                }
                check_native_organization_lists(
                    Arc::new(EphemeralStore::new(Arc::new(config.clone()))),
                    config.clone(),
                    false,
                    serial,
                    secondary,
                )
                .await?;
                let database = Database::connect("sqlite::memory:")
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                migrator::run_migrations(&database)
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                check_native_organization_lists(
                    Arc::new(SeaOrmStore::<BundledSchema>::new(
                        AuthConfig::default(),
                        database,
                    )),
                    config,
                    true,
                    serial,
                    secondary,
                )
                .await?;
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn memory_organization_owners_compare_object_identity_in_both_join_modes() -> AuthResult<()> {
    for joins in [false, true] {
        for shape in [json!({"owner":1}), json!([1])] {
            let mut config = AuthConfig::default();
            config.advanced.database.joins = Some(joins);
            let store = EphemeralStore::new(Arc::new(config));
            let organization = store
                .create_organization(CreateOrganization::new("Native", "native"))
                .await?;
            let owner = FieldValue::from_json(shape.clone())?;
            let mut member = CreateMember::new(organization.id.typed()?, "placeholder", "owner");
            member.user_id = better_auth_core::SchemaValue::from_field(owner.clone());
            let _ = store.create_member(member).await?;
            assert_eq!(store.list_user_organizations_value(&owner).await?.len(), 1);
            assert!(
                store
                    .list_user_organizations_value(&FieldValue::from_json(shape)?)
                    .await?
                    .is_empty()
            );
        }
    }
    Ok(())
}

async fn check_pending_invitation_output<S: AuthSchema>(
    inner: Arc<dyn AuthStore<S>>,
    config: AuthConfig,
    secondary: bool,
) -> AuthResult<()> {
    use better_auth_core::user_fields::UserFieldType;
    use better_auth_core::{CreateInvitation, FieldDate, FieldMap, InvitationStatus, SchemaValue};

    let past = 946_684_800_000.0;
    let future = 4_102_444_800_000.0;
    let later = future + 86_400_000.0;
    let _ = inner
        .create_user(CreateUser {
            id: Some("inviter".into()),
            email: Some("inviter@pending.test".into()),
            name: Some("Inviter".into()).into(),
            ..Default::default()
        })
        .await?;
    for id in ["organization", "outside"] {
        let _ = inner
            .create_organization(CreateOrganization {
                id: Some(id.into()),
                ..CreateOrganization::new(id, id)
            })
            .await?;
    }
    let mut stored = Vec::new();
    for (id, organization, email, expiry, status) in [
        (
            "first",
            "organization",
            "recipient@pending.test",
            past,
            InvitationStatus::Pending,
        ),
        (
            "second",
            "organization",
            "recipient@pending.test",
            future,
            InvitationStatus::Pending,
        ),
        (
            "third",
            "organization",
            "other@pending.test",
            later,
            InvitationStatus::Pending,
        ),
        (
            "canceled",
            "organization",
            "recipient@pending.test",
            later,
            InvitationStatus::Canceled,
        ),
        (
            "outside",
            "outside",
            "UPPER@pending.test",
            later,
            InvitationStatus::Pending,
        ),
    ] {
        let mut input = CreateInvitation::new(
            organization,
            email,
            "member",
            "inviter",
            FieldDate::from_milliseconds(expiry),
        );
        input.id = Some(id.into());
        input.created_at = Some(FieldDate::from_milliseconds(past));
        input.status = Some(status);
        stored.push(inner.create_invitation(input).await?);
    }
    let store: Arc<dyn AuthStore<S>> = if secondary {
        Arc::new(SecondaryStore::new(
            inner.clone(),
            Arc::new(MemoryCacheAdapter::new()),
            Arc::new(config.clone()),
            Default::default(),
        )?)
    } else {
        inner.clone()
    };
    let limit = config.advanced.database.default_find_many_limit;
    let events = Events::default();
    for (label, replacement, active, failure) in [
        (
            "date",
            FieldValue::Date(FieldDate::from_milliseconds(later)),
            true,
            false,
        ),
        (
            "text",
            FieldValue::from("2100-01-02T00:00:00.000Z"),
            true,
            false,
        ),
        ("number", FieldValue::Number(later), true, false),
        ("null", FieldValue::Null, false, false),
        ("undefined", FieldValue::Undefined, false, false),
        ("invalid", FieldValue::from("invalid-expiry"), false, false),
        (
            "invalid-date",
            FieldValue::Date(FieldDate::invalid()),
            false,
            false,
        ),
        (
            "object",
            FieldValue::from(FieldMap::from([("toString".into(), FieldValue::Null)])),
            false,
            true,
        ),
    ] {
        let seen = events.clone();
        let output = replacement.clone();
        let mut fields = OrganizationFields::default();
        let _ = fields.invitation.fields_mut().insert(
            "expiresAt".into(),
            UserFieldConfig {
                field_type: UserFieldType::Date,
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |value| {
                        let milliseconds =
                            better_auth_core::query::field_date(&value)?.milliseconds();
                        let name = if milliseconds == past {
                            "first"
                        } else if milliseconds == future {
                            "second"
                        } else {
                            "third"
                        };
                        seen.lock()
                            .map_err(|error| AuthError::internal(error.to_string()))?
                            .push(name.into());
                        Ok(if milliseconds == past {
                            output.clone()
                        } else if milliseconds == future {
                            "invalid-expiry".into()
                        } else {
                            value
                        })
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let _ = fields.invitation.fields_mut().insert(
            "status".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(|_| Ok("canceled".into()))),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        inner.configure_organization_fields(fields)?;
        let result = store
            .get_pending_invitation("organization", "RECIPIENT@pending.test")
            .await;
        let expected_events = if limit == Some(0.0) {
            vec![]
        } else if limit == Some(1.0) {
            vec!["first"]
        } else {
            vec!["first", "second"]
        };
        assert_eq!(
            take(&events)?,
            expected_events,
            "{label}: getter output page"
        );
        if failure && limit != Some(0.0) {
            assert!(
                matches!(result.expect_err("Date conversion must reject the object"), AuthError::TypeError(message) if message == "No default value")
            );
        } else if active && limit != Some(0.0) {
            let mut expected = stored[0].clone();
            expected.expires_at = SchemaValue::from_field(replacement);
            expected.status = InvitationStatus::Canceled.into();
            assert_eq!(
                result?,
                Some(expected),
                "{label}: complete projected invitation"
            );
        } else {
            assert_eq!(
                result?, None,
                "{label}: invalid or expired values must not remain pending"
            );
        }
        let result = store
            .count_pending_organization_invitations("organization")
            .await;
        let expected_events = if limit == Some(0.0) {
            vec![]
        } else if limit == Some(1.0) {
            vec!["first"]
        } else {
            vec!["first", "second", "third"]
        };
        assert_eq!(
            take(&events)?,
            expected_events,
            "{label}: quota output page"
        );
        if failure && limit != Some(0.0) {
            assert!(
                matches!(result.expect_err("Quota Date conversion must reject the object"), AuthError::TypeError(message) if message == "No default value")
            );
        } else {
            let count = if limit == Some(0.0) {
                0
            } else {
                i64::from(active) + i64::from(limit != Some(1.0))
            };
            assert_eq!(
                result?, count,
                "{label}: quota uses projected expiration after the default page"
            );
        }
        assert_eq!(
            store
                .get_pending_invitation("outside", "UPPER@pending.test")
                .await?,
            None
        );
        assert!(take(&events)?.is_empty());
    }
    let mut fields = OrganizationFields::default();
    let _ = fields.invitation.fields_mut().insert(
        "expiresAt".into(),
        UserFieldConfig {
            field_type: UserFieldType::Date,
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    if better_auth_core::query::field_date(&value)?.milliseconds() == future {
                        Err(AuthError::bad_request("later-invitation-output-failed"))
                    } else {
                        Ok(FieldValue::Date(FieldDate::from_milliseconds(later)))
                    }
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    inner.configure_organization_fields(fields)?;
    for result in [
        store
            .get_pending_invitation("organization", "recipient@pending.test")
            .await
            .map(|_| ()),
        store
            .count_pending_organization_invitations("organization")
            .await
            .map(|_| ()),
    ] {
        if limit.is_none() {
            assert!(
                matches!(result.expect_err("A later output failure must precede selecting the first invitation"), AuthError::BadRequest(message) if message == "later-invitation-output-failed")
            );
        } else {
            result?;
        }
    }
    inner.configure_organization_fields(OrganizationFields::default())?;
    for expected in stored {
        assert_eq!(
            inner.get_invitation_by_id(expected.id.typed()?).await?,
            Some(expected)
        );
    }
    Ok(())
}

#[tokio::test]
async fn pending_invitations_project_the_complete_page_before_expiry_and_quota() -> AuthResult<()> {
    for secondary in [false, true] {
        for limit in [None, Some(0.0), Some(1.0)] {
            let mut config =
                AuthConfig::new("pending-invitation-query-secret-at-least-32-characters");
            config.advanced.database.default_find_many_limit = limit;
            check_pending_invitation_output(
                Arc::new(EphemeralStore::new(Arc::new(config.clone()))),
                config.clone(),
                secondary,
            )
            .await?;
            let database = Database::connect("sqlite::memory:")
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
            migrator::run_migrations(&database)
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
            check_pending_invitation_output(
                Arc::new(SeaOrmStore::<BundledSchema>::new(config.clone(), database)),
                config,
                secondary,
            )
            .await?;
        }
    }
    Ok(())
}
