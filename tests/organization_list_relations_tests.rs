//! Organization list relations retain runtime cardinality and public projection boundaries.
#![cfg(feature = "seaorm2")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "The paired contract propagates setup errors and asserts complete results, callbacks, and storage."
)]

use async_trait::async_trait;
use better_auth::{
    BetterAuth,
    plugins::organization::{OrganizationConfig, OrganizationPlugin},
    server_api::EndpointInput,
};
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthPlugin, AuthRecordFields, AuthRequest, AuthResponse,
    AuthResult, AuthRoute, AuthSchema, AuthStore, CreateInvitation, CreateSession, CreateUser,
    FieldDate, FieldMap, FieldValue, HttpMethod, Member, Organization,
    store::{EphemeralStore, StatelessSchema, schema::EntityRole},
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldReference, UserFieldTransform,
    },
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement},
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
};

#[path = "organization_list_relations_tests/expectations.rs"]
mod expectations;
#[path = "organization_list_relations_tests/policies.rs"]
mod policies;
#[path = "support/sqlite_fixture_schema.rs"]
mod sqlite_fixture_schema;
#[path = "organization_list_relations_tests/storage.rs"]
mod storage;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Parent {
    Member,
    Invitation,
}
impl Parent {
    const ALL: [Self; 2] = [Self::Member, Self::Invitation];
    fn model(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Invitation => "invitation",
        }
    }
    fn role(self) -> EntityRole {
        match self {
            Self::Member => EntityRole::Member,
            Self::Invitation => EntityRole::Invitation,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    MappedMissing,
    Redirect,
    Many,
    UniqueDuplicates,
    NullProjection,
    FallbackKeyRedirect,
    FallbackKeyNull,
    NoRefs,
    NoRefsEmpty,
    MultipleRefs,
    MultipleRefsEmpty,
    ManyEmptySchema,
    FunctionUnfiltered,
    FunctionHidden,
}
impl Case {
    const ALL: [Self; 14] = [
        Self::MappedMissing,
        Self::Redirect,
        Self::Many,
        Self::UniqueDuplicates,
        Self::NullProjection,
        Self::FallbackKeyRedirect,
        Self::FallbackKeyNull,
        Self::NoRefs,
        Self::NoRefsEmpty,
        Self::MultipleRefs,
        Self::MultipleRefsEmpty,
        Self::ManyEmptySchema,
        Self::FunctionUnfiltered,
        Self::FunctionHidden,
    ];
    fn reverse(self) -> bool {
        matches!(
            self,
            Self::Many | Self::UniqueDuplicates | Self::ManyEmptySchema
        )
    }
    fn many(self) -> bool {
        matches!(self, Self::Many | Self::ManyEmptySchema)
    }
    fn fallback_key(self) -> bool {
        matches!(self, Self::FallbackKeyRedirect | Self::FallbackKeyNull)
    }
    fn empty(self) -> bool {
        matches!(self, Self::NoRefsEmpty | Self::MultipleRefsEmpty)
    }
    fn function(self) -> bool {
        matches!(self, Self::FunctionUnfiltered | Self::FunctionHidden)
    }
    fn parent_roles(self) -> Vec<&'static str> {
        if self.empty() {
            Vec::new()
        } else if self == Self::MappedMissing {
            vec!["org-a", "missing"]
        } else if self.many() {
            vec!["linked", "missing"]
        } else if self == Self::UniqueDuplicates {
            vec!["linked"]
        } else if matches!(self, Self::Redirect | Self::FallbackKeyRedirect) {
            vec!["slug-a"]
        } else {
            vec!["org-a"]
        }
    }
    fn error(self, parent: Parent) -> Option<String> {
        let model = parent.model();
        match self {
            Self::NoRefs | Self::NoRefsEmpty => Some(format!(
                "No foreign key found for model organization and base model {model} while performing join operation."
            )),
            Self::MultipleRefs | Self::MultipleRefsEmpty => Some(format!(
                "Multiple foreign keys found for model organization and base model {model} while performing join operation. Only one foreign key is supported."
            )),
            _ => None,
        }
    }
}

fn date() -> FieldDate {
    FieldDate::from_milliseconds(1_893_456_000_000.0)
}
fn config(native: bool) -> AuthConfig {
    let mut config =
        AuthConfig::new("organization-list-relations-secret-at-least-thirty-two-characters")
            .base_url("http://list-relations.test");
    config.logger = better_auth_core::LoggerConfig {
        disabled: Some(true),
        ..Default::default()
    }
    .into();
    config.advanced.database.joins = Some(native);
    config
}

#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<FieldValue>>>);
impl Events {
    fn push(&self, name: &str, value: FieldValue) -> AuthResult<()> {
        self.0
            .lock()
            .map_err(|error| AuthError::internal(error.to_string()))?
            .push(vec![name.into(), value].into());
        Ok(())
    }
    fn take(&self) -> AuthResult<Vec<FieldValue>> {
        Ok(std::mem::take(
            &mut *self
                .0
                .lock()
                .map_err(|error| AuthError::internal(error.to_string()))?,
        ))
    }
}

fn ordered(actual: &FieldValue, expected: &FieldValue) -> AuthResult<()> {
    assert_eq!(actual, expected);
    if let (Some(actual), Some(expected)) = (actual.as_object(), expected.as_object()) {
        let actual = actual.snapshot_fields()?;
        let expected = expected.snapshot_fields()?;
        assert_eq!(
            actual.keys().collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>()
        );
        for (name, value) in expected {
            ordered(
                actual
                    .get(&name)
                    .ok_or_else(|| AuthError::internal("Expected complete output key"))?,
                &value,
            )?;
        }
    } else if let (Some(actual), Some(expected)) = (actual.as_array(), expected.as_array()) {
        for (actual, expected) in actual.iter()?.zip(expected.iter()?) {
            ordered(&actual?, &expected?)?;
        }
    }
    Ok(())
}

async fn check<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: storage::Storage,
    native: bool,
    parent: Parent,
    case: Case,
) -> AuthResult<()> {
    let token = storage::seed(raw.as_ref(), parent, case).await?;
    let before = storage.snapshot().await?;
    let events = Events::default();
    let name = {
        let events = events.clone();
        let function: better_auth_core::user_fields::UserFieldFactory =
            better_auth_core::user_fields::UserFieldFactory::new(move || {
                events.push("function-called", FieldValue::Undefined)?;
                Ok("called".into())
            });
        FieldValue::Function(function.into())
    };
    let auth = policies::auth(raw, native, parent, case, &events, &name).await?;
    assert!(events.take()?.is_empty());
    for public in [false, true] {
        let actual: AuthResult<FieldValue> = if public {
            let cookie = better_auth_core::utils::cookie_utils::sign_cookie_value(
                &token,
                auth.config().signing_secret(),
            );
            auth.call_endpoint(
                HttpMethod::Get,
                if parent == Parent::Member {
                    "/organization/list"
                } else {
                    "/organization/list-user-invitations"
                },
                EndpointInput {
                    headers: Some(HashMap::from([(
                        "cookie".into(),
                        format!("better-auth.session_token={cookie}"),
                    )])),
                    ..Default::default()
                },
            )
            .await
            .and_then(|response| response.body.field_value())
        } else if parent == Parent::Member {
            auth.store()
                .list_user_organizations_value(&"user".into())
                .await
                .map(|rows| {
                    rows.into_iter()
                        .map(FieldValue::from)
                        .collect::<Vec<_>>()
                        .into()
                })
        } else {
            auth.store()
                .list_user_invitations("OWNER@LIST-RELATIONS.TEST")
                .await
                .and_then(|rows| {
                    rows.into_iter()
                        .map(|row| {
                            let mut fields = row.invitation.field_values()?;
                            let _ = fields.insert("organization".into(), row.organization.into());
                            Ok(fields.into())
                        })
                        .collect::<AuthResult<Vec<FieldValue>>>()
                        .map(FieldValue::from)
                })
        };
        if let Some(expected) = case.error(parent) {
            let error = actual.err().ok_or_else(|| {
                AuthError::internal("Invalid references must fail before reading parents")
            })?;
            assert!(matches!(error, AuthError::Config(message) if message == expected));
        } else if public && parent == Parent::Member && case == Case::FunctionHidden {
            assert!(matches!(actual, Err(AuthError::DataClone)));
        } else {
            ordered(
                &actual?,
                &expectations::result(storage.sqlite(), native, parent, case, public, &name),
            )?;
        }
        assert_eq!(
            events.take()?,
            expectations::events(storage.sqlite(), native, parent, case),
            "{parent:?}/{case:?}/native={native}/public={public}"
        );
        assert_eq!(
            storage.snapshot().await?,
            before,
            "{parent:?}/{case:?}/public={public}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn memory_organization_list_relations_match_upstream() -> AuthResult<()> {
    for native in [false, true] {
        for parent in Parent::ALL {
            for case in Case::ALL {
                let store = EphemeralStore::new(Arc::new(config(native)));
                let raw: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(store.clone());
                check(
                    raw,
                    storage::Storage::Memory(Box::new(store)),
                    native,
                    parent,
                    case,
                )
                .await?;
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_organization_list_relations_match_upstream() -> AuthResult<()> {
    for native in [false, true] {
        for parent in Parent::ALL {
            for case in Case::ALL {
                let database = Database::connect("sqlite::memory:")
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                migrator::run_migrations(&database)
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                if !case.reverse() {
                    // Mapped reads require a schema that can also pass HTTP write-column preflight.
                    sqlite_fixture_schema::rewrite_empty_table(&database, parent.model(), |sql| {
                        sqlite_fixture_schema::column_constraint(sql, "organization_id", "")
                    })
                    .await?;
                }
                let raw: Arc<dyn AuthStore<BundledSchema>> = Arc::new(
                    SeaOrmStore::<BundledSchema>::new(config(native), database.clone()),
                );
                check(
                    raw,
                    storage::Storage::Sqlite(database),
                    native,
                    parent,
                    case,
                )
                .await?;
            }
        }
    }
    Ok(())
}
