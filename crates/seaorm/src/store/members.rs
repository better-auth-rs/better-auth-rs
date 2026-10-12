use crate::store::query_compile::Execute;
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{EntityTrait, QueryFilter, QueryOrder, QuerySelect, Select};

use better_auth_core::store::{ListOrganizationMembersParams, MemberStore};

use crate::error::{AuthError, AuthResult};
use crate::schema::AuthSchema;
use crate::types_org::{CreateMember, Member};

use super::organization_models::{self as models, Entity, values};
use super::{SeaOrmStore, map_db_err};
use crate::SeaOrmOrganizationModel;
use better_auth_core::{FieldValue, SchemaField, store::schema::EntityRole};
use sea_orm::sea_query::Expr;

mod query;

#[async_trait]
impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> MemberStore
    for SeaOrmStore<S, O, P>
where
    S: AuthSchema + Send + Sync,
    S::User: crate::SeaOrmUserModel,
    S::Session: crate::SeaOrmSessionModel,
    S::Account: crate::SeaOrmAccountModel,
    S::Verification: crate::SeaOrmVerificationModel,
{
    async fn insert_member(&self, record: Member) -> AuthResult<Member> {
        let config = self.organization_fields()?.member;
        let core = models::with_id(
            models::values([
                ("organization_id", record.organization_id.into_field_value()),
                ("user_id", record.user_id.into_field_value()),
                ("role", record.role.into_field_value()),
                ("created_at", record.created_at.into_field_value()),
            ]),
            (!record.id.is_undefined()).then(|| record.id.field_value()),
        );
        let row = models::active::<O::Member>(
            core,
            record.additional_fields,
            &config,
            Some("member"),
            self.connection().get_database_backend(),
            self.config().advanced.database.generate_id(),
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::Member,
            ),
        )
        .await?
        .insert_raw(
            self.connection(),
            super::create_readback::CreateReadback {
                schema: &config,
                policy: self.config().advanced.database.generate_id(),
                scope: super::create_readback::ReadbackScope::Direct(self.connection()),
                column: O::Member::column,
            },
        )
        .await?
        .ok_or_else(|| AuthError::internal("Member creation returned no record"))?;
        models::record::<O::Member>(
            &row.into(),
            &config,
            self.connection().get_database_backend(),
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::Member,
            ),
        )
        .await
    }

    async fn create_member(&self, member: CreateMember) -> AuthResult<Member> {
        self.create_member_with_connection(
            self.connection(),
            super::create_readback::ReadbackScope::Direct(self.connection()),
            member,
        )
        .await
    }

    async fn get_member_with_user(
        &self,
        organization_id: &str,
        user_id: &str,
    ) -> AuthResult<Option<better_auth_core::store::MemberUser>> {
        let query = super::plugin_rows::select_all::<Entity<O::Member>>().filter(
            self.organization_fields_equal::<O::Member>(
                better_auth_core::store::schema::EntityRole::Member,
                [
                    ("organizationId", &organization_id.into()),
                    ("userId", &user_id.into()),
                ],
            )?,
        );
        self.read_member_user(query, false).await
    }
    async fn get_member_with_user_value(
        &self,
        organization_id: &FieldValue,
        user_id: &FieldValue,
    ) -> AuthResult<Option<better_auth_core::store::MemberUser>> {
        let query = super::plugin_rows::select_all::<Entity<O::Member>>().filter(
            self.organization_fields_equal::<O::Member>(
                better_auth_core::store::schema::EntityRole::Member,
                [("organizationId", organization_id), ("userId", user_id)],
            )?,
        );
        self.read_member_user(query, false).await
    }
    async fn get_member_by_id_with_user(
        &self,
        id: &str,
    ) -> AuthResult<Option<better_auth_core::store::MemberUser>> {
        let query = super::plugin_rows::select_all::<Entity<O::Member>>().filter(
            self.organization_field_equals::<O::Member>(
                better_auth_core::store::schema::EntityRole::Member,
                "id",
                &id.into(),
            )?,
        );
        self.read_member_user(query, true).await
    }

    async fn get_member(&self, organization_id: &str, user_id: &str) -> AuthResult<Option<Member>> {
        self.get_member_value(&organization_id.into(), &user_id.into())
            .await
    }

    async fn get_member_value(
        &self,
        organization_id: &FieldValue,
        user_id: &FieldValue,
    ) -> AuthResult<Option<Member>> {
        self.get_member_value_with_connection(self.connection(), organization_id, user_id)
            .await
    }

    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<Member>> {
        let query = super::plugin_rows::select_all::<Entity<O::Member>>().filter(
            self.organization_field_equals::<O::Member>(
                better_auth_core::store::schema::EntityRole::Member,
                "id",
                &id.into(),
            )?,
        );
        self.read_organization_model::<O::Member>(
            self.connection(),
            query,
            better_auth_core::store::schema::EntityRole::Member,
        )
        .await
    }

    async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<Member> {
        self.update_member_role_value(&member_id.into(), role).await
    }
    async fn update_member_role_value(
        &self,
        member_id: &better_auth_core::FieldValue,
        role: &str,
    ) -> AuthResult<Member> {
        self.update_member_role_optional_value(member_id, role)
            .await?
            .ok_or_else(|| AuthError::not_found("Organization record not found"))
    }
    async fn update_member_role_optional_value(
        &self,
        member_id: &better_auth_core::FieldValue,
        role: &str,
    ) -> AuthResult<Option<Member>> {
        self.update_organization_model_optional::<O::Member>(
            self.connection(),
            better_auth_core::store::schema::EntityRole::Member,
            member_id,
            values([("role", (role).to_owned().into_field())]),
            Default::default(),
            &self.organization_fields()?.member,
        )
        .await
    }

    async fn delete_member(&self, member_id: &str) -> AuthResult<()> {
        self.delete_member_value(&member_id.into()).await
    }
    async fn delete_member_value(
        &self,
        member_id: &better_auth_core::FieldValue,
    ) -> AuthResult<()> {
        use sea_orm::TransactionTrait;
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        let result = self.delete_member_with_connection(&tx, member_id).await?;
        tx.commit().await.map_err(map_db_err)?;
        Ok(result)
    }

    async fn delete_member_for_user(
        &self,
        member_id: &str,
        organization_id: &str,
        user_id: &str,
    ) -> AuthResult<()> {
        self.delete_member_for_user_value(
            &member_id.into(),
            &organization_id.into(),
            &user_id.into(),
        )
        .await
    }
    async fn delete_member_for_user_value(
        &self,
        member_id: &better_auth_core::FieldValue,
        organization_id: &better_auth_core::FieldValue,
        user_id: &better_auth_core::FieldValue,
    ) -> AuthResult<()> {
        use sea_orm::TransactionTrait;
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        self.delete_member_for_user_with_connection(&tx, member_id, organization_id, user_id)
            .await?;
        tx.commit().await.map_err(map_db_err)
    }

    async fn list_organization_members(&self, organization_id: &str) -> AuthResult<Vec<Member>> {
        self.list_organization_members_value(&organization_id.into())
            .await
    }

    async fn list_organization_members_value(
        &self,
        organization_id: &better_auth_core::FieldValue,
    ) -> AuthResult<Vec<Member>> {
        let rows = super::plugin_rows::all(
            self.connection(),
            super::plugin_rows::select_all::<Entity<O::Member>>()
                .filter(self.organization_field_equals::<O::Member>(
                    better_auth_core::store::schema::EntityRole::Member,
                    "organizationId",
                    organization_id,
                )?)
                .order_by_asc(O::Member::column("created_at")?),
        )
        .await?;
        models::project::<O::Member>(
            rows,
            &self.organization_fields()?.member,
            self.connection().get_database_backend(),
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::Member,
            ),
        )
        .await
    }

    async fn query_organization_members(
        &self,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<(Vec<Member>, usize)> {
        let page_store = self.clone();
        let page_params = params.clone();
        let count_store = self.clone();
        let count_params = params.clone();
        better_auth_core::request_runtime::concurrent::pair(
            "Member query task",
            async move { page_store.member_query_page(&page_params).await },
            async move { count_store.member_query_count(&count_params).await },
        )
        .await
    }

    async fn count_organization_members(&self, organization_id: &str) -> AuthResult<i64> {
        self.count_organization_members_with_connection(
            self.connection(),
            &(organization_id).to_owned().into_field(),
        )
        .await
    }

    async fn count_organization_members_value(
        &self,
        organization_id: &FieldValue,
    ) -> AuthResult<i64> {
        self.count_organization_members_with_connection(self.connection(), organization_id)
            .await
    }
    async fn count_organization_owners(&self, organization_id: &str) -> AuthResult<i64> {
        let query =
            Entity::<O::Member>::find().filter(self.organization_fields_equal::<O::Member>(
                better_auth_core::store::schema::EntityRole::Member,
                [
                    ("organizationId", &organization_id.into()),
                    ("role", &"owner".into()),
                ],
            )?);
        super::plugin_rows::count(self.connection(), query)
            .await
            .map(|count| count as i64)
    }
}

impl<
    S: better_auth_core::AuthSchema,
    O: crate::SeaOrmOrganizationSchema,
    P: crate::SeaOrmPluginSchema,
> SeaOrmStore<S, O, P>
{
    pub(super) async fn create_member_with_connection<C: sea_orm::ConnectionTrait>(
        &self,
        db: &C,
        scope: super::create_readback::ReadbackScope<'_>,
        member: CreateMember,
    ) -> AuthResult<Member> {
        let mut core = values([
            ("organization_id", member.organization_id.into_field_value()),
            ("user_id", member.user_id.into_field_value()),
            ("created_at", FieldValue::Date(Utc::now().into())),
        ]);
        if let Some(role) = Some(member.role.field_value()).filter(|value| !value.is_undefined()) {
            let _ = core.insert("role".into(), role);
        }
        models::insert::<O::Member, _>(
            db,
            scope,
            core,
            member.additional_fields,
            &self.organization_fields()?.member,
            self.config().advanced.database.generate_id(),
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::Member,
                "member",
            ),
        )
        .await
    }

    pub(super) async fn get_member_value_with_connection<C: sea_orm::ConnectionTrait>(
        &self,
        db: &C,
        organization_id: &FieldValue,
        user_id: &FieldValue,
    ) -> AuthResult<Option<Member>> {
        let query = super::plugin_rows::select_all::<Entity<O::Member>>().filter(
            self.organization_fields_equal::<O::Member>(
                better_auth_core::store::schema::EntityRole::Member,
                [("organizationId", organization_id), ("userId", user_id)],
            )?,
        );
        self.read_organization_model::<O::Member>(
            db,
            query,
            better_auth_core::store::schema::EntityRole::Member,
        )
        .await
    }

    pub(super) async fn count_organization_members_with_connection<C: sea_orm::ConnectionTrait>(
        &self,
        db: &C,
        organization_id: &FieldValue,
    ) -> AuthResult<i64> {
        let query =
            Entity::<O::Member>::find().filter(self.organization_field_equals::<O::Member>(
                better_auth_core::store::schema::EntityRole::Member,
                "organizationId",
                organization_id,
            )?);
        super::plugin_rows::count(db, query)
            .await
            .map(|count| count as i64)
    }

    pub(super) async fn delete_member_with_connection<C: sea_orm::ConnectionTrait>(
        &self,
        db: &C,
        member_id: &better_auth_core::FieldValue,
    ) -> AuthResult<()> {
        let Some(member) = self
            .find_organization_model::<O::Member>(
                db,
                better_auth_core::store::schema::EntityRole::Member,
                member_id,
            )
            .await?
        else {
            return Ok(());
        };
        let member = models::record::<O::Member>(
            &member,
            &self.organization_fields()?.member,
            db.get_database_backend(),
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::Member,
            ),
        )
        .await?;
        self.delete_resolved_member_for_user_with_connection(
            db,
            member_id,
            &member.organization_id.field_value(),
            &member.user_id.field_value(),
        )
        .await
    }

    pub(super) async fn delete_member_for_user_with_connection<C: sea_orm::ConnectionTrait>(
        &self,
        db: &C,
        member_id: &better_auth_core::FieldValue,
        organization_id: &better_auth_core::FieldValue,
        user_id: &better_auth_core::FieldValue,
    ) -> AuthResult<()> {
        let user_id = if user_id.is_truthy() {
            user_id.clone()
        } else {
            let member = self
                .find_organization_model::<O::Member>(db, EntityRole::Member, member_id)
                .await?
                .ok_or_else(|| AuthError::better_auth("Member not found"))?;
            models::record::<O::Member>(
                &member,
                &self.organization_fields()?.member,
                db.get_database_backend(),
                (&self.model_fields, EntityRole::Member),
            )
            .await?
            .user_id
            .field_value()
        };
        self.delete_resolved_member_for_user_with_connection(
            db,
            member_id,
            organization_id,
            &user_id,
        )
        .await
    }

    async fn delete_resolved_member_for_user_with_connection<C: sea_orm::ConnectionTrait>(
        &self,
        db: &C,
        member_id: &FieldValue,
        organization_id: &FieldValue,
        user_id: &FieldValue,
    ) -> AuthResult<()> {
        let _ = Entity::<O::Member>::delete_many()
            .filter(self.organization_field_equals::<O::Member>(
                better_auth_core::store::schema::EntityRole::Member,
                "id",
                member_id,
            )?)
            .exec_native(db)
            .await?;
        if !self.model_fields.organization_teams_enabled() {
            return Ok(());
        }
        let teams = super::plugin_rows::all(
            db,
            super::plugin_rows::select_all::<Entity<O::Team>>()
                .filter(self.organization_field_equals::<O::Team>(
                    better_auth_core::store::schema::EntityRole::Team,
                    "organizationId",
                    organization_id,
                )?)
                .limit(super::pagination::default_limit(
                    &self.config,
                    db.get_database_backend(),
                )?),
        )
        .await?;
        let teams = models::project::<O::Team>(
            teams,
            &self.organization_fields()?.team,
            db.get_database_backend(),
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::Team,
            ),
        )
        .await?;
        for team in teams {
            self.model_fields
                .begin_id_query(better_auth_core::store::schema::EntityRole::Team)?;
            let _ = Entity::<O::Team>::update_many()
                .col_expr(
                    O::Team::column("member_count")?,
                    Expr::col(O::Team::column("member_count")?),
                )
                .filter(super::value_filter::equals_id(
                    O::Team::column("id")?,
                    &team.id.field_value(),
                    self.config().advanced.database.generate_id(),
                    self.connection().get_database_backend(),
                )?)
                .exec_native(db)
                .await?;
            let deleted = Entity::<O::TeamMember>::delete_many()
                .filter(self.organization_fields_equal::<O::TeamMember>(
                    better_auth_core::store::schema::EntityRole::TeamMember,
                    [("teamId", &team.id.field_value()), ("userId", user_id)],
                )?)
                .exec_native(db)
                .await?;
            super::team_capacity::release::<O::Team, _>(
                db,
                super::create_readback::ReadbackScope::Transaction,
                &team.id.field_value(),
                deleted.rows_affected,
                &self.organization_fields()?.team,
                self.config(),
                (
                    &self.model_fields,
                    better_auth_core::store::schema::EntityRole::Team,
                ),
            )
            .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "The member contracts assert driver-bound patterns and pagination while propagating setup errors."
    )]
    use std::sync::Arc;

    use better_auth_core::config::AuthConfig;
    use better_auth_core::store::{
        ListOrganizationMembersParams, MemberStore, OrganizationStore, UserStore,
    };
    use better_auth_core::types::{CreateMember, CreateOrganization, CreateUser};

    use crate::Database;
    use crate::store::__private_test_support::bundled_schema::BundledSchema;
    use crate::store::__private_test_support::migrator::run_migrations;

    use super::SeaOrmStore;

    async fn test_store() -> better_auth_core::AuthResult<SeaOrmStore<BundledSchema>> {
        let database = Database::connect("sqlite::memory:")
            .await
            .map_err(super::map_db_err)?;
        run_migrations(&database).await.map_err(super::map_db_err)?;
        Ok(SeaOrmStore::new(
            Arc::new(AuthConfig::new("test-secret-key-at-least-32-chars-long")),
            database,
        ))
    }

    #[tokio::test]
    async fn member_patterns_keep_utf16_until_the_driver_binds_the_complete_pattern()
    -> better_auth_core::AuthResult<()> {
        use crate::SeaOrmOrganizationModel;
        use crate::store::{
            entities::member, map_db_err, record_bindings::parameter, value_filter,
        };
        use better_auth_core::{
            FieldValue, Utf16String, WhereMode, id::IdGeneration,
            organization_fields::OrganizationFields, query::where_operator,
            store::schema::EntityRole,
        };
        use sea_orm::{
            ConnectOptions, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect, QueryTrait,
            sea_query::Query,
        };

        let fields = OrganizationFields::default().into_storage().member;
        for encoding in ["UTF-8", "UTF-16le", "UTF-16be"] {
            let mut options = ConnectOptions::new("sqlite::memory:");
            let _ = options.max_connections(1);
            let database = Database::connect(options).await.map_err(map_db_err)?;
            let _ = database
                .execute_unprepared(&format!("PRAGMA encoding = '{encoding}'"))
                .await
                .map_err(map_db_err)?;
            let _ = database
                .execute_unprepared("CREATE TABLE member (id TEXT, role TEXT)")
                .await
                .map_err(map_db_err)?;
            for (operator, units, actual, matches) in [
                ("contains", vec![0xd800], "x\u{10025}", true),
                ("contains", vec![0xd800], "x\u{10025}y", false),
                ("starts_with", vec![0xd800], "\u{10025}", true),
                ("starts_with", vec![0xd800], "\u{10025}x", false),
                ("ends_with", vec![0xd800], "x\u{fffd}", true),
                ("ends_with", vec![0xd800], "x\u{fffd}y", false),
                ("contains", vec![0xfeff, 0x41], "x\u{feff}A", true),
                ("contains", vec![0xfeff, 0x41], "xA", false),
                ("starts_with", vec![0xfffe], "\u{2500}", true),
                ("starts_with", vec![0xfffe], "plain", false),
                ("starts_with", vec![0x5f], "x", true),
                ("starts_with", vec![0x5f], "", false),
                ("contains", vec![0x5c, 0x5f], "\\x", true),
                ("contains", vec![0x5c, 0x5f], "x", false),
            ] {
                let _ = database
                    .execute_unprepared("DELETE FROM member")
                    .await
                    .map_err(map_db_err)?;
                let insert = Query::insert()
                    .into_table(member::Entity)
                    .columns([member::Column::Id, member::Column::Role])
                    .values_panic([
                        parameter("member".into(), sea_orm::DbBackend::Sqlite)?,
                        parameter(actual.into(), sea_orm::DbBackend::Sqlite)?,
                    ])
                    .to_owned();
                let _ = database
                    .execute_raw(sea_orm::DbBackend::Sqlite.build(&insert))
                    .await
                    .map_err(map_db_err)?;
                let (column, value) = value_filter::bind_query_field(
                    &better_auth_core::plugin_runtime::ModelFields::default(),
                    EntityRole::Member,
                    &fields,
                    "role",
                    &FieldValue::Utf16String(Utf16String::from_units(units)),
                    &IdGeneration::Random,
                    sea_orm::DbBackend::Sqlite,
                )?;
                let query = member::Entity::find()
                    .select_only()
                    .column(member::Column::Id)
                    .filter(value_filter::predicate(
                        member::Model::column(&column)?,
                        where_operator(operator),
                        WhereMode::Sensitive,
                        value,
                        sea_orm::DbBackend::Sqlite,
                    )?);
                let rows = database
                    .query_all_raw(query.build(sea_orm::DbBackend::Sqlite))
                    .await
                    .map_err(map_db_err)?;
                let ids = rows
                    .iter()
                    .map(|row| row.try_get::<String>("", "id").map_err(map_db_err))
                    .collect::<better_auth_core::AuthResult<Vec<_>>>()?;
                assert_eq!(
                    ids,
                    if matches {
                        vec!["member"]
                    } else {
                        Vec::<&str>::new()
                    },
                    "{encoding}: {operator}, {actual:?}"
                );
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn query_organization_members_applies_filter_sort_and_pagination()
    -> better_auth_core::AuthResult<()> {
        let store = test_store().await?;
        let org_id = "org-1".to_string();
        let _organization = store
            .create_organization(CreateOrganization {
                additional_fields: Default::default(),
                id: Some(org_id.clone()),
                name: "Org".to_string().into(),
                slug: "org".to_string().into(),
                logo: None.into(),
                metadata: None.into(),
            })
            .await?;
        let _owner = store
            .create_user(CreateUser {
                name: Some("Fixture".into()).into(),
                id: Some("user-owner".to_string()),
                email: Some("owner@example.com".to_string()),
                ..CreateUser::default()
            })
            .await?;
        let _member = store
            .create_user(CreateUser {
                name: Some("Fixture".into()).into(),
                id: Some("user-member".to_string()),
                email: Some("member@example.com".to_string()),
                ..CreateUser::default()
            })
            .await?;
        let _admin = store
            .create_user(CreateUser {
                name: Some("Fixture".into()).into(),
                id: Some("user-admin".to_string()),
                email: Some("admin@example.com".to_string()),
                ..CreateUser::default()
            })
            .await?;

        let _ = store
            .create_member(CreateMember::new(&org_id, "user-owner", "owner"))
            .await?;
        let _ = store
            .create_member(CreateMember::new(&org_id, "user-member", "member"))
            .await?;
        let _ = store
            .create_member(CreateMember::new(&org_id, "user-admin", "admin"))
            .await?;

        let params = ListOrganizationMembersParams {
            organization_id: org_id.into(),
            limit: Some(1.0),
            offset: Some(1.0),
            sort_by: Some("role".to_string()),
            sort_direction: Some("asc".to_string()),
            filter_field: Some("role".to_string()),
            filter_value: Some("owner".into()),
            filter_operator: Some("ne".to_string()),
        };

        let (members, total) = store.query_organization_members(&params).await?;

        assert_eq!(total, 2);
        assert_eq!(members.len(), 1);
        let member = members
            .first()
            .ok_or_else(|| better_auth_core::AuthError::internal("Paginated member is absent"))?;
        assert_eq!(member.role, "member");
        Ok(())
    }
}
