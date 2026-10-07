use super::{
    SeaOrmStore, instrumentation::database_operation, map_db_err, organization_models::Entity,
};
use crate::{
    SeaOrmAccountModel, SeaOrmOrganizationModel, SeaOrmOrganizationSchema, SeaOrmPluginSchema,
    SeaOrmSessionModel, SeaOrmUserModel, SeaOrmVerificationModel, schema::AuthSchema,
};
use better_auth_core::{
    AuthRecordFields, AuthResult, FieldValue,
    store::{MemberUser, MemberUserJoin, schema::EntityRole},
};
use sea_orm::{ConnectionTrait, EntityTrait, QueryFilter, QuerySelect, Select};

impl<S: AuthSchema, O: SeaOrmOrganizationSchema, P: SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S::User: SeaOrmUserModel,
    S::Session: SeaOrmSessionModel,
    S::Account: SeaOrmAccountModel,
    S::Verification: SeaOrmVerificationModel,
{
    pub(super) async fn read_member_user(
        &self,
        query: Select<Entity<O::Member>>,
        require_user: bool,
    ) -> AuthResult<Option<MemberUser>> {
        let fields = self.organization_fields()?.member;
        let relation = MemberUser::resolve_schema(
            self.config(),
            &fields,
            &self.model_fields,
            super::model_names::table_matches::<S, O, P>,
        )?;
        let limit = if relation.many {
            self.config().advanced.database.find_many_limit()
        } else {
            1.0
        };
        let (member, selected_users) = if self.config().advanced.database.joins == Some(true) {
            self.model_fields.canonicalize_id(EntityRole::User)?;
            let query = super::joins::joined_query::<
                Entity<O::Member>,
                <S::User as SeaOrmUserModel>::Entity,
            >(
                query.limit(1),
                (
                    O::Member::column(&relation.from)?,
                    S::User::field_column(&relation.to)?,
                ),
                S::User::id_column(),
            );
            let rows =
                database_operation::<Entity<O::Member>, _>(
                    self.config(),
                    "findOne",
                    super::joins::joined_rows::<
                        Entity<O::Member>,
                        <S::User as SeaOrmUserModel>::Entity,
                    >(self.connection(), &query),
                )
                .await?;
            let mut rows = rows.into_iter();
            let Some((member, first_user)) = rows.next() else {
                return Ok(None);
            };
            let users = super::joins::limited_children::<<S::User as SeaOrmUserModel>::Entity>(
                std::iter::once(first_user)
                    .chain(rows.map(|(_, user)| user))
                    .flatten(),
                S::User::id_column(),
                limit,
            );
            (member, Some(users))
        } else {
            let member =
                database_operation::<Entity<O::Member>, _>(self.config(), "findOne", async {
                    query.one(self.connection()).await.map_err(map_db_err)
                })
                .await?;
            let Some(member) = member else {
                return Ok(None);
            };
            (member, None)
        };
        let member = member
            .record(&fields, self.connection().get_database_backend())
            .await?;
        let users = match selected_users {
            Some(users) => users,
            None => {
                let value = member
                    .field_values()?
                    .remove(&relation.fallback_from(&fields, &self.model_fields)?)
                    .unwrap_or_default();
                self.member_join_users(&relation, value, limit).await?
            }
        };
        let mut output = Vec::with_capacity(users.len());
        for user in users {
            output.push(self.output_user(&user, self.connection()).await?);
        }
        relation.finish(member, output, require_user)
    }

    async fn member_join_users(
        &self,
        relation: &MemberUserJoin,
        value: FieldValue,
        limit: f64,
    ) -> AuthResult<Vec<S::User>> {
        if value.is_null() || value.is_undefined() {
            return Ok(Vec::new());
        }
        let (logical_to, physical_to) =
            relation.fallback_target(self.config(), &self.model_fields)?;
        let field = MemberUserJoin::target_field(self.config(), &logical_to);
        let policy = self.config().advanced.database.generate_id();
        let backend = self.connection().get_database_backend();
        let original = value.clone();
        let value = if logical_to == "id" || field.references_id() {
            policy.adapter_id_query(value)?
        } else {
            value
        };
        let value = better_auth_core::user_query::bind_filter(&field, &value)?;
        let value = super::value_filter::adapter_query_value(value, &original, &field, backend)?;
        let column = S::User::field_column(&physical_to)?;
        let query = <S::User as SeaOrmUserModel>::Entity::find()
            .filter(super::value_filter::equals(column, &value, backend)?);
        database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
            self.config(),
            if relation.many { "findMany" } else { "findOne" },
            async {
                if relation.many {
                    query
                        .limit(super::pagination::sql_pagination(backend, Some(limit), None)?.0)
                        .all(self.connection())
                        .await
                        .map_err(map_db_err)
                } else {
                    query
                        .one(self.connection())
                        .await
                        .map(|user| user.into_iter().collect())
                        .map_err(map_db_err)
                }
            },
        )
        .await
    }
}
