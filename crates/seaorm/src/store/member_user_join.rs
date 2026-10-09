use super::{
    SeaOrmStore, instrumentation::database_operation, map_db_err, organization_models::Entity,
};
use crate::{
    SeaOrmAccountModel, SeaOrmOrganizationModel, SeaOrmOrganizationSchema, SeaOrmPluginSchema,
    SeaOrmSessionModel, SeaOrmUserModel, SeaOrmVerificationModel, schema::AuthSchema,
};
use better_auth_core::{
    AuthRecordFields, AuthResult, FromFieldMap, MemberUserView,
    store::{MemberUser, schema::EntityRole},
};
use sea_orm::{QuerySelect, Select};

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
        let native_join = self.config().advanced.database.joins == Some(true);
        let (member, selected_users) = if native_join {
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
            let rows = database_operation::<Entity<O::Member>, _>(
                self.config(),
                "findOne",
                super::joins::joined_raw_rows(self.connection(), &query),
            )
            .await?;
            let mut rows = rows.into_iter();
            let Some((member, first_user)) = rows.next() else {
                return Ok(None);
            };
            let users = super::joins::selected_raw_children(
                std::iter::once(first_user)
                    .chain(rows.map(|(_, user)| user))
                    .flatten(),
                S::User::id_column(),
                true,
                limit,
            )?;
            (member.model::<O::Member>()?, Some(users))
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
        let member = super::organization_models::record(
            &member,
            &fields,
            self.connection().get_database_backend(),
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::Member,
            ),
        )
        .await?;
        let users = match selected_users {
            Some(users) => users,
            None => {
                let value = member
                    .field_values()?
                    .remove(&relation.fallback_from(
                        (
                            EntityRole::Member,
                            "member",
                            &MemberUser::field_schema(&fields),
                        ),
                        &self.model_fields,
                    )?)
                    .unwrap_or_default();
                self.selected_join_users(&relation, value, limit).await?
            }
        };
        let mut output = Vec::with_capacity(users.len());
        for user in users {
            output.push(if native_join {
                self.output_member_join_user(&user).await?
            } else {
                MemberUserView::from_user(&self.output_user(&user, self.connection()).await?)
            });
        }
        MemberUser::finish(&relation, member, output, require_user)
    }

    async fn output_member_join_user(
        &self,
        user: &super::plugin_rows::SqlRow,
    ) -> AuthResult<MemberUserView> {
        // The one selected child remains a complete field map for the summary decoder.
        let mut pages = self
            .output_native_user_pages(vec![std::slice::from_ref(user)])
            .await?;
        MemberUserView::from_field_values(pages.remove(0).remove(0))
    }
}
