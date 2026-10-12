use super::{SeaOrmStore, plugin_rows};
use crate::{
    SeaOrmOrganizationSchema, SeaOrmPluginSchema, SeaOrmUserModel, schema::AuthSchema,
    store::instrumentation::database_operation,
};
use better_auth_core::{
    AuthResult, FieldMap,
    store::{JoinValue, OrganizationDetails, schema::EntityRole},
};
use sea_orm::{QueryFilter, QuerySelect};

impl<S: AuthSchema, O: SeaOrmOrganizationSchema, P: SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S::User: SeaOrmUserModel,
    S::Session: crate::SeaOrmSessionModel,
    S::Account: crate::SeaOrmAccountModel,
    S::Verification: crate::SeaOrmVerificationModel,
{
    pub(super) async fn consume_organization_details(
        &self,
        parent: FieldMap,
        invitations: JoinValue<FieldMap>,
        members: JoinValue<FieldMap>,
        teams: Option<JoinValue<FieldMap>>,
        users_limit: f64,
    ) -> AuthResult<OrganizationDetails> {
        // The plugin consumes members only after every adapter relationship completes output.
        let members = members.into_required_page("members")?;
        let users = if members.is_empty() {
            Vec::new()
        } else {
            let owners = members
                .iter()
                .map(|member| member.get("userId").cloned().unwrap_or_default())
                .collect::<Vec<_>>();
            let backend = self.connection().get_database_backend();
            let fields = self.field_policy().user();
            let bound =
                self.bind_query_field(EntityRole::User, &fields, "id", &owners.into(), backend)?;
            let rows = database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
                self.config(),
                "findMany",
                async {
                    let (column, owners) = bound.resolve(EntityRole::User, &fields)?;
                    let query = plugin_rows::select_all::<<S::User as SeaOrmUserModel>::Entity>()
                        .filter(crate::store::value_filter::is_in(
                            S::User::field_column(&column)?,
                            &owners,
                            backend,
                        )?);
                    let (limit, _) =
                        crate::store::pagination::sql_pagination(backend, Some(users_limit), None)?;
                    plugin_rows::all(self.connection(), query.limit(limit)).await
                },
            )
            .await?;
            self.output_users(&rows, self.connection()).await?
        };
        Ok(OrganizationDetails {
            organization: parent,
            invitations,
            members,
            users,
            teams,
        })
    }
}
