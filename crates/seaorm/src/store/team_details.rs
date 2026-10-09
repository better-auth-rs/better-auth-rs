//! Read scoped Teams and their configured membership relationship before capacity callbacks.

use super::{
    SeaOrmStore,
    organization_models::{self as models, Entity},
    plugin_rows::{self, SqlRow},
};
use crate::SeaOrmOrganizationModel;
use better_auth_core::{
    AuthResult, FieldMap, FieldValue,
    store::{ResolvedJoin, TeamDetails, schema::EntityRole},
    user_fields::UserConfig,
};
use sea_orm::{DbBackend, EntityTrait, QueryFilter, QuerySelect};

impl<S: crate::schema::AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmStore<S, O, P>
where
    S::User: crate::SeaOrmUserModel,
    S::Session: crate::SeaOrmSessionModel,
    S::Account: crate::SeaOrmAccountModel,
    S::Verification: crate::SeaOrmVerificationModel,
{
    pub(super) async fn read_team_details(
        &self,
        team_id: &FieldValue,
        organization_id: Option<&FieldValue>,
        include_members: bool,
    ) -> AuthResult<Option<TeamDetails>> {
        let backend = self.connection().get_database_backend();
        let mut selectors = vec![("id", team_id)];
        if let Some(organization_id) = organization_id.filter(|value| value.is_truthy()) {
            selectors.push(("organizationId", organization_id));
        }
        let parent = Entity::<O::Team>::find()
            .filter(self.organization_fields_equal::<O::Team>(EntityRole::Team, selectors)?)
            .limit(1);
        let team_fields = self.organization_query_schema(EntityRole::Team)?;
        let member_fields = self.model_fields.plugin_fields(EntityRole::TeamMember);
        let runtime = self.model_fields.organization_join_schema(self.config());
        let relation = include_members
            .then(|| {
                ResolvedJoin::resolve(
                    (EntityRole::Team, "team", &team_fields),
                    (EntityRole::TeamMember, "teamMember", &member_fields),
                    &runtime,
                    super::model_names::table_matches::<S, O, P>,
                )
            })
            .transpose()?;
        let selected = if let Some(relation) = relation
            .as_ref()
            .filter(|_| self.config().advanced.database.joins == Some(true))
        {
            self.model_fields.canonicalize_id(EntityRole::TeamMember)?;
            let query = super::joins::joined_query::<Entity<O::Team>, Entity<O::TeamMember>>(
                parent,
                (
                    O::Team::column(&relation.from)?,
                    O::TeamMember::column(&relation.to)?,
                ),
                O::TeamMember::column("id")?,
            );
            super::joins::grouped_raw_rows(
                super::joins::joined_raw_rows(self.connection(), &query).await?,
                O::Team::column("id")?,
            )?
            .into_iter()
            .next()
            .map(|(team, members)| {
                super::joins::selected_raw_children(
                    members.into_iter(),
                    O::TeamMember::column("id")?,
                    relation.many,
                    self.config().advanced.database.find_many_limit(),
                )
                .map(|members| (team, Some(members)))
            })
            .transpose()?
        } else {
            plugin_rows::one(self.connection(), parent)
                .await?
                .map(|team| (team, None))
        };
        let Some((row, native_members)) = selected else {
            return Ok(None);
        };
        let output = team_fields
            .organization_output_records(
                vec![models::raw_record::<O::Team>(
                    &row,
                    &team_fields,
                    backend,
                    (&self.model_fields, EntityRole::Team),
                )?],
                backend == DbBackend::Postgres,
            )
            .await?
            .remove(0);
        let output = plugin_rows::ordered_output(&team_fields, output);
        let members = if let Some(relation) = relation {
            let native = native_members.is_some();
            let rows = match native_members {
                Some(rows) => rows,
                None => {
                    self.fallback_team_members(&relation, &runtime, &team_fields, &output)
                        .await?
                }
            };
            let mut pages = super::joins::project_child_pages(
                &member_fields,
                vec![rows.as_slice()],
                backend,
                &|row: &SqlRow| {
                    let record = if native {
                        row.native_record::<Entity<O::TeamMember>>(
                            &member_fields,
                            backend,
                            O::TeamMember::column("id")?,
                            O::TeamMember::column,
                        )?
                    } else {
                        row.record::<Entity<O::TeamMember>>(
                            &member_fields,
                            backend,
                            O::TeamMember::column("id")?,
                            O::TeamMember::column,
                        )?
                    };
                    Ok(record.with_id_output(&self.model_fields, EntityRole::TeamMember))
                },
            )
            .await?;
            let members = pages
                .remove(0)
                .into_iter()
                .map(|output| plugin_rows::ordered_output(&member_fields, output))
                .collect();
            Some((members, relation.many))
        } else {
            None
        };
        TeamDetails::from_adapter_output(output, members).map(Some)
    }

    async fn fallback_team_members(
        &self,
        relation: &ResolvedJoin,
        runtime: &better_auth_core::plugin_runtime::ModelFields,
        fields: &UserConfig,
        output: &FieldMap,
    ) -> AuthResult<Vec<SqlRow>> {
        let field = relation.fallback_from((EntityRole::Team, "team", fields), runtime)?;
        let value = output.get(&field).cloned().unwrap_or_default();
        if value.is_null() || value.is_undefined() {
            return Ok(Vec::new());
        }
        let query = Entity::<O::TeamMember>::find().filter(
            self.organization_field_equals::<O::TeamMember>(
                EntityRole::TeamMember,
                &relation.to,
                &value,
            )?,
        );
        if relation.many {
            plugin_rows::all(
                self.connection(),
                query.limit(super::pagination::default_limit(
                    self.config(),
                    self.connection().get_database_backend(),
                )?),
            )
            .await
        } else {
            plugin_rows::one(self.connection(), query)
                .await
                .map(|row| row.into_iter().collect())
        }
    }
}
