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
use sea_orm::{Condition, ConnectionTrait, DbBackend, EntityName, QueryFilter, QuerySelect};

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
        conn: &impl ConnectionTrait,
        team_id: &FieldValue,
        organization_id: Option<&FieldValue>,
        include_members: bool,
    ) -> AuthResult<Option<TeamDetails>> {
        let condition = self.team_details_condition(team_id, organization_id)?;
        self.read_team_details_with_condition(conn, condition, include_members)
            .await
    }

    pub(super) fn team_details_condition(
        &self,
        team_id: &FieldValue,
        organization_id: Option<&FieldValue>,
    ) -> AuthResult<Condition> {
        let mut selectors = vec![("id", team_id)];
        if let Some(organization_id) = organization_id.filter(|value| value.is_truthy()) {
            selectors.push(("organizationId", organization_id));
        }
        self.organization_fields_equal::<O::Team>(EntityRole::Team, selectors)
    }

    pub(super) async fn read_team_details_with_condition(
        &self,
        conn: &impl ConnectionTrait,
        condition: Condition,
        include_members: bool,
    ) -> AuthResult<Option<TeamDetails>> {
        let backend = conn.get_database_backend();
        let parent = super::plugin_rows::select_all::<Entity<O::Team>>()
            .filter(condition)
            .limit(1);
        let team_fields = self.organization_query_schema(EntityRole::Team)?;
        let member_fields = self
            .model_fields
            .plugin_fields(EntityRole::TeamMember)
            .adapter_fields(&[]);
        let runtime = self.model_fields.organization_join_schema();
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
                backend,
                (parent, O::Team::column("id")?),
                (
                    O::Team::column(&relation.from)?,
                    O::TeamMember::column(&relation.to)?,
                ),
                &member_fields,
                O::TeamMember::column,
            )?;
            super::joins::grouped_raw_rows(
                super::joins::joined_raw_rows(conn, &query).await?,
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
            plugin_rows::one(conn, parent)
                .await?
                .map(|team| (team, None))
        };
        let Some((row, native_members)) = selected else {
            return Ok(None);
        };
        let mut record = models::raw_record::<O::Team>(
            &row,
            &team_fields,
            backend,
            (&self.model_fields, EntityRole::Team),
        )?;
        if let Some(members) = &native_members {
            let entity = Entity::<O::TeamMember>::default();
            let physical = self
                .model_fields
                .storage_model_name(EntityRole::TeamMember, entity.table_name());
            record = record.with_storage_property(
                physical,
                super::joins::raw_relation_value(
                    members,
                    &member_fields,
                    relation
                        .as_ref()
                        .ok_or_else(|| {
                            better_auth_core::AuthError::internal(
                                "Team query lost its member relationship",
                            )
                        })?
                        .many,
                    O::TeamMember::column,
                )?,
            );
        }
        let output = team_fields
            .organization_output_records(vec![record], backend == DbBackend::Postgres)
            .await?
            .remove(0);
        let output = plugin_rows::ordered_output(&team_fields, output);
        let members = if let Some(relation) = relation {
            let native = native_members.is_some();
            let rows = match native_members {
                Some(rows) => rows,
                None => {
                    self.fallback_team_members(conn, &relation, &runtime, &team_fields, &output)
                        .await?
                }
            };
            let record_fields = member_fields.clone();
            let record_runtime = self.model_fields.clone();
            let mut pages = super::joins::project_child_pages(
                &member_fields,
                vec![rows.as_slice()],
                backend,
                &move |row: &SqlRow| {
                    let record = if native {
                        row.native_record(&record_fields, backend, O::TeamMember::column)?
                    } else {
                        row.record::<Entity<O::TeamMember>>(
                            &record_fields,
                            backend,
                            O::TeamMember::column("id")?,
                            O::TeamMember::column,
                        )?
                    };
                    Ok(record.with_id_output(&record_runtime, EntityRole::TeamMember))
                },
            )
            .await?;
            let members = pages.remove(0);
            Some((members, relation.many))
        } else {
            None
        };
        TeamDetails::from_adapter_output(output, members).map(Some)
    }

    async fn fallback_team_members(
        &self,
        conn: &impl ConnectionTrait,
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
        let query = super::plugin_rows::select_all::<Entity<O::TeamMember>>().filter(
            self.organization_field_equals::<O::TeamMember>(
                EntityRole::TeamMember,
                &relation.to,
                &value,
            )?,
        );
        if relation.many {
            plugin_rows::all(
                conn,
                query.limit(super::pagination::default_limit(
                    self.config(),
                    conn.get_database_backend(),
                )?),
            )
            .await
        } else {
            plugin_rows::one(conn, query)
                .await
                .map(|row| row.into_iter().collect())
        }
    }
}
