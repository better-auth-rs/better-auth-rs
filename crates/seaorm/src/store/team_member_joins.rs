use super::{
    SeaOrmStore,
    organization_models::{self as models, Entity},
    plugin_rows::{self, SqlRow},
};
use crate::SeaOrmOrganizationModel;
use better_auth_core::{
    AuthError, AuthResult, FieldMap, FieldValue, Team,
    store::{ResolvedJoin, schema::EntityRole},
    user_fields::UserConfig,
};
use sea_orm::{DbBackend, EntityName, QueryFilter, QuerySelect};
use std::sync::Arc;

impl<S: crate::schema::AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmStore<S, O, P>
where
    S::User: crate::SeaOrmUserModel,
    S::Session: crate::SeaOrmSessionModel,
    S::Account: crate::SeaOrmAccountModel,
    S::Verification: crate::SeaOrmVerificationModel,
{
    pub(super) async fn list_user_teams_with_schema(
        &self,
        user_id: &FieldValue,
    ) -> AuthResult<Vec<Team>> {
        let backend = self.connection().get_database_backend();
        let parent = super::plugin_rows::select_all::<Entity<O::TeamMember>>()
            .filter(self.organization_field_equals::<O::TeamMember>(
                EntityRole::TeamMember,
                "userId",
                user_id,
            )?)
            .limit(super::pagination::default_limit(self.config(), backend)?);
        let membership_fields = self.model_fields.plugin_fields(EntityRole::TeamMember);
        let team_fields = self
            .organization_query_schema(EntityRole::Team)?
            .adapter_fields(&[]);
        let runtime = self.model_fields.organization_join_schema();
        let relation = ResolvedJoin::resolve(
            (EntityRole::TeamMember, "teamMember", &membership_fields),
            (EntityRole::Team, "team", &team_fields),
            &runtime,
            super::model_names::table_matches::<S, O, P>,
        )?;
        let native = self.config().advanced.database.joins == Some(true);
        let (memberships, children) = if native {
            self.model_fields.canonicalize_id(EntityRole::Team)?;
            let query = super::joins::joined_query::<Entity<O::TeamMember>, Entity<O::Team>>(
                backend,
                (parent, O::TeamMember::column("id")?),
                (
                    O::TeamMember::column(&relation.from)?,
                    O::Team::column(&relation.to)?,
                ),
                &team_fields,
                O::Team::column,
            )?;
            let rows = super::joins::grouped_raw_rows(
                super::joins::joined_raw_rows(self.connection(), &query).await?,
                O::TeamMember::column("id")?,
            )?;
            let mut memberships = Vec::with_capacity(rows.len());
            let mut children = Vec::with_capacity(rows.len());
            for (membership, teams) in rows {
                memberships.push(membership);
                children.push(super::joins::selected_raw_children(
                    teams.into_iter(),
                    O::Team::column("id")?,
                    relation.many,
                    self.config().advanced.database.find_many_limit(),
                )?);
            }
            (memberships, Some(children))
        } else {
            (plugin_rows::all(self.connection(), parent).await?, None)
        };
        let mut records = self.team_member_records(&memberships, backend)?;
        if let Some(children) = &children {
            let entity = Entity::<O::Team>::default();
            let physical = self
                .model_fields
                .storage_model_name(EntityRole::Team, entity.table_name());
            records = records
                .into_iter()
                .zip(children)
                .map(|(record, teams)| {
                    Ok(record.with_storage_property(
                        physical,
                        super::joins::raw_relation_value(
                            teams,
                            &team_fields,
                            relation.many,
                            O::Team::column,
                        )?,
                    ))
                })
                .collect::<AuthResult<Vec<_>>>()?;
        }
        let pages = if let Some(children) = children {
            let continuation = Arc::new((children, team_fields));
            let store = self.clone();
            membership_fields
                .organization_output_records_owned_batches_then(
                    records,
                    backend == DbBackend::Postgres,
                    |_, output| Ok(output),
                    move |ready| {
                        let continuation = continuation.clone();
                        let store = store.clone();
                        async move {
                            let (children, team_fields) = continuation.as_ref();
                            let pages = ready
                                .iter()
                                .map(|(index, _)| {
                                    children.get(*index).map(Vec::as_slice).ok_or_else(|| {
                                        AuthError::internal(
                                            "Team member projection lost its joined Team page",
                                        )
                                    })
                                })
                                .collect::<AuthResult<Vec<_>>>()?;
                            let record_fields = team_fields.clone();
                            let runtime = store.model_fields.clone();
                            let output = super::joins::project_child_pages(
                                team_fields,
                                pages,
                                backend,
                                &move |row: &SqlRow| {
                                    row.native_record(&record_fields, backend, O::Team::column)
                                        .map(|record| {
                                            record.with_id_output(&runtime, EntityRole::Team)
                                        })
                                },
                            )
                            .await?;
                            Ok(ready
                                .into_iter()
                                .zip(output)
                                .map(|((index, _), page)| (index, page))
                                .collect())
                        }
                    },
                )
                .await?
        } else {
            let continuation = Arc::new((
                relation.clone(),
                membership_fields.clone(),
                team_fields,
                runtime,
            ));
            let store = self.clone();
            membership_fields
                .organization_output_records_owned_then(
                    records,
                    backend == DbBackend::Postgres,
                    move |_, output| {
                        let continuation = continuation.clone();
                        let store = store.clone();
                        async move {
                            let (relation, membership_fields, team_fields, runtime) =
                                continuation.as_ref();
                            let field = relation.fallback_from(
                                (EntityRole::TeamMember, "teamMember", membership_fields),
                                runtime,
                            )?;
                            let value = output.get(&field).cloned().unwrap_or_default();
                            store
                                .selected_member_teams(relation, team_fields, value)
                                .await
                        }
                    },
                )
                .await?
        };
        pages
            .into_iter()
            .map(|page| Team::from_membership_join(page, relation.many))
            .collect()
    }

    async fn selected_member_teams(
        &self,
        relation: &ResolvedJoin,
        fields: &UserConfig,
        value: FieldValue,
    ) -> AuthResult<Vec<FieldMap>> {
        if value.is_null() || value.is_undefined() {
            return Ok(Vec::new());
        }
        let backend = self.connection().get_database_backend();
        let query = super::plugin_rows::select_all::<Entity<O::Team>>().filter(
            self.organization_field_equals::<O::Team>(EntityRole::Team, &relation.to, &value)?,
        );
        let rows = if relation.many {
            plugin_rows::all(
                self.connection(),
                query.limit(super::pagination::default_limit(self.config(), backend)?),
            )
            .await?
        } else {
            plugin_rows::one(self.connection(), query)
                .await?
                .into_iter()
                .collect()
        };
        let record_fields = fields.clone();
        let runtime = self.model_fields.clone();
        let mut pages = super::joins::project_child_pages(
            fields,
            vec![rows.as_slice()],
            backend,
            &move |row| {
                models::raw_record::<O::Team>(
                    row,
                    &record_fields,
                    backend,
                    (&runtime, EntityRole::Team),
                )
            },
        )
        .await?;
        Ok(pages.remove(0))
    }
}
