use super::{
    SeaOrmStore,
    instrumentation::database_operation,
    organization_models::{self as models, Entity},
    plugin_rows::{self, SqlRow},
};
use crate::{
    SeaOrmOrganizationModel, SeaOrmOrganizationSchema, SeaOrmPluginSchema, SeaOrmUserModel,
    schema::AuthSchema,
};
use better_auth_core::{
    AuthResult, FieldMap, FieldValue,
    plugin_runtime::ModelFields,
    store::{
        JoinValue, OrganizationDetails, OrganizationDetailsQuery, OrganizationKey, ResolvedJoin,
        schema::EntityRole,
    },
    user_fields::UserConfig,
};
use sea_orm::{DbBackend, QueryFilter, QuerySelect};

mod consumption;
mod native;

struct DetailRelation {
    role: EntityRole,
    model: &'static str,
    fields: UserConfig,
    join: ResolvedJoin,
    limit: f64,
}

struct DetailRelations {
    invitations: DetailRelation,
    members: DetailRelation,
    teams: Option<DetailRelation>,
}

struct DetailChildren {
    invitations: Vec<SqlRow>,
    members: Vec<SqlRow>,
    teams: Option<Vec<SqlRow>>,
}

impl<S: AuthSchema, O: SeaOrmOrganizationSchema, P: SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S::User: SeaOrmUserModel,
    S::Session: crate::SeaOrmSessionModel,
    S::Account: crate::SeaOrmAccountModel,
    S::Verification: crate::SeaOrmVerificationModel,
{
    pub(super) async fn read_organization_details(
        &self,
        input: OrganizationDetailsQuery<'_>,
    ) -> AuthResult<Option<OrganizationDetails>> {
        let fields = self
            .organization_query_schema(EntityRole::Organization)?
            .adapter_fields(&[]);
        let backend = self.connection().get_database_backend();
        let (name, value) = match input.organization {
            OrganizationKey::Id(value) => ("id", value.into()),
            OrganizationKey::IdValue(value) => ("id", value.clone()),
            OrganizationKey::Slug(value) => ("slug", value.into()),
        };
        let predicate = self.organization_field_equals::<O::Organization>(
            EntityRole::Organization,
            name,
            &value,
        )?;
        let runtime = self.model_fields.organization_join_schema();
        let default_limit = self.config().advanced.database.find_many_limit();
        let relation = |role, model, limit| -> AuthResult<DetailRelation> {
            let child_fields = self.organization_query_schema(role)?.adapter_fields(&[]);
            let join = ResolvedJoin::resolve(
                (EntityRole::Organization, "organization", &fields),
                (role, model, &child_fields),
                &runtime,
                super::model_names::table_matches::<S, O, P>,
            )?;
            Ok(DetailRelation {
                role,
                model,
                fields: child_fields,
                join,
                limit,
            })
        };
        let relations = DetailRelations {
            invitations: relation(EntityRole::Invitation, "invitation", default_limit)?,
            members: relation(
                EntityRole::Member,
                "member",
                input.members_limit.unwrap_or(default_limit),
            )?,
            teams: input
                .include_teams
                .then(|| relation(EntityRole::Team, "team", default_limit))
                .transpose()?,
        };
        let query = super::plugin_rows::select_all::<Entity<O::Organization>>()
            .filter(predicate)
            .limit((backend != DbBackend::MySql).then_some(1));
        let selected = if self.config().advanced.database.joins == Some(true) {
            self.select_native_organization_details(query, &relations)
                .await?
                .map(|(row, children)| (row, Some(children)))
        } else {
            database_operation::<Entity<O::Organization>, _>(
                self.config(),
                "findOne",
                plugin_rows::one(self.connection(), query),
            )
            .await?
            .map(|row| (row, None))
        };
        let Some((organization, children)) = selected else {
            return Ok(None);
        };
        let record = models::raw_record::<O::Organization>(
            &organization,
            &fields,
            backend,
            (&self.model_fields, EntityRole::Organization),
        )?;
        let record = if let Some(children) = &children {
            self.native_detail_record(record, &relations, children)?
        } else {
            record
        };
        let mut parent = fields
            .organization_output_records(vec![record], backend == DbBackend::Postgres)
            .await?
            .remove(0);
        let (invitations, members, teams) = match children {
            Some(children) => (
                Some(children.invitations),
                Some(children.members),
                children.teams,
            ),
            None => (None, None, None),
        };
        let invitations = self
            .project_detail_relation::<O::Invitation>(
                &mut parent,
                &fields,
                &runtime,
                &relations.invitations,
                invitations,
            )
            .await?;
        let members = self
            .project_detail_relation::<O::Member>(
                &mut parent,
                &fields,
                &runtime,
                &relations.members,
                members,
            )
            .await?;
        let teams = if let Some(relation) = &relations.teams {
            Some(
                self.project_detail_relation::<O::Team>(
                    &mut parent,
                    &fields,
                    &runtime,
                    relation,
                    teams,
                )
                .await?,
            )
        } else {
            None
        };
        self.consume_organization_details(parent, invitations, members, teams, input.users_limit)
            .await
            .map(Some)
    }

    async fn project_detail_relation<M: SeaOrmOrganizationModel>(
        &self,
        parent: &mut FieldMap,
        parent_fields: &UserConfig,
        runtime: &ModelFields,
        relation: &DetailRelation,
        selected: Option<Vec<SqlRow>>,
    ) -> AuthResult<JoinValue<FieldMap>> {
        let native = selected.is_some();
        let rows = if let Some(rows) = selected {
            rows
        } else {
            let from = relation.join.fallback_from(
                (EntityRole::Organization, "organization", parent_fields),
                runtime,
            )?;
            let value = parent.get(&from).cloned().unwrap_or_default();
            self.select_detail_relation::<M>(relation, value).await?
        };
        let backend = self.connection().get_database_backend();
        let record_fields = relation.fields.clone();
        let record_runtime = self.model_fields.clone();
        let role = relation.role;
        let mut pages = super::joins::project_child_pages(
            &relation.fields,
            vec![rows.as_slice()],
            backend,
            &move |row: &SqlRow| {
                if native {
                    row.native_record(&record_fields, backend, M::column)
                        .map(|record| record.with_id_output(&record_runtime, role))
                } else {
                    models::raw_record::<M>(row, &record_fields, backend, (&record_runtime, role))
                }
            },
        )
        .await?;
        let result = super::joins::relation_value(relation.join.many, pages.remove(0));
        let value = match &result {
            JoinValue::One(row) => row.clone().map_or(FieldValue::Null, FieldValue::from),
            JoinValue::Many(rows) => rows
                .iter()
                .cloned()
                .map(FieldValue::from)
                .collect::<Vec<_>>()
                .into(),
        };
        // A later fallback relationship reads the parent's preceding projected relationships.
        let _ = parent.insert(relation.model.into(), value);
        Ok(result)
    }

    async fn select_detail_relation<M: SeaOrmOrganizationModel>(
        &self,
        relation: &DetailRelation,
        value: FieldValue,
    ) -> AuthResult<Vec<SqlRow>> {
        if value.is_null() || value.is_undefined() {
            return Ok(Vec::new());
        }
        let bound = self.bind_organization_query_field(relation.role, &relation.join.to, &value)?;
        let backend = self.connection().get_database_backend();
        database_operation::<Entity<M>, _>(
            self.config(),
            if relation.join.many {
                "findMany"
            } else {
                "findOne"
            },
            async {
                let (column, value) =
                    self.resolve_organization_query_field::<M>(relation.role, bound)?;
                let query = super::plugin_rows::select_all::<Entity<M>>()
                    .filter(super::value_filter::equals(column, &value, backend)?);
                if relation.join.many {
                    let (limit, _) =
                        super::pagination::sql_pagination(backend, Some(relation.limit), None)?;
                    plugin_rows::all(self.connection(), query.limit(limit)).await
                } else {
                    plugin_rows::one(self.connection(), query)
                        .await
                        .map(|row| row.into_iter().collect())
                }
            },
        )
        .await
    }
}
