use better_auth_core::{
    AuthResult, FieldValue, ListUsersParams, WhereMode, WhereOperator,
    query::{validate_where_operand, where_operator},
    store::schema::EntityRole,
};
use sea_orm::{QueryFilter, QueryOrder, QuerySelect, Select};

use crate::{SeaOrmUserModel, schema::AuthSchema};

use super::super::{
    SeaOrmStore,
    instrumentation::database_operation,
    pagination, plugin_rows,
    value_filter::{self, BoundQueryField},
};

struct BoundUserFilter {
    field: BoundQueryField,
    operator: WhereOperator,
}

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
{
    fn bind_user_query(&self, params: &ListUsersParams) -> AuthResult<Vec<BoundUserFilter>> {
        let fields = self.field_policy().user();
        let backend = self.connection().get_database_backend();
        let bind = |name: &str,
                    value: &FieldValue,
                    operator: &str|
         -> AuthResult<BoundUserFilter> {
            let operator = where_operator(operator);
            validate_where_operand(operator, value)?;
            Ok(BoundUserFilter {
                field: self.bind_query_field(EntityRole::User, &fields, name, value, backend)?,
                operator,
            })
        };
        let mut bound = Vec::new();
        if let Some(value) = params
            .search_value
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            bound.push(bind(
                params
                    .search_field
                    .as_deref()
                    .filter(|field| !field.is_empty())
                    .unwrap_or("email"),
                &value.into(),
                params
                    .search_operator
                    .as_deref()
                    .filter(|operator| !operator.is_empty())
                    .unwrap_or("contains"),
            )?);
        }
        if let Some(value) = &params.filter_value {
            bound.push(bind(
                params
                    .filter_field
                    .as_deref()
                    .filter(|field| !field.is_empty())
                    .unwrap_or("email"),
                value,
                params
                    .filter_operator
                    .as_deref()
                    .filter(|operator| !operator.is_empty())
                    .unwrap_or("eq"),
            )?);
        }
        Ok(bound)
    }

    fn resolve_user_query(
        &self,
        bound: Vec<BoundUserFilter>,
        sort: Option<&ListUsersParams>,
    ) -> AuthResult<Select<<S::User as SeaOrmUserModel>::Entity>> {
        let fields = self.field_policy().user();
        let bound = bound
            .into_iter()
            .map(|bound| {
                let (column, value) = bound.field.resolve(EntityRole::User, &fields)?;
                Ok((S::User::field_column(&column)?, bound.operator, value))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        let mut query = plugin_rows::select_all::<<S::User as SeaOrmUserModel>::Entity>();
        if let Some(params) = sort
            && let Some(field) = params.sort_by.as_deref().filter(|field| !field.is_empty())
        {
            let fields = self
                .model_fields
                .runtime_fields(EntityRole::User, &fields)?;
            let (_, column) = value_filter::query_field_name(EntityRole::User, &fields, field)?;
            let column = S::User::field_column(column)?;
            query = if params.sort_direction.as_deref() == Some("desc") {
                query.order_by_desc(column)
            } else {
                query.order_by_asc(column)
            };
        }
        Ok(query.filter(value_filter::all(
            bound.into_iter().map(|(column, operator, value)| {
                value_filter::QueryPredicate::new(column, operator, WhereMode::Sensitive, value)
            }),
            self.connection().get_database_backend(),
        )?))
    }

    pub(super) async fn user_query_page(
        &self,
        params: &ListUsersParams,
    ) -> AuthResult<Vec<plugin_rows::SqlRow>> {
        let bound = self.bind_user_query(params)?;
        database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
            self.config(),
            "findMany",
            async {
                let mut query = self.resolve_user_query(bound, Some(params))?;
                let (limit, offset) = pagination::sql_pagination(
                    self.connection().get_database_backend(),
                    Some(
                        params
                            .limit
                            .unwrap_or(self.config().advanced.database.find_many_limit()),
                    ),
                    params.offset,
                )?;
                let unbounded_offset = if limit.is_none() {
                    offset.unwrap_or(0)
                } else {
                    0
                };
                if let Some(limit) = limit {
                    query = query.limit(limit);
                    if let Some(offset) = offset {
                        query = query.offset(offset);
                    }
                }
                let rows = plugin_rows::all(self.connection(), query).await?;
                let skip = std::cmp::min(unbounded_offset, rows.len() as u64) as usize;
                Ok(rows.into_iter().skip(skip).collect())
            },
        )
        .await
    }

    pub(super) async fn user_query_count(&self, params: &ListUsersParams) -> AuthResult<usize> {
        let bound = self.bind_user_query(params)?;
        database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
            self.config(),
            "count",
            async {
                plugin_rows::count(self.connection(), self.resolve_user_query(bound, None)?)
                    .await
                    .map(|count| count as usize)
            },
        )
        .await
    }
}
