use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, FromQueryResult, IdenStatic, Iterable, ModelTrait,
    QueryTrait, Select,
    sea_query::{Expr, ExprTrait, JoinType, Query, SelectStatement},
};

use crate::error::AuthResult;
use better_auth_core::{
    FieldMap, FieldValue,
    store::schema::resolve_field_name,
    user_fields::{UserConfig, UserFieldConfig},
};

const PARENT: &str = "_auth_parent";
const CHILD: &str = "_auth_child";
const CHILD_PRESENT: &str = "_auth_child_present";

pub(super) fn native_child_fields(
    fields: &UserConfig,
    mut read: impl FnMut(&str, &UserFieldConfig) -> AuthResult<FieldValue>,
) -> AuthResult<FieldMap> {
    let mut selected = FieldMap::new();
    for (name, field) in fields.fields() {
        let physical = resolve_field_name(field.field_name.as_deref(), name);
        if !selected.contains_key(physical) {
            let _ = selected.insert(physical.to_owned(), read(physical, field)?);
        }
    }
    let mut output = FieldMap::new();
    // Kysely remaps selected physical names into a new child object; later columns overwrite aliases.
    for (physical, value) in selected {
        let logical = if physical == "_id" { "id" } else { &physical };
        let mapped = fields.fields().get(logical).map_or(logical, |field| {
            resolve_field_name(field.field_name.as_deref(), logical)
        });
        let _ = output.insert(mapped.to_owned(), value);
    }
    Ok(output)
}

// Current core callers have no sort. An ordered caller must order both query levels explicitly.
pub(super) fn joined_query<P: EntityTrait, C: EntityTrait>(
    parent: Select<P>,
    on: (P::Column, C::Column),
    child_id: C::Column,
) -> SelectStatement {
    let mut parent = parent.into_query();
    // Keep the parent page intact. Apply model-specific select casts only in the outer query.
    let _ = parent.clear_selects();
    for column in P::Column::iter() {
        let _ = parent.expr(Expr::col(column.as_column_ref()));
    }
    let mut query = Query::select();
    let _ = query.from_subquery(parent, PARENT).join_as(
        JoinType::LeftJoin,
        C::default().table_ref(),
        CHILD,
        Expr::col((PARENT, on.0)).equals((CHILD, on.1)),
    );
    select_model::<P>(&mut query, PARENT, "A_");
    select_model::<C>(&mut query, CHILD, "B_");
    let _ = query.expr_as(Expr::col((CHILD, child_id)).is_not_null(), CHILD_PRESENT);
    query
}

pub(super) fn select_model<E: EntityTrait>(
    query: &mut SelectStatement,
    table: &'static str,
    prefix: &str,
) {
    for column in E::Column::iter() {
        let _ = query.expr_as(
            column.select_as(Expr::col((table, column))),
            format!("{prefix}{}", column.as_str()),
        );
    }
}

pub(super) fn limited_children<E: EntityTrait>(
    rows: impl Iterator<Item = E::Model>,
    id: E::Column,
    limit: f64,
) -> Vec<E::Model> {
    // Kysely caps the assembled child array with slice, not a SQL LIMIT.
    let limit = limit as usize;
    let mut selected = Vec::new();
    let mut ids = Vec::new();
    for row in rows {
        if selected.len() >= limit {
            break;
        }
        let id = row.get(id);
        if !ids.contains(&id) {
            ids.push(id);
            selected.push(row);
        }
    }
    selected
}

pub(super) fn optional_model<M: FromQueryResult>(
    row: &sea_orm::QueryResult,
    prefix: &str,
    presence_column: &str,
) -> AuthResult<Option<M>> {
    // SeaORM's optional decoder discards decode errors. Only SQL NULL means no child.
    if row
        .try_get::<bool>("", presence_column)
        .map_err(super::map_db_err)?
    {
        M::from_query_result(row, prefix)
            .map(Some)
            .map_err(super::map_db_err)
    } else {
        Ok(None)
    }
}

pub(super) async fn joined_rows<P: EntityTrait, C: EntityTrait>(
    db: &impl ConnectionTrait,
    query: &SelectStatement,
) -> AuthResult<Vec<(P::Model, Option<C::Model>)>> {
    db.query_all(query)
        .await
        .map_err(super::map_db_err)?
        .iter()
        .map(|row| {
            let parent = P::Model::from_query_result(row, "A_").map_err(super::map_db_err)?;
            let child = optional_model::<C::Model>(row, "B_", CHILD_PRESENT)?;
            Ok((parent, child))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{Database, DbErr, QueryResult};

    #[derive(Debug)]
    struct DisplayDecodeFailure;

    impl FromQueryResult for DisplayDecodeFailure {
        fn from_query_result(_row: &QueryResult, _prefix: &str) -> Result<Self, DbErr> {
            Err(DbErr::Custom("Ordinary display decoder failed".into()))
        }
    }

    #[tokio::test]
    async fn optional_child_distinguishes_absence_from_decode_failure() -> AuthResult<()> {
        let db = Database::connect("sqlite::memory:")
            .await
            .map_err(super::super::map_db_err)?;
        for present in [false, true] {
            let mut query = Query::select();
            let _ = query.expr_as(Expr::val(present), CHILD_PRESENT);
            let row = db
                .query_one(&query)
                .await
                .map_err(super::super::map_db_err)?
                .ok_or_else(|| {
                    crate::error::AuthError::internal("Presence query returned no row")
                })?;
            let result = optional_model::<DisplayDecodeFailure>(&row, "B_", CHILD_PRESENT);
            if present {
                assert!(result.is_err_and(|error| {
                    error
                        .to_string()
                        .contains("Ordinary display decoder failed")
                }));
            } else {
                assert!(matches!(result, Ok(None)));
            }
        }
        Ok(())
    }
}
