use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, FromQueryResult, IdenStatic, Iterable, ModelTrait,
    QueryTrait, Select,
    sea_query::{Expr, ExprTrait, JoinType, Query, SelectStatement},
};

use crate::error::AuthResult;
use better_auth_core::{
    FieldMap, FieldValue,
    store::JoinValue,
    store::schema::resolve_field_name,
    user_fields::{AdapterRecord, UserConfig, UserFieldConfig},
};

const PARENT: &str = "_auth_parent";
const CHILD: &str = "_auth_child";
const CHILD_PRESENT: &str = "_auth_child_present";

use super::plugin_rows::SqlRow;

pub(super) fn relation_value<T>(many: bool, mut rows: Vec<T>) -> JoinValue<T> {
    if many {
        JoinValue::Many(rows)
    } else {
        JoinValue::One(rows.pop())
    }
}

fn grouped_by_key<P, C, K: PartialEq>(
    rows: impl Iterator<Item = (K, P, Option<C>)>,
) -> Vec<(P, Vec<C>)> {
    let mut groups: Vec<(K, P, Vec<C>)> = Vec::new();
    for (id, parent, child) in rows {
        if let Some((_, _, children)) = groups.iter_mut().find(|(stored, _, _)| *stored == id) {
            children.extend(child);
        } else {
            groups.push((id, parent, child.into_iter().collect()));
        }
    }
    groups
        .into_iter()
        .map(|(_, parent, children)| (parent, children))
        .collect()
}

pub(super) fn grouped_raw_rows(
    rows: Vec<(SqlRow, Option<SqlRow>)>,
    parent_id: impl IdenStatic,
) -> AuthResult<Vec<(SqlRow, Vec<SqlRow>)>> {
    let rows = rows
        .into_iter()
        .map(|(parent, child)| Ok((parent.value(parent_id.as_str())?, parent, child)))
        .collect::<AuthResult<Vec<_>>>()?;
    Ok(grouped_by_key(rows.into_iter()))
}

pub(super) fn selected_raw_children(
    rows: impl Iterator<Item = SqlRow>,
    id: impl IdenStatic,
    many: bool,
    limit: f64,
) -> AuthResult<Vec<SqlRow>> {
    if !many {
        // Kysely overwrites a singular relationship for every matching SQL row.
        return Ok(rows.last().into_iter().collect());
    }
    let mut selected = Vec::new();
    let mut ids = Vec::new();
    for row in rows {
        if selected.len() >= limit as usize {
            break;
        }
        let key = row.value(id.as_str())?;
        if !ids.contains(&key) {
            ids.push(key);
            selected.push(row);
        }
    }
    Ok(selected)
}

type ChildPagesFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = AuthResult<Vec<Vec<FieldMap>>>> + Send + 'a>,
>;

pub(super) fn project_child_pages<'a, M: Sync, F>(
    fields: &'a UserConfig,
    pages: Vec<&'a [M]>,
    backend: sea_orm::DbBackend,
    record: &'a F,
) -> ChildPagesFuture<'a>
where
    F: Fn(&M) -> AuthResult<AdapterRecord> + Sync,
{
    Box::pin(async move {
        let mut output: Vec<Vec<FieldMap>> = pages.iter().map(|_| Vec::new()).collect();
        let mut active = Vec::new();
        let mut records = Vec::new();
        for (index, page) in pages.into_iter().enumerate() {
            if let Some((first, rest)) = page.split_first() {
                active.push((index, rest));
                records.push(record(first)?);
            }
        }
        if records.is_empty() {
            return Ok(output);
        }
        let projected = fields
            .project_adapter_records_batches_then(
                records,
                backend == sea_orm::DbBackend::Postgres,
                backend != sea_orm::DbBackend::Sqlite,
                |ready| {
                    let active = &active;
                    async move {
                        let tails = ready
                            .iter()
                            .map(|(index, _)| {
                                active.get(*index).map(|(_, tail)| *tail).ok_or_else(|| {
                                    crate::error::AuthError::internal(
                                        "Child projection lost its parent page",
                                    )
                                })
                            })
                            .collect::<AuthResult<Vec<_>>>()?;
                        // Ready parents advance together; each page completes one child at a time.
                        let remaining = project_child_pages(fields, tails, backend, record).await?;
                        Ok(ready
                            .into_iter()
                            .zip(remaining)
                            .map(|((index, first), mut rest)| {
                                rest.insert(0, first);
                                (index, rest)
                            })
                            .collect())
                    }
                },
            )
            .await?;
        for ((index, _), page) in active.into_iter().zip(projected) {
            *output.get_mut(index).ok_or_else(|| {
                crate::error::AuthError::internal("Child projection lost its result page")
            })? = page;
        }
        Ok(output)
    })
}

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
    limited_by_key(rows.map(|row| (row.get(id), row)), limit)
}

fn limited_by_key<T, K: PartialEq>(rows: impl Iterator<Item = (K, T)>, limit: f64) -> Vec<T> {
    // Kysely caps the assembled child array with slice, not a SQL LIMIT.
    let limit = limit as usize;
    let mut selected = Vec::new();
    let mut ids = Vec::new();
    for (id, row) in rows {
        if selected.len() >= limit {
            break;
        }
        if !ids.contains(&id) {
            ids.push(id);
            selected.push(row);
        }
    }
    selected
}

pub(super) async fn joined_raw_rows(
    db: &impl ConnectionTrait,
    query: &SelectStatement,
) -> AuthResult<Vec<(SqlRow, Option<SqlRow>)>> {
    db.query_all(query)
        .await
        .map_err(super::map_db_err)?
        .into_iter()
        .map(|row| {
            let present = row
                .try_get::<bool>("", CHILD_PRESENT)
                .map_err(super::map_db_err)?;
            let row = SqlRow::from(row);
            Ok((row.prefixed("A_"), present.then(|| row.prefixed("B_"))))
        })
        .collect()
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
    use better_auth_core::user_fields::{FieldTransforms, UserFieldTransform};
    use sea_orm::{Database, DbErr, QueryResult};
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn native_child_pages_advance_ready_parents_without_reordering_children() -> AuthResult<()>
    {
        let events = Arc::new(Mutex::new(Vec::new()));
        let release = Arc::new(tokio::sync::Notify::new());
        let mut fields = UserConfig::default();
        for phase in ["alpha", "beta"] {
            let events = events.clone();
            let release = release.clone();
            let _ = fields.fields_mut().insert(
                phase.into(),
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        output: Some(UserFieldTransform::new_async(move |value| {
                            let events = events.clone();
                            let release = release.clone();
                            async move {
                                let name = value.as_str().ok_or_else(|| {
                                    crate::error::AuthError::internal("Child name is not a string")
                                })?;
                                if phase == "alpha" && name == "slow-1" {
                                    release.notified().await;
                                }
                                events
                                    .lock()
                                    .map_err(|_| {
                                        crate::error::AuthError::internal(
                                            "Child event lock poisoned",
                                        )
                                    })?
                                    .push(format!("{phase}:{name}"));
                                if phase == "beta" && name == "fast-2" {
                                    release.notify_one();
                                }
                                Ok(value)
                            }
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
        }
        let row = |name: &str| {
            FieldMap::from([("alpha".into(), name.into()), ("beta".into(), name.into())])
        };
        let slow = [row("slow-1"), row("slow-2")];
        let fast = [row("fast-1"), row("fast-2")];
        let projected = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            project_child_pages(
                &fields,
                vec![&[], &slow, &fast],
                sea_orm::DbBackend::Sqlite,
                &|row: &FieldMap| Ok(AdapterRecord::new(FieldMap::new(), row.clone())),
            ),
        )
        .await
        .map_err(|_| {
            crate::error::AuthError::internal(
                "A ready parent waited for an unfinished peer instead of advancing its child page",
            )
        })??;
        assert_eq!(projected, vec![Vec::new(), slow.to_vec(), fast.to_vec()]);
        let events = events
            .lock()
            .map_err(|_| crate::error::AuthError::internal("Child event lock poisoned"))?;
        assert_eq!(events.len(), 8);
        let position = |event: &str| {
            events
                .iter()
                .position(|value| value == event)
                .ok_or_else(|| {
                    crate::error::AuthError::internal(format!("Missing child event: {event}"))
                })
        };
        assert!(position("beta:fast-1")? < position("alpha:fast-2")?);
        assert!(position("beta:fast-2")? < position("alpha:slow-1")?);
        assert!(position("beta:slow-1")? < position("alpha:slow-2")?);
        Ok(())
    }

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
