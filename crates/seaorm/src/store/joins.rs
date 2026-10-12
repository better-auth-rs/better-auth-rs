use sea_orm::{
    ConnectionTrait, DbBackend, EntityTrait, IdenStatic, QueryTrait, Select,
    sea_query::{Asterisk, Expr, ExprTrait, JoinType, Query, SelectStatement},
};

use crate::error::AuthResult;
use better_auth_core::{
    FieldMap, FieldValue,
    store::JoinValue,
    store::schema::resolve_field_name,
    user_fields::{AdapterRecord, UserConfig, UserFieldConfig},
};
use std::sync::Arc;

const PARENT: &str = "_auth_parent";
const CHILD: &str = "_auth_child";
use super::plugin_rows::SqlRow;

pub(super) struct ChildSelection {
    prefix: String,
    alternate_prefix: String,
    columns: Vec<String>,
}

impl ChildSelection {
    pub(super) fn aliases(&self) -> impl Iterator<Item = String> + '_ {
        self.columns.iter().flat_map(|column| {
            [
                format!("{}{column}", self.prefix),
                format!("{}{}", self.alternate_prefix, capitalize_first_unit(column)),
            ]
        })
    }

    pub(super) fn read(&self, row: &SqlRow) -> AuthResult<Option<SqlRow>> {
        let child = row.prefixed(&self.prefix);
        for column in &self.columns {
            if !child.is_nullish(column)? {
                return Ok(Some(child));
            }
        }
        Ok(None)
    }
}

pub(super) struct NativeJoinQuery {
    query: SelectStatement,
    parent_id: String,
    child: ChildSelection,
}

fn capitalize_first_unit(value: &str) -> String {
    let mut chars = value.chars();
    chars.next().map_or_else(String::new, |first| {
        // JavaScript uppercases one UTF-16 unit; a leading surrogate remains unchanged.
        if first.len_utf16() == 2 {
            value.to_owned()
        } else {
            first.to_uppercase().chain(chars).collect()
        }
    })
}

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
        if !key.is_truthy() || !ids.contains(&key) {
            ids.push(key);
            selected.push(row);
        }
    }
    Ok(selected)
}

type ChildPagesFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = AuthResult<Vec<Vec<FieldMap>>>> + Send + 'a>,
>;

pub(super) fn project_child_pages<M: Clone + Send + Sync + 'static, F>(
    fields: &UserConfig,
    pages: Vec<&[M]>,
    backend: sea_orm::DbBackend,
    record: &F,
) -> ChildPagesFuture<'static>
where
    F: Fn(&M) -> AuthResult<AdapterRecord> + Clone + Send + Sync + 'static,
{
    project_owned_child_pages(
        Arc::new(fields.clone()),
        pages.into_iter().map(|page| (Arc::from(page), 0)).collect(),
        backend,
        Arc::new(record.clone()),
    )
}

fn project_owned_child_pages<M: Send + Sync + 'static, F>(
    fields: Arc<UserConfig>,
    pages: Vec<(Arc<[M]>, usize)>,
    backend: sea_orm::DbBackend,
    record: Arc<F>,
) -> ChildPagesFuture<'static>
where
    F: Fn(&M) -> AuthResult<AdapterRecord> + Send + Sync + 'static,
{
    Box::pin(async move {
        let mut output: Vec<Vec<FieldMap>> = pages.iter().map(|_| Vec::new()).collect();
        let mut active = Vec::new();
        let mut records = Vec::new();
        for (index, (page, position)) in pages.into_iter().enumerate() {
            if let Some(first) = page.get(position) {
                records.push(record(first)?);
                active.push((index, (page, position + 1)));
            }
        }
        if records.is_empty() {
            return Ok(output);
        }
        let active = Arc::new(active);
        let continuation = (active.clone(), fields.clone());
        let projected = fields
            .project_adapter_records_owned_batches_then(
                records,
                backend == sea_orm::DbBackend::Postgres,
                backend != sea_orm::DbBackend::Sqlite,
                move |ready| {
                    let (active, fields) = continuation.clone();
                    let record = record.clone();
                    async move {
                        let tails = ready
                            .iter()
                            .map(|(index, _)| {
                                active
                                    .get(*index)
                                    .map(|(_, tail)| tail.clone())
                                    .ok_or_else(|| {
                                        crate::error::AuthError::internal(
                                            "Child projection lost its parent page",
                                        )
                                    })
                            })
                            .collect::<AuthResult<Vec<_>>>()?;
                        // Ready parents advance together; each page completes one child at a time.
                        let remaining =
                            project_owned_child_pages(fields.clone(), tails, backend, record)
                                .await?;
                        Ok(ready
                            .into_iter()
                            .zip(remaining)
                            .map(|((index, first), mut rest)| {
                                rest.insert(0, super::plugin_rows::ordered_output(&fields, first));
                                (index, rest)
                            })
                            .collect())
                    }
                },
            )
            .await?;
        for ((index, _), page) in active.iter().zip(projected) {
            *output.get_mut(*index).ok_or_else(|| {
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

pub(super) fn raw_relation_value<C: IdenStatic>(
    rows: &[SqlRow],
    fields: &UserConfig,
    many: bool,
    column: impl Fn(&str) -> AuthResult<C>,
) -> AuthResult<FieldValue> {
    let mut values = rows
        .iter()
        .map(|row| row.native_object(fields, &column).map(FieldValue::Object))
        .collect::<AuthResult<Vec<_>>>()?;
    Ok(if many {
        values.into()
    } else {
        values.pop().unwrap_or(FieldValue::Null)
    })
}

pub(super) fn joined_query<P: EntityTrait, C: EntityTrait>(
    backend: DbBackend,
    parent: (Select<P>, P::Column),
    on: (P::Column, C::Column),
    child_fields: &UserConfig,
    column: impl Fn(&str) -> AuthResult<C::Column>,
) -> AuthResult<NativeJoinQuery> {
    let model = C::default();
    let child_model = if backend == DbBackend::MySql {
        mysql_join_model_name(model.table_name())
    } else {
        model.table_name()
    };
    let (mut query, parent_alias, child_alias) = if backend == DbBackend::MySql {
        (
            super::query_compile::find_query(parent.0.into_query()),
            "primary",
            format!("join_{child_model}"),
        )
    } else {
        let mut query = Query::select();
        let _ = query
            .from_subquery(parent.0.into_query(), PARENT)
            .expr(Expr::col((PARENT, Asterisk)));
        (query, PARENT, CHILD.to_owned())
    };
    let condition = if backend == DbBackend::MySql {
        Expr::col((child_alias.clone(), on.1)).equals((parent_alias, on.0))
    } else {
        Expr::col((parent_alias, on.0)).equals((child_alias.clone(), on.1))
    };
    let _ = query.join_as(
        JoinType::LeftJoin,
        model.table_ref(),
        child_alias.clone(),
        condition,
    );
    let child = select_child_fields(&mut query, &child_alias, child_model, child_fields, column)?;
    Ok(NativeJoinQuery {
        query,
        parent_id: parent.1.as_str().to_owned(),
        child,
    })
}

pub(super) fn mysql_join_model_name(model: &str) -> &str {
    model.split('.').nth(1).unwrap_or(model)
}

pub(super) fn native_parent(
    row: &SqlRow,
    parent_id: &str,
    child_aliases: impl IntoIterator<Item = String>,
) -> AuthResult<Option<SqlRow>> {
    let parent = row.without_columns(child_aliases);
    // Kysely discards falsy raw parent IDs after SQL pagination and before output callbacks.
    Ok(parent.value(parent_id)?.is_truthy().then_some(parent))
}

pub(super) fn select_child_fields<C: IdenStatic>(
    query: &mut SelectStatement,
    table: &str,
    model: &str,
    fields: &UserConfig,
    column: impl Fn(&str) -> AuthResult<C>,
) -> AuthResult<ChildSelection> {
    let model = model.rsplit('.').next().unwrap_or(model);
    let prefix = format!("_joined_{model}_");
    let mut columns = Vec::new();
    for (name, field) in fields.fields() {
        let column = column(resolve_field_name(field.field_name.as_deref(), name))?;
        let alias = format!("{prefix}{}", column.as_str());
        let _ = query.expr_as(Expr::col((table.to_owned(), column)), alias);
        columns.push(column.as_str().to_owned());
    }
    Ok(ChildSelection {
        prefix,
        alternate_prefix: format!("_Joined{}", capitalize_first_unit(model)),
        columns,
    })
}

pub(super) async fn joined_raw_rows(
    db: &impl ConnectionTrait,
    query: &NativeJoinQuery,
) -> AuthResult<Vec<(SqlRow, Option<SqlRow>)>> {
    let rows = db
        .query_all_raw(super::query_compile::build(
            db.get_database_backend(),
            &query.query,
        )?)
        .await
        .map_err(super::map_db_err)?;
    let mut selected = Vec::new();
    for row in rows {
        let row = SqlRow::from(row);
        if let Some(parent) = native_parent(&row, &query.parent_id, query.child.aliases())? {
            selected.push((parent, query.child.read(&row)?));
        }
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::user_fields::{FieldTransforms, UserFieldTransform};
    use sea_orm::Database;
    use std::sync::{Arc, Mutex};

    #[test]
    fn reserved_child_aliases_capitalize_only_the_first_utf16_unit() {
        let selection = ChildSelection {
            prefix: "_joined_team_member_".into(),
            alternate_prefix: "_JoinedTeam_member".into(),
            columns: vec!["team_id".into(), "ßeta".into(), "𐐨name".into()],
        };
        assert_eq!(
            selection.aliases().collect::<Vec<_>>(),
            [
                "_joined_team_member_team_id",
                "_JoinedTeam_memberTeam_id",
                "_joined_team_member_ßeta",
                "_JoinedTeam_memberSSeta",
                "_joined_team_member_𐐨name",
                "_JoinedTeam_member𐐨name",
            ]
        );
    }

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

    #[tokio::test]
    async fn child_presence_uses_every_selected_column() -> AuthResult<()> {
        let db = Database::connect("sqlite::memory:")
            .await
            .map_err(super::super::map_db_err)?;
        let selection = ChildSelection {
            prefix: "_joined_child_".into(),
            alternate_prefix: "_JoinedChild".into(),
            columns: vec!["id".into(), "name".into()],
        };
        for present in [false, true] {
            let mut query = Query::select();
            let _ = query
                .expr_as(Expr::val(Option::<String>::None), "_joined_child_id")
                .expr_as(Expr::val(present.then_some(0)), "_joined_child_name");
            let row = db
                .query_one(&query)
                .await
                .map_err(super::super::map_db_err)?
                .ok_or_else(|| {
                    crate::error::AuthError::internal("Presence query returned no row")
                })?;
            let child = selection.read(&SqlRow::from(row))?;
            if present {
                assert_eq!(
                    child.map(|row| row.value("name")).transpose()?,
                    Some(0.into())
                );
            } else {
                assert!(child.is_none());
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn child_presence_does_not_decode_values_before_selection() -> AuthResult<()> {
        let db = Database::connect("sqlite::memory:")
            .await
            .map_err(super::super::map_db_err)?;
        let mut query = Query::select();
        let _ = query
            .expr_as(Expr::val(Option::<String>::None), "_joined_child_id")
            .expr_as(Expr::cust("X'01'"), "_joined_child_name");
        let row = db
            .query_one(&query)
            .await
            .map_err(super::super::map_db_err)?
            .ok_or_else(|| crate::error::AuthError::internal("Presence query returned no row"))?;
        let selection = ChildSelection {
            prefix: "_joined_child_".into(),
            alternate_prefix: "_JoinedChild".into(),
            columns: vec!["id".into(), "name".into()],
        };
        let child = selection
            .read(&SqlRow::from(row))?
            .ok_or_else(|| crate::error::AuthError::internal("A non-null BLOB must be present"))?;
        assert!(child.value("name").is_err_and(|error| {
            error
                .to_string()
                .contains("unsupported SQLite storage type BLOB")
        }));
        Ok(())
    }
}
