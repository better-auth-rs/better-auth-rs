use super::UserFieldConfig;
use crate::AuthResult;
use futures_util::{
    StreamExt,
    future::BoxFuture,
    stream::{self, FuturesUnordered},
};
use indexmap::IndexMap;
use std::future::Future;

pub(crate) async fn project_fields<T: Send>(
    rows: &mut [T],
    fields: &IndexMap<String, UserFieldConfig>,
    project: impl for<'a> Fn(&'a mut T, &'a str, &'a UserFieldConfig) -> BoxFuture<'a, AuthResult<()>>
    + Sync,
) -> AuthResult<()> {
    project_fields_then(rows, fields, project, |_, _| std::future::ready(Ok(())))
        .await
        .map(|_| ())
}

pub(crate) async fn project_fields_then<T: Send, R: Send, F>(
    rows: &mut [T],
    fields: &IndexMap<String, UserFieldConfig>,
    project: impl for<'a> Fn(&'a mut T, &'a str, &'a UserFieldConfig) -> BoxFuture<'a, AuthResult<()>>
    + Sync,
    complete: impl Fn(usize, &mut T) -> F + Sync,
) -> AuthResult<Vec<R>>
where
    F: Future<Output = AuthResult<R>> + Send,
{
    let (mut first_error, mut pending) = projection_tasks(rows, fields, &project, &complete).await;
    let mut completed = Vec::new();
    while let Some(result) = pending.next().await {
        match result {
            Ok(value) => completed.push(value),
            Err(error) if first_error.is_none() => first_error = Some(error),
            Err(_) => {}
        }
    }
    // A failed row must not cancel other started rows. Complete their callbacks,
    // then propagate the first original error, preserving the synchronous batch contract.
    match first_error {
        Some(error) => Err(error),
        None => {
            completed.sort_unstable_by_key(|(index, _)| *index);
            Ok(completed.into_iter().map(|(_, value)| value).collect())
        }
    }
}

type ProjectionTasks<'a, R> = FuturesUnordered<BoxFuture<'a, AuthResult<(usize, R)>>>;

async fn projection_tasks<'a, T: Send, R: Send + 'a, F>(
    rows: &'a mut [T],
    fields: &'a IndexMap<String, UserFieldConfig>,
    project: &'a (
            impl for<'b> Fn(&'b mut T, &'b str, &'b UserFieldConfig) -> BoxFuture<'b, AuthResult<()>>
            + Sync
        ),
    complete: &'a (impl Fn(usize, &mut T) -> F + Sync),
) -> (Option<crate::AuthError>, ProjectionTasks<'a, R>)
where
    F: Future<Output = AuthResult<R>> + Send + 'a,
{
    let mut first_error = None;
    let pending: FuturesUnordered<BoxFuture<'_, AuthResult<(usize, R)>>> = FuturesUnordered::new();
    if fields.values().any(|field| {
        field
            .output_transform()
            .is_some_and(super::UserFieldTransform::is_async)
    }) {
        for (index, row) in rows.iter_mut().enumerate() {
            pending.push(Box::pin(async move {
                for (name, field) in fields {
                    project(row, name, field).await?;
                }
                Ok((index, complete(index, row).await?))
            }));
        }
    } else {
        let mut active = vec![true; rows.len()];
        for (name, field) in fields {
            for (row, active) in rows.iter_mut().zip(&mut active) {
                if !*active {
                    continue;
                }
                if let Err(error) = project(row, name, field).await {
                    *active = false;
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        for ((index, row), active) in rows.iter_mut().enumerate().zip(active) {
            if active {
                let future = complete(index, row);
                pending.push(Box::pin(async move { Ok((index, future.await?)) }));
            }
        }
    }
    (first_error, pending)
}

/// Continue currently ready rows together without waiting for suspended peer rows.
/// A failed row skips its continuation; other started rows retain their write and output stages.
pub(crate) async fn project_fields_batches_then<T: Send, V: Send, R: Send, F>(
    rows: &mut [T],
    fields: &IndexMap<String, UserFieldConfig>,
    project: impl for<'a> Fn(&'a mut T, &'a str, &'a UserFieldConfig) -> BoxFuture<'a, AuthResult<()>>
    + Sync,
    extract: impl Fn(usize, &mut T) -> AuthResult<V> + Sync,
    complete: impl Fn(Vec<(usize, V)>) -> F + Sync,
) -> AuthResult<Vec<R>>
where
    F: Future<Output = AuthResult<Vec<(usize, R)>>> + Send,
{
    let capacity = rows.len().max(1);
    let extract = |index, row: &mut T| std::future::ready(extract(index, row));
    let (mut first_error, pending) = projection_tasks(rows, fields, &project, &extract).await;
    let stages = pending
        .ready_chunks(capacity)
        .map(|batch| {
            let mut ready = Vec::new();
            let mut errors = Vec::new();
            for result in batch {
                match result {
                    Ok(row) => ready.push(row),
                    Err(error) => errors.push(Err(error)),
                }
            }
            let complete = &complete;
            // Poll parent projections while earlier batches await their child output.
            stream::iter(errors).chain(Box::pin(stream::once(async move {
                if ready.is_empty() {
                    Ok(Vec::new())
                } else {
                    complete(ready).await
                }
            })))
        })
        .flatten_unordered(None);
    futures_util::pin_mut!(stages);
    let mut completed = Vec::new();
    while let Some(result) = stages.next().await {
        match result {
            Ok(rows) => completed.extend(rows),
            Err(error) if first_error.is_none() => first_error = Some(error),
            Err(_) => {}
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => {
            completed.sort_unstable_by_key(|(index, _)| *index);
            Ok(completed.into_iter().map(|(_, value)| value).collect())
        }
    }
}
