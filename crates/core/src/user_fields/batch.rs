use super::UserFieldConfig;
use crate::AuthResult;
use futures_util::{StreamExt, future::BoxFuture, stream::FuturesUnordered};
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
    let mut first_error = None;
    let mut pending: FuturesUnordered<BoxFuture<'_, AuthResult<(usize, R)>>> =
        FuturesUnordered::new();
    if fields.values().any(|field| {
        field
            .output_transform()
            .is_some_and(super::UserFieldTransform::is_async)
    }) {
        for (index, row) in rows.iter_mut().enumerate() {
            let project = &project;
            let complete = &complete;
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
