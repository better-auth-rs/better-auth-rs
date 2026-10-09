use super::UserFieldConfig;
use crate::AuthResult;
use futures_util::{
    Stream, StreamExt,
    future::BoxFuture,
    stream::{self, BoxStream, FuturesUnordered},
};
use indexmap::IndexMap;
use std::{
    future::{Future, poll_fn},
    task::Poll,
};

type ReadyRow<'a, T> = (usize, &'a mut T, usize);

pub(crate) async fn await_boundary() {
    let mut queued = false;
    poll_fn(|context| {
        if queued {
            return Poll::Ready(());
        }
        queued = true;
        // Wake the callback queue directly; Tokio's deferred yields reverse ready peers.
        context.waker().wake_by_ref();
        Poll::Pending
    })
    .await;
}

async fn start_callback<T>(callback: &mut BoxFuture<'_, T>) -> Poll<T> {
    // JavaScript runs each callback's synchronous prefix before starting the next row.
    poll_fn(|cx| Poll::Ready(callback.as_mut().poll(cx))).await
}

fn source_projection_results<'a, T: Send, V: Send + 'a, R: Send + 'a>(
    rows: &'a mut [T],
    fields: &'a IndexMap<String, UserFieldConfig>,
    read: &'a (impl Fn(&mut T, &str, &UserFieldConfig) -> AuthResult<V> + Sync),
    apply: &'a (
            impl for<'b> Fn(&'b mut T, &'b str, &'b UserFieldConfig, V) -> BoxFuture<'b, AuthResult<()>>
            + Sync
        ),
    complete: &'a (impl Fn(usize, &mut T) -> AuthResult<R> + Sync),
) -> BoxStream<'a, AuthResult<(usize, R)>> {
    let capacity = rows.len().max(1);
    let ready: Vec<_> = rows
        .iter_mut()
        .enumerate()
        .map(|(index, row)| (index, row, 0))
        .collect();
    let pending: FuturesUnordered<BoxFuture<'a, AuthResult<ReadyRow<'a, T>>>> =
        FuturesUnordered::new();
    stream::unfold(
        (ready, pending),
        move |(mut ready, mut pending)| async move {
            let mut completed = Vec::new();
            loop {
                for (index, row, mut position) in ready {
                    loop {
                        let Some((name, field)) = fields.get_index(position) else {
                            completed.push(complete(index, row).map(|value| (index, value)));
                            break;
                        };
                        let value = match read(row, name, field) {
                            Ok(value) => value,
                            Err(error) => {
                                completed.push(Err(error));
                                break;
                            }
                        };
                        position += 1;
                        if field.output_transform().is_some() {
                            // Capture only this field. Later fields must observe writes made while awaiting.
                            let mut callback: BoxFuture<'a, AuthResult<ReadyRow<'a, T>>> =
                                Box::pin(async move {
                                    apply(row, name, field, value).await?;
                                    Ok((index, row, position))
                                });
                            match start_callback(&mut callback).await {
                                Poll::Ready(Ok(row)) => {
                                    pending.push(Box::pin(std::future::ready(Ok(row))))
                                }
                                Poll::Ready(Err(error)) => completed.push(Err(error)),
                                Poll::Pending => pending.push(callback),
                            }
                            break;
                        }
                        if let Err(error) = apply(row, name, field, value).await {
                            completed.push(Err(error));
                            break;
                        }
                    }
                }
                // Expose completed parents before polling suspended peers for another field.
                if !completed.is_empty() {
                    return Some((completed, (Vec::new(), pending)));
                }
                let batch = pending.by_ref().ready_chunks(capacity).next().await?;
                ready = Vec::new();
                for result in batch {
                    match result {
                        Ok(row) => ready.push(row),
                        Err(error) => completed.push(Err(error)),
                    }
                }
            }
        },
    )
    .flat_map(stream::iter)
    .boxed()
}

fn source_apply<T, F>(apply: F) -> F
where
    F: for<'a> Fn(&'a mut T, &'a str, &'a UserFieldConfig, ()) -> BoxFuture<'a, AuthResult<()>>
        + Sync,
{
    apply
}

/// Continue completed live rows without delaying their child reads behind suspended peers.
pub(crate) async fn project_source_fields_batches_then<T: Send, I: Send, V: Send, R: Send, F>(
    rows: &mut [T],
    fields: &IndexMap<String, UserFieldConfig>,
    read: impl Fn(&mut T, &str, &UserFieldConfig) -> AuthResult<I> + Sync,
    apply: impl for<'a> Fn(&'a mut T, &'a str, &'a UserFieldConfig, I) -> BoxFuture<'a, AuthResult<()>>
    + Sync,
    extract: impl Fn(usize, &mut T) -> AuthResult<V> + Sync,
    complete: impl Fn(Vec<(usize, V)>) -> F + Sync,
) -> AuthResult<Vec<R>>
where
    F: Future<Output = AuthResult<Vec<(usize, R)>>> + Send,
{
    let capacity = rows.len().max(1);
    let pending = source_projection_results(rows, fields, &read, &apply, &extract);
    continue_projection_batches(pending, capacity, None, complete).await
}

fn collect_result<T>(
    result: AuthResult<T>,
    first_error: &mut Option<crate::AuthError>,
    completed: &mut Vec<T>,
) {
    match result {
        Ok(value) => completed.push(value),
        Err(error) => {
            let _ = first_error.get_or_insert(error);
        }
    }
}

fn finish_projection<R>(
    first_error: Option<crate::AuthError>,
    mut completed: Vec<(usize, R)>,
) -> AuthResult<Vec<R>> {
    // Drain started peers before returning the first original callback error.
    match first_error {
        Some(error) => Err(error),
        None => {
            completed.sort_unstable_by_key(|(index, _)| *index);
            Ok(completed.into_iter().map(|(_, value)| value).collect())
        }
    }
}

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
    let capacity = rows.len().max(1);
    let read = |_: &mut T, _: &str, _: &UserFieldConfig| Ok(());
    let apply = source_apply(|row, name, field, ()| project(row, name, field));
    let extract = |index, row: &mut T| Ok(complete(index, row));
    let pending = source_projection_results(rows, fields, &read, &apply, &extract)
        .map(|result| async move {
            let (index, complete) = result?;
            Ok((index, complete.await?))
        })
        .buffer_unordered(capacity);
    futures_util::pin_mut!(pending);
    let mut first_error = None;
    let mut completed = Vec::new();
    while let Some(result) = pending.next().await {
        collect_result(result, &mut first_error, &mut completed);
    }
    // A failed row must not cancel other started rows. Complete their callbacks,
    // then propagate the first original error, preserving the synchronous batch contract.
    finish_projection(first_error, completed)
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
    let read = |_: &mut T, _: &str, _: &UserFieldConfig| Ok(());
    let apply = source_apply(|row, name, field, ()| project(row, name, field));
    let pending = source_projection_results(rows, fields, &read, &apply, &extract);
    continue_projection_batches(pending, capacity, None, complete).await
}

async fn continue_projection_batches<V: Send, R: Send, F>(
    pending: impl Stream<Item = AuthResult<(usize, V)>> + Send,
    capacity: usize,
    mut first_error: Option<crate::AuthError>,
    complete: impl Fn(Vec<(usize, V)>) -> F + Sync,
) -> AuthResult<Vec<R>>
where
    F: Future<Output = AuthResult<Vec<(usize, R)>>> + Send,
{
    let stages = Box::pin(pending)
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
    finish_projection(first_error, completed)
}
