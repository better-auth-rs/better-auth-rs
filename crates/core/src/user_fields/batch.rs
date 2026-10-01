use super::UserFieldConfig;
use crate::AuthResult;
use futures_util::{StreamExt, future::BoxFuture, stream::FuturesUnordered};
use indexmap::IndexMap;

pub(crate) fn project_fields_sync<T>(
    rows: &mut [T],
    fields: &IndexMap<String, UserFieldConfig>,
    mut project: impl FnMut(&mut T, &str, &UserFieldConfig) -> AuthResult<()>,
) -> AuthResult<()> {
    let mut active = vec![true; rows.len()];
    let mut first_error = None;
    for (name, field) in fields {
        for (row, active) in rows.iter_mut().zip(&mut active) {
            if !*active {
                continue;
            }
            if let Err(error) = project(row, name, field) {
                *active = false;
                // Upstream starts every row before awaiting the batch. Complete other rows
                // so their callbacks still run, then propagate the first original error.
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

pub(crate) async fn project_fields<T: Send>(
    rows: &mut [T],
    fields: &IndexMap<String, UserFieldConfig>,
    project: impl for<'a> Fn(&'a mut T, &'a str, &'a UserFieldConfig) -> BoxFuture<'a, AuthResult<()>>
    + Sync,
) -> AuthResult<()> {
    let mut first_error = None;
    if fields.values().any(|field| {
        field
            .output_transform
            .as_ref()
            .is_some_and(super::UserFieldTransform::is_async)
    }) {
        let mut pending = rows
            .iter_mut()
            .map(|row| {
                let project = &project;
                async move {
                    for (name, field) in fields {
                        project(row, name, field).await?;
                    }
                    Ok(())
                }
            })
            .collect::<FuturesUnordered<_>>();
        while let Some(result) = pending.next().await {
            if let Err(error) = result
                && first_error.is_none()
            {
                first_error = Some(error);
            }
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
    }
    // A failed row must not cancel other started rows. Complete their callbacks,
    // then propagate the first original error, preserving the synchronous batch contract.
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}
