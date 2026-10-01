use super::UserFieldConfig;
use crate::AuthResult;
use indexmap::IndexMap;

pub(crate) fn project_fields<T>(
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
