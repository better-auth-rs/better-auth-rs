use super::{AuthError, AuthResult, FieldValue, append};
use better_auth_core::FieldArray;

// shortcut: This Rust safety limit does not match JavaScript engine thresholds or caller depth.
// Replace this limit when a shared native interpreter owns the call stack.
const MAX_ACTIVE_FRAMES: usize = 16_384;

#[derive(Clone, Copy)]
pub(super) enum Mode {
    Values,
    Identifiers,
}

struct Frame {
    array: FieldArray,
    next: usize,
    length: usize,
    close_parenthesis: bool,
    effect_epoch: usize,
}

fn stack_error() -> AuthError {
    AuthError::RangeError("Maximum call stack size exceeded.".into())
}

fn observable_read(epoch: &mut usize) -> AuthResult<()> {
    *epoch = epoch.checked_add(1).ok_or_else(stack_error)?;
    Ok(())
}

fn enter(
    array: &FieldArray,
    close_parenthesis: bool,
    frames: &mut Vec<Frame>,
    epoch: &mut usize,
) -> AuthResult<()> {
    if frames.len() == MAX_ACTIVE_FRAMES {
        return Err(stack_error());
    }
    if array.has_live_indices() {
        observable_read(epoch)?;
    }
    let length = array.len()?;
    // A repeated owned path cannot change until a native getter or conversion callback runs.
    if frames
        .iter()
        .rev()
        .take_while(|frame| frame.effect_epoch == *epoch)
        .any(|frame| frame.array.same_array(array))
    {
        return Err(stack_error());
    }
    frames.push(Frame {
        array: array.clone(),
        next: 0,
        length,
        close_parenthesis,
        effect_epoch: *epoch,
    });
    Ok(())
}

/// Preserve captured lengths and live index reads without using the Rust call stack.
pub(super) fn write(array: &FieldArray, mode: Mode, output: &mut Vec<u16>) -> AuthResult<()> {
    let mut frames = Vec::new();
    let mut epoch = 0;
    enter(array, false, &mut frames, &mut epoch)?;
    while let Some(frame) = frames.last_mut() {
        if frame.next == frame.length {
            if frame.close_parenthesis {
                output.push(u16::from(b')'));
            }
            let _ = frames.pop();
            continue;
        }
        let index = frame.next;
        frame.next += 1;
        if index != 0 {
            append(output, ", ");
        }
        if frame.array.has_live_indices() {
            observable_read(&mut epoch)?;
        }
        let value = frame.array.get(index)?.unwrap_or_default();
        if let FieldValue::Array(array) = value {
            let nested = matches!(mode, Mode::Values);
            if nested {
                output.push(u16::from(b'('));
            }
            enter(&array, nested, &mut frames, &mut epoch)?;
        } else {
            if matches!(
                value,
                FieldValue::Object(_) | FieldValue::Date(_) | FieldValue::Function(_)
            ) {
                observable_read(&mut epoch)?;
            }
            match mode {
                Mode::Values => super::escape(&value, output)?,
                Mode::Identifiers => super::identifier(&value, output)?,
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
