//! The sql-escaper scanner ignores quoted text and non-executable comments.

fn context(sql: &[u8], position: usize) -> Option<usize> {
    let first = *sql.get(position)?;
    let next = sql.get(position + 1).copied();
    if first == b'\'' || first == b'`' {
        let mut cursor = position + 1;
        while let Some(&byte) = sql.get(cursor) {
            if first == b'\'' && byte == b'\\' {
                cursor += 2;
                continue;
            }
            if byte == first {
                if first == b'`' && sql.get(cursor + 1) == Some(&b'`') {
                    cursor += 2;
                    continue;
                }
                return Some(cursor + 1);
            }
            cursor += 1;
        }
        return Some(sql.len());
    }
    if first == b'-'
        && next == Some(b'-')
        && sql.get(position + 2).is_none_or(|value| *value <= b' ')
    {
        return Some(
            sql.get(position + 2..)?
                .iter()
                .position(|value| *value == b'\n')
                .map_or(sql.len(), |offset| position + 3 + offset),
        );
    }
    if first == b'/' && next == Some(b'*') && !matches!(sql.get(position + 2), Some(b'!' | b'+')) {
        return Some(
            sql.get(position + 2..)?
                .windows(2)
                .position(|value| value == b"*/")
                .map_or(sql.len(), |offset| position + 4 + offset),
        );
    }
    None
}

pub(super) fn placeholder(sql: &str, start: usize) -> Option<(usize, usize)> {
    let sql = sql.as_bytes();
    let mut position = start;
    while let Some(&byte) = sql.get(position) {
        if byte == b'?' {
            let mut end = position + 1;
            while sql.get(end) == Some(&b'?') {
                end += 1;
            }
            if end - position <= 2 {
                return Some((position, end));
            }
            position = end;
        } else {
            position = context(sql, position).unwrap_or(position + 1);
        }
    }
    None
}

fn word_character(value: u8) -> bool {
    value.is_ascii_alphanumeric() || value == b'_'
}

fn whitespace(value: u8) -> bool {
    matches!(value, b' ' | b'\t' | b'\n' | b'\r')
}

fn word(sql: &[u8], start: usize, word: &[u8]) -> bool {
    sql.get(start..start + word.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(word))
        && start
            .checked_sub(1)
            .and_then(|position| sql.get(position))
            .is_none_or(|value| !word_character(*value))
        && sql
            .get(start + word.len())
            .is_none_or(|value| !word_character(*value))
}

fn set_keyword(sql: &[u8], start: usize) -> Option<usize> {
    let mut position = start;
    while position < sql.len() {
        if let Some(end) = context(sql, position) {
            position = end;
            continue;
        }
        if word(sql, position, b"set") {
            return Some(position + 3);
        }
        if word(sql, position, b"key") {
            let mut cursor = position + 3;
            while sql.get(cursor).is_some_and(|value| whitespace(*value)) {
                cursor += 1;
            }
            if word(sql, cursor, b"update") {
                return Some(cursor + 6);
            }
        }
        position += 1;
    }
    None
}

pub(super) fn assignment(
    sql: &str,
    chunk: usize,
    placeholder: usize,
    nearest_set: &mut Option<(Option<usize>, Option<usize>)>,
) -> bool {
    let sql = sql.as_bytes();
    let previous = sql
        .get(chunk..placeholder)
        .into_iter()
        .flatten()
        .rev()
        .copied()
        .find(|value| !whitespace(*value));
    if !previous.is_some_and(|value| value.is_ascii_alphabetic() || value == b',') {
        return false;
    }
    let (set, next) = nearest_set.get_or_insert_with(|| {
        let set = set_keyword(sql, 0);
        (set, set.and_then(|position| set_keyword(sql, position)))
    });
    while let Some(position) = *next {
        if position > placeholder {
            break;
        }
        *set = Some(position);
        *next = set_keyword(sql, position);
    }
    let Some(mut position) = *set else {
        return false;
    };
    if position > placeholder {
        return false;
    }
    let mut depth = 0;
    let mut content = false;
    let mut comma = false;
    while let Some(&value) = sql.get(position).filter(|_| position < placeholder) {
        if let Some(end) = context(sql, position) {
            position = end;
            content = true;
            comma = false;
            continue;
        }
        if whitespace(value) {
            position += 1;
            continue;
        }
        if value == b'(' {
            depth += 1;
        } else if value == b')' {
            if depth == 0 {
                return false;
            }
            depth -= 1;
        } else if word_character(value) {
            if depth == 0
                && !value.is_ascii_digit()
                && [
                    b"where".as_slice(),
                    b"order",
                    b"group",
                    b"having",
                    b"limit",
                    b"union",
                    b"returning",
                    b"into",
                    b"for",
                    b"lock",
                    b"offset",
                    b"window",
                    b"procedure",
                    b"on",
                ]
                .iter()
                .any(|keyword| word(sql, position, keyword))
            {
                return false;
            }
            position += 1;
            while position < placeholder
                && sql
                    .get(position)
                    .is_some_and(|value| word_character(*value))
            {
                position += 1;
            }
            content = true;
            comma = false;
            continue;
        } else if depth == 0 {
            if value == b';' {
                return false;
            }
            if value == b',' {
                comma = true;
                content = true;
                position += 1;
                continue;
            }
        }
        content = true;
        comma = false;
        position += 1;
    }
    depth == 0 && (!content || comma)
}
