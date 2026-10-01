use crate::{AuthError, AuthResult};

pub fn matches(pattern: &str, path: &str) -> AuthResult<bool> {
    if !pattern.contains('*') {
        return Ok(pattern == path);
    }
    let segments: Vec<_> = pattern.split('/').collect();
    let mut source = String::from("^");
    for (index, segment) in segments.iter().enumerate() {
        if segment.is_empty() && index > 0 {
            continue;
        }
        let separator = if index == segments.len() - 1 {
            r"[/\\]*?"
        } else if segments.get(index + 1) != Some(&"**") {
            r"[/\\]+?"
        } else {
            ""
        };
        if *segment == "**" {
            if !separator.is_empty() {
                if index != 0 {
                    source.push_str(separator);
                }
                source.push_str(&format!(r"(?:[^/\\]*?{separator})*?"));
            }
            continue;
        }
        let mut chars = segment.chars();
        while let Some(char) = chars.next() {
            match char {
                '\\' => {
                    if let Some(char) = chars.next() {
                        source.push_str(&regex::escape(&char.to_string()));
                    }
                }
                '?' => source.push_str(r"[^/\\]"),
                '*' => source.push_str(r"[^/\\]*?"),
                char => source.push_str(&regex::escape(&char.to_string())),
            }
        }
        source.push_str(separator);
    }
    source.push('$');
    Ok(regex::Regex::new(&source)
        .map_err(|error| AuthError::internal(format!("Invalid endpoint pattern: {error}")))?
        .is_match(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_globs_preserve_segment_and_double_star_rules() {
        for (pattern, path, expected) in [
            ("/sign-in/*", "/sign-in/email", true),
            ("/sign-in/*", "/sign-in/email/nested", false),
            ("/sign-in/**", "/sign-in/email/nested", true),
            ("/sign-in/**", "/sign-in-extra", true),
            ("/a/?*", "/a/b", true),
            ("/a/?*", "/a/", false),
            ("/a/?", "/a/b", false),
            ("/a/\\**", "/a/*literal", true),
            ("/a/[bc]*", "/a/bcd", false),
            ("/a/[bc]*", "/a/[bc]d", true),
        ] {
            assert_eq!(
                matches(pattern, path).unwrap(),
                expected,
                "{pattern} {path}"
            );
        }
    }
}
