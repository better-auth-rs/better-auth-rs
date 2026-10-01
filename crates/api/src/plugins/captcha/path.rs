pub(super) use better_auth_core::utils::path::matches;

pub(super) fn normalize(path: &str, base_path: &str) -> String {
    let path = path.strip_prefix(base_path).unwrap_or(path);
    let mut result = String::from("/");
    for part in path.split('/').filter(|part| !part.is_empty()) {
        if result.len() > 1 {
            result.push('/');
        }
        result.push_str(part);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::normalize;

    #[test]
    fn captcha_normalizes_repeated_path_separators() {
        assert_eq!(
            normalize("/api/auth//sign-in/email///", "/api/auth"),
            "/sign-in/email"
        );
    }
}
