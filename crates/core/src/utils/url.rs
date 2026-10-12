//! URL composition for trusted application redirect destinations.

use crate::{AuthError, AuthResult};

/// Append a serialized URL query before the fragment of an absolute or root-relative URL.
/// This operation composes URLs. The caller must validate untrusted redirect destinations.
pub fn append_query_params(target: &str, params: &str) -> AuthResult<String> {
    if target.starts_with("//") || target.starts_with("/\\") {
        return Err(AuthError::type_error(
            "Expected an absolute or root-relative URL",
        ));
    }
    let relative = target.starts_with('/');
    let reference = "https://better-auth.invalid";
    let mut parsed = if relative {
        url::Url::parse(&format!("{reference}{target}"))
    } else {
        url::Url::parse(target)
    }
    .map_err(|_| AuthError::type_error("Invalid URL"))?;
    if relative && parsed.origin().ascii_serialization() != reference {
        return Err(AuthError::type_error(
            "Expected an absolute or root-relative URL",
        ));
    }
    if params.is_empty() {
        return Ok(target.to_owned());
    }
    let query = match parsed.query().filter(|value| !value.is_empty()) {
        Some(value) => format!(
            "{value}{}{params}",
            if value.ends_with('&') { "" } else { "&" }
        ),
        None => params.to_owned(),
    };
    parsed.set_query(Some(&query));
    if relative {
        Ok(parsed[url::Position::BeforePath..].to_owned())
    } else {
        Ok(parsed.into())
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "Required fixture operations must succeed before comparing the contract."
)]
mod tests {
    use super::append_query_params;
    use crate::AuthError;

    #[test]
    fn redirect_preserves_plus_in_path_and_encodes_spaces_in_query() {
        let params = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("error_description", "space value")
            .finish();
        let url =
            append_query_params("/dashboard+beta", &params).expect("redirect URL should build");
        assert_eq!(url, "/dashboard+beta?error_description=space+value");
    }

    #[test]
    fn redirect_rejects_network_path_references() {
        for (target, message) in [
            ("invalid/api/auth/error", "Invalid URL"),
            (
                "//other.example/error",
                "Expected an absolute or root-relative URL",
            ),
            (
                "/\\other.example/error",
                "Expected an absolute or root-relative URL",
            ),
        ] {
            for params in ["", "error=missing_profile"] {
                let result = append_query_params(target, params);
                assert!(
                    matches!(result, Err(AuthError::TypeError(ref actual)) if actual == message)
                );
            }
        }
    }

    #[test]
    fn redirect_preserves_empty_query_input_after_url_validation() {
        for (target, params, expected) in [
            (
                "https://query.proxy-runtime.test/a b?one=1&",
                "",
                "https://query.proxy-runtime.test/a b?one=1&",
            ),
            ("/a b?one=1&#fragment", "", "/a b?one=1&#fragment"),
            (
                "/space path+keep?one=1&#fragment",
                "two=2",
                "/space%20path+keep?one=1&two=2#fragment",
            ),
        ] {
            assert_eq!(
                append_query_params(target, params).expect("valid URL"),
                expected
            );
        }
    }
}
