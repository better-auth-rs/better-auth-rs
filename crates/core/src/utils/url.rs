//! URL composition for trusted application redirect destinations.

use crate::{AuthError, AuthResult};

/// Append a serialized URL query before the fragment of an absolute or root-relative URL.
/// This operation composes URLs. The caller must validate untrusted redirect destinations.
pub fn append_query_params(target: &str, params: &str) -> AuthResult<String> {
    if target.starts_with("//") || target.starts_with("/\\") {
        return Err(AuthError::internal("Invalid URL"));
    }
    let relative = target.starts_with('/');
    let reference = "https://better-auth.invalid";
    let mut parsed = if relative {
        url::Url::parse(&format!("{reference}{target}"))
    } else {
        url::Url::parse(target)
    }
    .map_err(|error| AuthError::internal(format!("Invalid URL: {error}")))?;
    if relative && parsed.origin().ascii_serialization() != reference {
        return Err(AuthError::internal("Invalid URL"));
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
mod tests {
    use super::append_query_params;

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
        for target in ["//other.example/error", "/\\other.example/error"] {
            assert!(append_query_params(target, "error=denied").is_err());
        }
    }
}
