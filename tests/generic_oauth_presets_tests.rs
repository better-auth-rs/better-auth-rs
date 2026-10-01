use better_auth::plugins::oauth::GenericOAuthConfig;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    provider: String,
    address: String,
    override_scopes: Option<Vec<String>>,
    expected: Option<Expected>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Expected {
    discovery_url: String,
    scopes: Vec<String>,
}

#[test]
fn oidc_presets_match_upstream_url_normalization() -> Result<(), Box<dyn std::error::Error>> {
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("fixtures/generic-oidc-presets-1.7.6.json"))?;
    for case in cases {
        let configured = match case.provider.as_str() {
            "auth0" => GenericOAuthConfig::auth0("client", "secret", &case.address),
            "keycloak" => Ok(GenericOAuthConfig::keycloak(
                "client",
                "secret",
                &case.address,
            )),
            "okta" => Ok(GenericOAuthConfig::okta("client", "secret", &case.address)),
            _ => return Err("Unknown fixture provider".into()),
        };
        if let Some(expected) = case.expected {
            let mut config = configured?;
            if let Some(scopes) = case.override_scopes {
                config.scopes = scopes;
            }
            assert_eq!(
                config.discovery_url.as_deref(),
                Some(expected.discovery_url.as_str())
            );
            assert_eq!(config.scopes, expected.scopes);
        } else {
            assert!(configured.is_err());
        }
    }
    Ok(())
}
