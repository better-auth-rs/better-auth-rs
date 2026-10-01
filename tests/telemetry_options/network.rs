use super::{AuthConfig, AuthError, AuthRequest, AuthResult, BetterAuth, Value, configuration};
use better_auth::__private_core::{
    CookieAttributes, CookieOverride, CrossSubDomainConfig, HttpMethod,
};

#[test]
fn network_options_match_upstream_in_a_production_process() -> Result<(), Box<dyn std::error::Error>>
{
    let output = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "network::configured_network_options",
            "--ignored",
        ])
        .env("NODE_ENV", "production")
        .output()?;
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn configure(config: &mut AuthConfig, name: &str) {
    if matches!(name, "empty" | "defaults" | "values") {
        config.advanced.cookies = Some(Default::default());
        config.advanced.cross_sub_domain_cookies = Some(Default::default());
    }
    match name {
        "defaults" => {
            config.advanced.ip_address.headers = Some(vec!["x-forwarded-for".into()]);
            config.advanced.ip_address.disable_ip_tracking = Some(false);
            config.advanced.cross_sub_domain_cookies = Some(CrossSubDomainConfig {
                enabled: Some(false),
                additional_cookies: Some(Vec::new()),
                ..Default::default()
            });
        }
        "values" => {
            config.advanced.ip_address.headers = Some(Vec::new());
            config.advanced.ip_address.disable_ip_tracking = Some(true);
            config.advanced.cross_sub_domain_cookies = Some(CrossSubDomainConfig {
                enabled: Some(true),
                domain: Some("parent.test".into()),
                additional_cookies: Some(vec!["custom".into()]),
            });
            let _ = config.advanced.cookies.get_or_insert_default().insert(
                "session_token".into(),
                CookieOverride {
                    name: Some("session.custom".into()),
                    attributes: CookieAttributes {
                        path: Some("/auth".into()),
                        ..Default::default()
                    },
                },
            );
        }
        "headerOrder" => {
            config.advanced.ip_address.headers =
                Some(vec!["x-real-ip".into(), "x-forwarded-for".into()]);
            config.advanced.cross_sub_domain_cookies = Some(CrossSubDomainConfig {
                enabled: Some(true),
                ..Default::default()
            });
        }
        "emptyHeaders" => {
            config.advanced.ip_address.headers = Some(Vec::new());
            config.advanced.cross_sub_domain_cookies = Some(CrossSubDomainConfig {
                enabled: Some(false),
                domain: Some("parent.test".into()),
                ..Default::default()
            });
        }
        _ => {}
    }
}

#[tokio::test]
#[ignore = "the parent invokes this case in a fresh production process"]
async fn configured_network_options() -> AuthResult<()> {
    let oracle: Value =
        serde_json::from_str(include_str!("../fixtures/network-options-1.7.6.json"))?;
    let cases = oracle
        .as_object()
        .ok_or_else(|| AuthError::internal("network oracle must be an object"))?;
    for (name, expected) in cases {
        let (mut config, reports) = configuration();
        configure(&mut config, name);
        let auth = BetterAuth::stateless(config).build().await?;
        let cookie = auth
            .config()
            .auth_cookie("session_token", CookieAttributes::default());
        let mut request = AuthRequest::new(HttpMethod::Get, "/normal-network-options");
        let _ = request
            .headers
            .insert("x-forwarded-for".into(), "192.0.2.1".into());
        let _ = request
            .headers
            .insert("x-real-ip".into(), "192.0.2.2".into());
        let actual = serde_json::json!({
            "advanced": reports.config()?.get("advanced"),
            "cookie": { "name": cookie.name, "path": cookie.attributes.path, "domain": cookie.attributes.domain },
            "ip": auth.config().advanced.ip_address.resolve(&request),
        });
        assert_eq!(&actual, expected, "{name}");
    }
    Ok(())
}
