use super::OAuthProvider;
use super::authorization::{AuthorizationRequest, build_authorization_url};
use super::resolved::ResolvedProvider;

#[test]
fn social_authorization_omits_nonce_and_preserves_provider_login_hint_behavior()
-> Result<(), Box<dyn std::error::Error>> {
    for (id, config, forwards_hint) in [
        ("google", OAuthProvider::google("client", "secret"), true),
        ("github", OAuthProvider::github("client", "secret"), true),
        ("gitlab", OAuthProvider::gitlab("client", "secret"), true),
        ("spotify", OAuthProvider::spotify("client", "secret"), false),
        (
            "huggingface",
            OAuthProvider::huggingface("client", "secret"),
            false,
        ),
        ("polar", OAuthProvider::polar("client", "secret"), false),
        ("vercel", OAuthProvider::vercel("client", "secret"), false),
        ("figma", OAuthProvider::figma("client", "secret"), false),
        ("dropbox", OAuthProvider::dropbox("client", "secret"), false),
        ("kick", OAuthProvider::kick("client", "secret"), false),
        (
            "linkedin",
            OAuthProvider::linkedin("client", "secret"),
            true,
        ),
        ("linear", OAuthProvider::linear("client", "secret"), true),
    ] {
        let provider = ResolvedProvider {
            config: config.resolve(),
            generic: None,
        };
        let build = |login_hint, nonce| -> Result<url::Url, Box<dyn std::error::Error>> {
            Ok(url::Url::parse(&build_authorization_url(
                &provider,
                AuthorizationRequest {
                    callback_url: "https://app.example.test/callback/provider",
                    scopes: None,
                    state: "ordinary-state",
                    code_challenge: "ordinary-challenge",
                    login_hint,
                    nonce,
                    additional_params: None,
                },
            )?)?)
        };
        let baseline = build(None, None)?;
        let actual = build(Some("reader@example.test"), Some("ordinary-nonce"))?;
        let mut expected: Vec<_> = baseline.query_pairs().into_owned().collect();
        if forwards_hint {
            expected.push(("login_hint".into(), "reader@example.test".into()));
        }
        expected.sort_unstable();
        let mut actual_query: Vec<_> = actual.query_pairs().into_owned().collect();
        actual_query.sort_unstable();
        assert!(!actual_query.iter().any(|(key, _)| key == "nonce"), "{id}");
        assert_eq!(actual_query, expected, "{id}");
    }
    Ok(())
}
