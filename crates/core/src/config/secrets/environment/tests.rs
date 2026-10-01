use super::*;

#[test]
fn environment_precedence_preserves_legacy_decryption() {
    let env = SecretEnvironment {
        secrets: Some("2:new-key,1:old-key".into()),
        secret: Some("environment-legacy".into()),
        auth_secret: Some("fallback-legacy".into()),
        ..Default::default()
    };
    let mut config = AuthConfig::default();
    config.resolve_secret_environment(&env).unwrap();
    assert_eq!(config.signing_secret(), "new-key");
    assert_eq!(config.secret, "environment-legacy");
    let legacy = crate::utils::symmetric::encrypt("environment-legacy", "stored-token").unwrap();
    assert_eq!(
        crate::utils::symmetric::decrypt(config.encryption_secret(), &legacy).unwrap(),
        "stored-token"
    );

    let mut explicit = AuthConfig::new("explicit-legacy")
        .secrets(vec![VersionedSecret::new(3, "explicit-current")]);
    explicit
        .resolve_secret_environment(&SecretEnvironment {
            secrets: Some("malformed".into()),
            ..env
        })
        .unwrap();
    assert_eq!(explicit.signing_secret(), "explicit-current");
    assert_eq!(explicit.secret, "explicit-legacy");
    let encrypted =
        crate::utils::symmetric::encrypt(explicit.encryption_secret(), "stored-token").unwrap();
    assert!(encrypted.starts_with("$ba$3$"));
}

#[test]
fn empty_options_and_environment_follow_upstream_fallbacks() {
    let mut config = AuthConfig::new("");
    config
        .resolve_secret_environment(&SecretEnvironment {
            secret: Some(String::new()),
            auth_secret: Some("auth-fallback".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(config.signing_secret(), "auth-fallback");

    let mut config = AuthConfig::default();
    config
        .resolve_secret_environment(&SecretEnvironment::default())
        .unwrap();
    assert_eq!(config.signing_secret(), DEFAULT_SECRET);

    let mut config = AuthConfig::default().secrets(vec![]);
    assert!(
        config
            .resolve_secret_environment(&SecretEnvironment {
                secrets: Some("1:valid".into()),
                ..Default::default()
            })
            .is_err()
    );

    let mut config =
        AuthConfig::new(DEFAULT_SECRET).secrets(vec![VersionedSecret::new(1, "current")]);
    config
        .resolve_secret_environment(&SecretEnvironment::default())
        .unwrap();
    assert!(matches!(
        config.encryption_secret(),
        SecretKey::Versioned {
            legacy_secret: None,
            ..
        }
    ));
}

#[test]
fn production_rejects_only_default_single_secret_outside_test_mode() {
    let production = SecretEnvironment {
        node_env: Some("production".into()),
        ..Default::default()
    };
    for secret in ["", DEFAULT_SECRET] {
        assert!(
            AuthConfig::new(secret)
                .resolve_secret_environment(&production)
                .is_err()
        );
    }
    AuthConfig::new("short")
        .resolve_secret_environment(&production)
        .unwrap();
    AuthConfig::default()
        .secrets(vec![VersionedSecret::new(1, DEFAULT_SECRET)])
        .resolve_secret_environment(&production)
        .unwrap();
    for test in ["true", "0", "FALSE"] {
        AuthConfig::default()
            .resolve_secret_environment(&SecretEnvironment {
                node_env: Some("production".into()),
                test: Some(test.into()),
                ..Default::default()
            })
            .unwrap();
    }
    for test in ["", "false"] {
        assert!(
            AuthConfig::default()
                .resolve_secret_environment(&SecretEnvironment {
                    node_env: Some("production".into()),
                    test: Some(test.into()),
                    ..Default::default()
                })
                .is_err()
        );
    }
    AuthConfig::default()
        .resolve_secret_environment(&SecretEnvironment {
            node_env: Some("test".into()),
            ..Default::default()
        })
        .unwrap();
}

#[test]
fn environment_versions_match_pinned_decimal_prefix_and_number_rounding() {
    for (raw, version) in [
        ("+2tail", 2),
        ("-0", 0),
        ("1.2", 1),
        ("0x10", 0),
        ("9007199254740993", 9_007_199_254_740_992),
        ("100000000000000000000", 100_000_000_000_000_000_000),
    ] {
        let mut config = AuthConfig::default();
        config
            .resolve_secret_environment(&SecretEnvironment {
                secrets: Some(format!("{raw}:key")),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(config.secrets.as_ref().unwrap()[0].version, version);
    }
    let keys = parse_secrets_env(Some(" \u{feff}2:new:tail, 1:old \u{feff}"))
        .unwrap()
        .unwrap();
    assert_eq!(keys[0].value, "new:tail");
    assert_eq!(keys[1].value, "old");
    for raw in [
        "1000000000000000000000:key",
        "-1:key",
        "bad:key",
        "1: ",
        "1:a,01:b",
        "1:a,",
    ] {
        let mut config = AuthConfig::new("unchanged");
        assert!(
            config
                .resolve_secret_environment(&SecretEnvironment {
                    secrets: Some(raw.into()),
                    ..Default::default()
                })
                .is_err(),
            "{raw}"
        );
        assert_eq!(config.secret, "unchanged");
        assert!(config.secrets.is_none());
    }
}
