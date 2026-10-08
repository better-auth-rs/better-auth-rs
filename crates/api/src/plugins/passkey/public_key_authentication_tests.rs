use super::*;

#[tokio::test]
async fn native_public_key_decoding_matches_upstream_without_relaxing_signature_checks()
-> TestResult {
    let path = std::env::temp_dir().join(format!(
        "better-auth-passkey-key-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    drop(std::fs::File::create_new(&path)?);
    let mut fixture = Fixture::create(&path).await?;
    let raw = fixture.ctx.database.clone();
    let owner = raw
        .create_user(
            CreateUser::new()
                .with_name("Key owner")
                .with_email("key@passkey.example"),
        )
        .await?;
    let authenticator = Authenticator::new()?;
    let passkey = seed_native(&fixture, &owner, &authenticator).await?;
    let encoded = STANDARD.encode(&authenticator.cose);
    let unpadded = encoded.trim_end_matches('=');
    let mut ignored_surrogate = encoded.encode_utf16().collect::<Vec<_>>();
    ignored_surrogate.push(0xd800);
    let mut trailing_bits = unpadded.as_bytes().to_vec();
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let last = trailing_bits
        .last_mut()
        .ok_or("Missing public key encoding")?;
    let index = alphabet
        .iter()
        .position(|value| *value == *last)
        .ok_or("Invalid fixture encoding")?;
    *last = alphabet[index | 1];
    // Indefinite CBOR encodes the same key in 78 bytes, permitting a discarded orphan sextet.
    let mut indefinite = vec![0xbf];
    indefinite.extend_from_slice(&authenticator.cose[1..]);
    indefinite.push(0xff);
    assert_eq!(indefinite.len() % 3, 0);
    let indefinite = STANDARD.encode(indefinite);
    assert!(indefinite.ends_with('/'));
    let wrong_key = Authenticator::new()?;
    for (name, public_key, allowed) in [
        ("standard", FieldValue::from(encoded.clone()), true),
        ("unpadded", unpadded.into(), true),
        (
            "url-safe",
            URL_SAFE_NO_PAD.encode(&authenticator.cose).into(),
            true,
        ),
        (
            "ignored suffix",
            format!("{encoded}not base64").into(),
            true,
        ),
        (
            "ignored surrogate",
            Utf16String::from_units(ignored_surrogate).into(),
            true,
        ),
        (
            "trailing bits",
            String::from_utf8(trailing_bits)?.into(),
            true,
        ),
        ("orphan sextet", format!("{indefinite}A").into(), true),
        ("invalid prefix", format!("!{encoded}").into(), false),
        ("mixed alphabet", format!("+_{encoded}").into(), false),
        (
            "alphabet selected by suffix",
            format!("{indefinite}=-").into(),
            false,
        ),
        (
            "invalid orphan sextet",
            format!("{indefinite}!").into(),
            false,
        ),
        (
            "wrong signing key",
            STANDARD.encode(&wrong_key.cose).into(),
            false,
        ),
        ("null", FieldValue::Null, false),
    ] {
        raw.update_passkey_authentication(
            &passkey.id,
            UpdatePasskeyAuthentication::Native { counter: 0 },
        )
        .await?;
        let config = fixture.ctx.config.as_ref().clone();
        install_fields(
            &mut fixture,
            raw.clone(),
            config,
            UserConfig {
                additional_fields: Some(
                    [(
                        "publicKey".into(),
                        output(UserFieldTransform::new(move |_| Ok(public_key.clone()))),
                    )]
                    .into(),
                ),
            },
            Vec::new(),
        )
        .await?;
        let response = authenticate(&fixture, &authenticator, owner.id.typed()?).await?;
        assert_eq!(response.status, if allowed { 200 } else { 400 }, "{name}");
        if allowed {
            assert_login(response, owner.id.typed()?)?;
        } else {
            assert_error(response, "AUTHENTICATION_FAILED")?;
        }
        let stored = raw
            .get_passkey_by_id(passkey.id.typed()?)
            .await?
            .ok_or("Missing passkey")?;
        assert_eq!(stored.counter, u64::from(allowed), "{name}");
        assert_eq!(stored.public_key, passkey.public_key, "{name}");
    }
    drop(raw);
    fixture.close().await?;
    std::fs::remove_file(path)?;
    Ok(())
}
