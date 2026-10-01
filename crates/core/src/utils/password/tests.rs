use super::{
    Argon2PasswordHasher, PasswordHasher, ScryptPasswordHasher, hash_password, verify_password,
};

#[tokio::test]
async fn legacy_argon2_requires_explicit_selection() {
    let legacy = Argon2PasswordHasher.hash("Password123!").await.unwrap();
    assert!(legacy.starts_with("$argon2id$"));
    assert!(
        Argon2PasswordHasher
            .verify(&legacy, "Password123!")
            .await
            .unwrap()
    );
    assert!(!Argon2PasswordHasher.verify(&legacy, "wrong").await.unwrap());
    assert!(
        ScryptPasswordHasher
            .verify(&legacy, "Password123!")
            .await
            .is_err()
    );
    assert!(
        verify_password(None, "Password123!", &legacy)
            .await
            .is_err()
    );
    let current = hash_password(None, "Ｆｕｌｌ123!😀").await.unwrap();
    assert!(verify_password(None, "Full123!😀", &current).await.is_ok());
    assert!(
        Argon2PasswordHasher
            .verify(&current, "Full123!😀")
            .await
            .is_err()
    );
}
