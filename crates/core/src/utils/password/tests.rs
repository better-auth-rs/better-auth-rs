#![expect(
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Assertions report exact contract mismatches while Result propagates fixture errors."
)]

use super::{
    Argon2PasswordHasher, PasswordHasher, ScryptPasswordHasher, hash_password, verify_password,
    verify_password_native,
};
use crate::{AuthError, AuthResult, FieldFunction, FieldMap, FieldValue, Utf16String};
use std::sync::{Arc, Mutex};

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

#[tokio::test]
async fn native_scrypt_invokes_split_and_retains_its_values_until_kdf_comparison() -> AuthResult<()>
{
    let original: FieldValue = FieldMap::from([("reason".into(), "split failed".into())]).into();
    for (split, expected) in [
        (
            Ok(vec!["salt".into(), "wrong-key".into()].into()),
            "mismatch",
        ),
        (Ok("ab".into()), "mismatch"),
        (Ok(vec!["salt".into(), 17.into()].into()), "mismatch"),
        (Ok(vec![17.into(), "wrong-key".into()].into()), "salt"),
        (Ok(Vec::<FieldValue>::new().into()), "empty"),
        (Err(original.clone()), "throws"),
    ] {
        let calls = Arc::new(Mutex::new(0));
        let observed = calls.clone();
        let hash: FieldValue = FieldMap::from([
            ("marker".into(), "native-hash".into()),
            (
                "split".into(),
                FieldFunction::contextual(move |receiver, args| {
                    assert_eq!(receiver.model_property("marker")?, "native-hash".into());
                    assert_eq!(args, &[FieldValue::from(":")]);
                    *observed.lock().unwrap() += 1;
                    split.clone().map_err(AuthError::from_thrown)
                })
                .into(),
            ),
        ])
        .into();
        let result = ScryptPasswordHasher
            .verify_native(&hash, "Password123!")
            .await;
        assert_eq!(*calls.lock().unwrap(), 1);
        match expected {
            "mismatch" => assert_eq!(result?, false.into()),
            "throws" => assert!(
                result
                    .unwrap_err()
                    .raw_value()
                    .unwrap()
                    .strict_equals(&original)
            ),
            "salt" => {
                let error = result.unwrap_err();
                assert!(matches!(error, AuthError::TypeError(_)));
                assert_eq!(
                    error.instrumentation_message()?,
                    "The \"salt\" argument must be of type string, ArrayBuffer, Buffer, TypedArray, or DataView. Received type number (17)"
                );
            }
            _ => assert_eq!(
                result.unwrap_err().instrumentation_message()?,
                "Invalid password hash"
            ),
        }
    }
    for (hash, description) in [
        (FieldValue::from(17), "undefined"),
        (FieldMap::new().into(), "undefined"),
        (
            FieldMap::from([("split".into(), false.into())]).into(),
            "false",
        ),
    ] {
        let expected = format!(
            "hash.split is not a function. (In 'hash.split(\":\")', 'hash.split' is {description})"
        );
        assert!(
            matches!(ScryptPasswordHasher.verify_native(&hash, "Password123!").await,
            Err(AuthError::TypeError(message)) if message == expected)
        );
    }
    let key = super::algorithms::ScryptPasswordHasher
        .hash("Password123!")
        .await?;
    assert_eq!(
        ScryptPasswordHasher
            .verify_native(&Utf16String::from(key).into(), "Password123!")
            .await?,
        true.into()
    );
    Ok(())
}

struct NativeVerifier {
    hash: FieldValue,
    result: FieldValue,
}

#[async_trait::async_trait]
impl PasswordHasher for NativeVerifier {
    async fn hash(&self, _: &str) -> AuthResult<String> {
        Err(AuthError::internal("Verification must not hash"))
    }

    async fn verify(&self, _: &str, _: &str) -> AuthResult<bool> {
        Err(AuthError::internal(
            "Native verification must not call the typed bridge",
        ))
    }

    async fn verify_native(&self, hash: &FieldValue, password: &str) -> AuthResult<FieldValue> {
        assert!(hash.strict_equals(&self.hash));
        assert_eq!(password, "Password123!");
        Ok(self.result.clone())
    }
}

#[tokio::test]
async fn native_verifier_results_use_truthiness_without_hash_or_result_coercion() -> AuthResult<()>
{
    let hash: FieldValue = FieldMap::from([("hash".into(), "native".into())]).into();
    for (result, accepted) in [
        (FieldMap::new().into(), true),
        (Vec::<FieldValue>::new().into(), true),
        ("false".into(), true),
        (0.into(), false),
        (FieldValue::Undefined, false),
        (false.into(), false),
    ] {
        let hasher: Arc<dyn PasswordHasher> = Arc::new(NativeVerifier {
            hash: hash.clone(),
            result,
        });
        let result = verify_password_native(Some(&hasher), "Password123!", &hash).await;
        if accepted {
            result?;
        } else {
            assert!(matches!(result, Err(AuthError::InvalidCredentials)));
        }
    }
    Ok(())
}
