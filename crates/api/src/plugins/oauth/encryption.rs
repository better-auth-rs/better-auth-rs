//! Upstream-compatible OAuth token encryption and plaintext transition behavior.

use better_auth_core::{
    AuthContext, AuthError, AuthResult, AuthSchema, FieldValue, SchemaValue, SecretKey,
};

/// Encrypt a token with Better Auth's shared record codec.
pub fn encrypt_token<'a>(plaintext: &str, secret: impl Into<SecretKey<'a>>) -> AuthResult<String> {
    crate::plugins::symmetric::encrypt(secret, plaintext)
}

/// Decrypt an encrypted token with its configured key.
pub fn decrypt_token<'a>(encrypted: &str, secret: impl Into<SecretKey<'a>>) -> AuthResult<String> {
    crate::plugins::symmetric::decrypt(secret, encrypted)
}

/// Preserve absent and empty tokens; encrypt nonempty values when enabled.
pub fn maybe_encrypt<'a>(
    value: Option<String>,
    encrypt: bool,
    secret: impl Into<SecretKey<'a>>,
) -> AuthResult<Option<String>> {
    match value {
        Some(value) if encrypt && !value.is_empty() => encrypt_token(&value, secret).map(Some),
        value => Ok(value),
    }
}

/// Preserve existing plaintext records while encryption is enabled.
pub fn maybe_decrypt<'a>(
    value: Option<&str>,
    encrypt: bool,
    secret: impl Into<SecretKey<'a>>,
) -> AuthResult<Option<String>> {
    match value {
        Some(value) if encrypt && is_likely_encrypted(value) => {
            decrypt_token(value, secret).map(Some)
        }
        value => Ok(value.map(str::to_owned)),
    }
}

fn is_likely_encrypted(value: &str) -> bool {
    value.starts_with("$ba$")
        || (!value.is_empty()
            && value.len().is_multiple_of(2)
            && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

/// A set of OAuth tokens after conditional encryption.
pub struct EncryptedTokenSet {
    pub access_token: SchemaValue<Option<String>>,
    pub refresh_token: SchemaValue<Option<String>>,
    pub id_token: SchemaValue<Option<String>>,
}

/// Preserve native values until the cipher requires a string.
pub(super) fn encrypt_value<'a>(
    value: SchemaValue<Option<String>>,
    encrypt: bool,
    secret: impl Into<SecretKey<'a>>,
) -> AuthResult<SchemaValue<Option<String>>> {
    if !encrypt || !value.is_truthy()? {
        return Ok(value);
    }
    let value = value.into_field_value();
    let plaintext = match &value {
        FieldValue::String(value) => std::borrow::Cow::Borrowed(value.as_str()),
        FieldValue::Utf16String(value) => {
            std::borrow::Cow::Owned(String::from_utf16_lossy(value.as_utf16()))
        }
        _ => return Err(AuthError::type_error("string expected")),
    };
    Ok(Some(encrypt_token(&plaintext, secret)?).into())
}

pub(super) fn decrypt_value<'a>(
    value: &SchemaValue<Option<String>>,
    encrypt: bool,
    secret: impl Into<SecretKey<'a>>,
) -> AuthResult<SchemaValue<Option<String>>> {
    if !encrypt || !value.is_truthy()? {
        return Ok(value.clone());
    }
    let native = value.field_value();
    let text = match &native {
        FieldValue::String(value) => std::borrow::Cow::Borrowed(value.as_str()),
        FieldValue::Utf16String(value) => {
            std::borrow::Cow::Owned(String::from_utf16_lossy(value.as_utf16()))
        }
        _ => return Err(AuthError::type_error("token.startsWith is not a function")),
    };
    if is_likely_encrypted(&text) {
        Ok(Some(decrypt_token(&text, secret)?).into())
    } else {
        Ok(value.clone())
    }
}

pub fn encrypt_token_set(
    ctx: &AuthContext<impl AuthSchema>,
    access_token: SchemaValue<Option<String>>,
    refresh_token: SchemaValue<Option<String>>,
    id_token: SchemaValue<Option<String>>,
) -> AuthResult<EncryptedTokenSet> {
    let encrypt = ctx.config.account.encrypt_oauth_tokens();
    let secret = ctx.config.encryption_secret();
    Ok(EncryptedTokenSet {
        access_token: encrypt_value(access_token, encrypt, secret)?,
        refresh_token: encrypt_value(refresh_token, encrypt, secret)?,
        id_token,
    })
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Assertions report exact contract mismatches while Result propagates fixture errors."
)]
mod tests {
    use super::*;

    #[test]
    fn native_tokens_remain_unchanged_until_the_cipher_boundary() -> AuthResult<()> {
        let native: FieldValue =
            better_auth_core::FieldMap::from([("token".into(), 7.0.into())]).into();
        let input = SchemaValue::Dynamic(native.clone());
        assert!(
            encrypt_value(input.clone(), false, "secret")?
                .field_value()
                .strict_equals(&native)
        );
        assert!(
            decrypt_value(&input, false, "secret")?
                .field_value()
                .strict_equals(&native)
        );
        let falsey = SchemaValue::Dynamic(0.0.into());
        assert_eq!(
            encrypt_value(falsey.clone(), true, "secret")?.field_value(),
            0.0.into()
        );
        assert_eq!(
            decrypt_value(&falsey, true, "secret")?.field_value(),
            0.0.into()
        );
        let error = match encrypt_value(input, true, "secret") {
            Err(error) => error,
            Ok(_) => return Err(AuthError::internal("Expected a cipher string type error")),
        };
        assert_eq!(error.message_value()?, "string expected".into());
        let plaintext =
            SchemaValue::Dynamic(better_auth_core::Utf16String::from_units(vec![0xd800]).into());
        assert!(
            decrypt_value(&plaintext, true, "secret")?
                .field_value()
                .strict_equals(&plaintext.field_value())
        );
        Ok(())
    }

    // Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/utils.ts; adapted to the Rust OAuth token encryption helpers.
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let secret = "a]vt!MFX8H-e!4igKa5)Tu.{ec:2$z%n";
        let plaintext = "ya29.a0AfH6SMBx-some-access-token";

        let encrypted = encrypt_token(plaintext, secret).unwrap();
        assert_ne!(encrypted, plaintext);

        let decrypted = decrypt_token(&encrypted, secret).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/utils.ts; adapted to the Rust OAuth token encryption helpers.
    #[test]
    fn test_maybe_encrypt_none() {
        let result = maybe_encrypt(None, true, "secret-key-that-is-32-chars-long").unwrap();
        assert!(result.is_none());
    }

    // Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/utils.ts; adapted to the Rust OAuth token encryption helpers.
    #[test]
    fn test_maybe_encrypt_disabled() {
        let token = "plain-token".to_string();
        let result = maybe_encrypt(Some(token.clone()), false, "secret").unwrap();
        assert_eq!(result, Some(token));
    }

    // Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/utils.ts; adapted to the Rust OAuth token encryption helpers.
    #[test]
    fn test_maybe_decrypt_none() {
        let result = maybe_decrypt(None, true, "secret-key-that-is-32-chars-long").unwrap();
        assert!(result.is_none());
    }

    // Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/utils.ts; adapted to the Rust OAuth token encryption helpers.
    #[test]
    fn test_maybe_decrypt_preserves_plaintext_when_encryption_is_enabled() {
        let plaintext = "ya29.a0AfH6SMBx-some-access-token";
        let result = maybe_decrypt(Some(plaintext), true, "some-secret");
        assert_eq!(result.unwrap().as_deref(), Some(plaintext));
    }
}
