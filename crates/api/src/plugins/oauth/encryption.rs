//! Upstream-compatible OAuth token encryption and plaintext transition behavior.

use better_auth_core::{AuthContext, AuthResult, AuthSchema, SecretKey};

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
        Some(value)
            if encrypt
                && (value.starts_with("$ba$")
                    || (!value.is_empty()
                        && value.len().is_multiple_of(2)
                        && value.bytes().all(|byte| byte.is_ascii_hexdigit()))) =>
        {
            decrypt_token(value, secret).map(Some)
        }
        value => Ok(value.map(str::to_owned)),
    }
}

/// A set of OAuth tokens after conditional encryption.
pub struct EncryptedTokenSet {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
}

pub fn encrypt_token_set(
    ctx: &AuthContext<impl AuthSchema>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    id_token: Option<String>,
) -> AuthResult<EncryptedTokenSet> {
    let encrypt = ctx.config.account.encrypt_oauth_tokens;
    let secret = ctx.config.encryption_secret();
    Ok(EncryptedTokenSet {
        access_token: maybe_encrypt(access_token, encrypt, secret)?,
        refresh_token: maybe_encrypt(refresh_token, encrypt, secret)?,
        id_token,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
