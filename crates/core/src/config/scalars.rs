use super::{
    AccountConfig, AccountLinkingConfig, AdvancedDatabaseConfig, ApiErrorConfig, AuthConfig,
    CrossSubDomainConfig, IpAddressConfig, SessionConfig, TrustedValues, VerificationConfig,
};
use chrono::Duration;

impl SessionConfig {
    /// Read the effective session lifetime. Omission and zero use seven days.
    pub fn expires_in(&self) -> Duration {
        self.expires_in
            .filter(|age| !age.is_zero())
            .unwrap_or_else(|| Duration::days(7))
    }

    /// Read the effective refresh interval. Omission uses one day; zero refreshes on every read.
    pub fn update_age(&self) -> Duration {
        self.update_age.unwrap_or_else(|| Duration::days(1))
    }

    /// Read the effective refresh policy. Omission permits refresh.
    pub fn disable_session_refresh(&self) -> bool {
        self.disable_session_refresh.unwrap_or(false)
    }

    /// Read the database persistence policy used with secondary storage.
    pub fn store_session_in_database(&self) -> bool {
        self.store_session_in_database.unwrap_or(false)
    }

    /// Read the ended-session retention policy. Omission permits deletion.
    pub fn preserve_session_in_database(&self) -> bool {
        self.preserve_session_in_database.unwrap_or(false)
    }
}

impl AccountConfig {
    /// Read the token refresh policy. Omission updates stored tokens on sign-in.
    pub fn update_account_on_sign_in(&self) -> bool {
        self.update_account_on_sign_in.unwrap_or(true)
    }

    /// Read the token encryption policy. Omission keeps plaintext storage.
    pub fn encrypt_oauth_tokens(&self) -> bool {
        self.encrypt_oauth_tokens.unwrap_or(false)
    }
}

impl AccountLinkingConfig {
    /// Read the effective account-linking setting. Omission enables linking.
    pub fn enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }

    /// Read the last-account removal policy. Omission keeps one linked account.
    pub fn allow_unlinking_all(&self) -> bool {
        self.allow_unlinking_all.unwrap_or(false)
    }

    /// Read the profile update policy. Omission preserves existing user information.
    pub fn update_user_info_on_link(&self) -> bool {
        self.update_user_info_on_link.unwrap_or(false)
    }
}

impl VerificationConfig {
    /// Read the expired-record cleanup policy. Omission permits cleanup.
    pub fn disable_cleanup(&self) -> bool {
        self.disable_cleanup.unwrap_or(false)
    }
}

impl ApiErrorConfig {
    /// Read the HTTP failure policy. Omission returns an ordinary error response.
    pub fn throw_errors(&self) -> bool {
        self.throw_errors.unwrap_or(false)
    }
}

impl IpAddressConfig {
    /// Read the configured header order. Omission uses `x-forwarded-for`; an empty list stays empty.
    pub fn headers(&self) -> impl Iterator<Item = &str> {
        self.headers
            .iter()
            .flatten()
            .map(String::as_str)
            .chain(self.headers.is_none().then_some("x-forwarded-for"))
    }

    /// Read the IP tracking policy. Omission keeps tracking enabled.
    pub fn disable_ip_tracking(&self) -> bool {
        self.disable_ip_tracking.unwrap_or(false)
    }
}

impl CrossSubDomainConfig {
    /// Read the cross-subdomain policy. Omission disables sharing.
    pub fn enabled(&self) -> bool {
        self.enabled.unwrap_or(false)
    }
}

impl AdvancedDatabaseConfig {
    /// Read the effective ID policy. Omission uses random alphanumeric IDs.
    pub fn generate_id(&self) -> &crate::id::IdGeneration {
        self.generate_id
            .as_ref()
            .unwrap_or(&crate::id::IdGeneration::Random)
    }
}

static EMPTY_TRUSTED_VALUES: TrustedValues = TrustedValues::Static(Vec::new());

impl AuthConfig {
    pub(crate) fn trusted_origin_values(&self) -> &TrustedValues {
        self.trusted_origins
            .as_ref()
            .unwrap_or(&EMPTY_TRUSTED_VALUES)
    }
}

impl AccountLinkingConfig {
    pub(crate) fn trusted_provider_values(&self) -> &TrustedValues {
        self.trusted_providers
            .as_ref()
            .unwrap_or(&EMPTY_TRUSTED_VALUES)
    }
}
