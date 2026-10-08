use super::{AuthError, AuthResult, DEFAULT_TOTP_PERIOD_SECS, TOTP, Utc};

/// Keep the configured period separate from the library's integer counter clock.
pub(super) struct Totp {
    inner: TOTP,
    period: f64,
}

impl Totp {
    pub(super) fn new(mut inner: TOTP, period: f64) -> Self {
        inner.step = 1;
        Self { inner, period }
    }

    pub(super) fn with_default_period(mut self) -> Self {
        if self.period == 0.0 || self.period.is_nan() {
            self.period = DEFAULT_TOTP_PERIOD_SECS;
        }
        self
    }

    fn counter(&self, time_millis: i64) -> f64 {
        (time_millis as f64 / (self.period * 1000.0)).floor()
    }

    fn hotp_counter(counter: f64) -> AuthResult<u64> {
        if !counter.is_finite() {
            return Err(AuthError::config("Not an integer"));
        }
        // Upstream converts the integral Number to BigInt, then stores it modulo 2^64.
        let remainder = counter % 18_446_744_073_709_551_616.0;
        Ok(if remainder < 0.0 {
            // Adding 2^64 as a float would round small negative remainders incorrectly.
            0_u64.wrapping_sub((-remainder) as u64)
        } else {
            remainder as u64
        })
    }

    pub(super) fn generate_at(&self, time_millis: i64) -> AuthResult<String> {
        self.generate_hotp(self.counter(time_millis))
    }

    pub(super) fn generate_current(&self) -> AuthResult<String> {
        self.generate_at(Utc::now().timestamp_millis())
    }

    pub(super) fn check_current(&self, token: &str) -> AuthResult<bool> {
        self.check_at(token, Utc::now().timestamp_millis())
    }

    fn check_at(&self, token: &str, time_millis: i64) -> AuthResult<bool> {
        let counter = self.counter(time_millis);
        let skew = i16::from(self.inner.skew);
        let mut matched = false;
        for offset in -skew..=skew {
            // Upstream adds each window offset as a Number before converting to BigInt.
            let candidate = self.generate_hotp(counter + f64::from(offset))?;
            matched |= token.len() == candidate.len()
                && openssl::memcmp::eq(token.as_bytes(), candidate.as_bytes());
        }
        Ok(matched)
    }

    fn generate_hotp(&self, counter: f64) -> AuthResult<String> {
        if !(1..=8).contains(&self.inner.digits) {
            return Err(AuthError::internal("Digits must be between 1 and 8"));
        }
        let counter = Self::hotp_counter(counter)?;
        if self.inner.secret.is_empty() {
            return Err(AuthError::internal("HMAC key must not be empty"));
        }
        Ok(self.inner.generate(counter))
    }

    pub(super) fn get_url(&self) -> AuthResult<String> {
        let mut uri = url::Url::parse(&self.inner.get_url())
            .map_err(|error| AuthError::internal(format!("Build TOTP URI: {error}")))?;
        let parameters: Vec<_> = uri
            .query_pairs()
            .filter(|(name, _)| name != "period" && name != "digits")
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
        let _ = uri
            .query_pairs_mut()
            .clear()
            .extend_pairs(parameters)
            .append_pair("digits", &self.inner.digits.to_string())
            .append_pair(
                "period",
                &better_auth_core::schema_value::number_string(self.period),
            );
        Ok(uri.into())
    }
}

#[cfg(test)]
mod tests;
