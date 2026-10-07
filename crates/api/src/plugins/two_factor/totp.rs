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

    fn counter(&self, time_millis: i64) -> AuthResult<u64> {
        let milliseconds = self.period * 1000.0;
        if !milliseconds.is_finite() || milliseconds <= 0.0 {
            return Err(AuthError::config(
                "TOTP period must resolve to positive finite milliseconds",
            ));
        }
        let counter = (time_millis as f64 / milliseconds).floor();
        if !(0.0..u64::MAX as f64).contains(&counter) {
            return Err(AuthError::config("TOTP counter is out of range"));
        }
        let counter = counter as u64;
        let skew = u64::from(self.inner.skew);
        // totp-rs subtracts skew before checking. Both window ends must fit its counter type.
        if counter.checked_sub(skew).is_none() || counter.checked_add(skew).is_none() {
            return Err(AuthError::config("TOTP counter window is out of range"));
        }
        Ok(counter)
    }

    pub(super) fn generate_at(&self, time_millis: i64) -> AuthResult<String> {
        Ok(self.inner.generate(self.counter(time_millis)?))
    }

    pub(super) fn generate_current(&self) -> AuthResult<String> {
        self.generate_at(Utc::now().timestamp_millis())
    }

    pub(super) fn check_current(&self, token: &str) -> AuthResult<bool> {
        self.check_at(token, Utc::now().timestamp_millis())
    }

    fn check_at(&self, token: &str, time_millis: i64) -> AuthResult<bool> {
        Ok(self.inner.check(token, self.counter(time_millis)?))
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
