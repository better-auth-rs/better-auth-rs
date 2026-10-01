/// Explicit application storage configuration, independent of adapter wrappers.
#[derive(Clone, Copy, Debug)]
pub struct StoreCapabilities {
    /// The application supplied a durable database adapter.
    pub database: bool,
    /// The application supplied secondary storage.
    pub secondary: bool,
}

impl StoreCapabilities {
    /// Sessions can be checked against an application-owned server store.
    pub const fn server_sessions(self) -> bool {
        self.database || self.secondary
    }
}

impl Default for StoreCapabilities {
    fn default() -> Self {
        Self {
            database: true,
            secondary: false,
        }
    }
}
