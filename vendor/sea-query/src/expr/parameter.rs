use std::{any::Any, fmt, sync::Arc};

/// An owned native parameter for a dedicated query compiler and parameter collector.
///
/// Cloning a parameter shares its payload. The AST never contains an index into another query.
/// Ordinary builders and writers reject this node because the payload is not a SQL value.
#[derive(Clone)]
pub struct ExternalParameter(Arc<dyn Any + Send + Sync>);

impl ExternalParameter {
    /// Retain a native parameter without converting or reading the payload.
    pub fn new<T: Any + Send + Sync>(value: T) -> Self {
        Self(Arc::new(value))
    }

    /// Recover the owned payload when the dedicated collector recognizes its type.
    pub fn downcast<T: Any + Send + Sync>(self) -> Result<Arc<T>, Self> {
        self.0.downcast::<T>().map_err(Self)
    }
}

impl fmt::Debug for ExternalParameter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExternalParameter")
            .finish_non_exhaustive()
    }
}

impl PartialEq for ExternalParameter {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for ExternalParameter {}

#[cfg(test)]
mod tests;
