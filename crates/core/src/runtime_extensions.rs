use std::{
    any::{Any, TypeId},
    collections::HashMap,
    sync::Arc,
};

/// Typed plugin configuration shared after initialization.
#[derive(Clone, Default)]
pub struct RuntimeExtensions(HashMap<TypeId, Arc<dyn Any + Send + Sync>>);

impl RuntimeExtensions {
    /// Publish configuration for other plugins. The latest value replaces the previous value.
    pub fn insert<T: Send + Sync + 'static>(&mut self, value: T) {
        let _ = self.0.insert(TypeId::of::<T>(), Arc::new(value));
    }

    /// Read configuration published during plugin initialization.
    pub fn get<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.0.get(&TypeId::of::<T>())?.downcast_ref()
    }
}
