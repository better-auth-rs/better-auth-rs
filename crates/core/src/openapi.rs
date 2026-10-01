//! Runtime OpenAPI documentation from configured plugin declarations.

mod builder;
mod catalog;
mod field_schema;
mod metadata;
mod organization;
mod registry;

pub use builder::{OpenApiBuilder, OpenApiInfo, OpenApiRouteMetadata, OpenApiSpec};
pub use metadata::OpenApiPluginMetadata;
pub use registry::OpenApiRegistry;

#[cfg(test)]
mod tests;
