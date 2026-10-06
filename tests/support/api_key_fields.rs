#[path = "api_key_fields_common.rs"]
mod common;

pub(crate) use common::{sqlite, sqlite_for};

common::api_key_model!(renamed, "stored_name");
