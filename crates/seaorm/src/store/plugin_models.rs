use crate::SeaOrmPluginModel;
use better_auth_core::AuthResult;
use serde::Serialize;
use serde_json::Map;

pub(super) type Entity<M> = <M as SeaOrmPluginModel>::Entity;

pub(super) fn set<M: SeaOrmPluginModel>(
    active: &mut M::ActiveModel,
    name: &str,
    value: impl Serialize,
) -> AuthResult<()> {
    M::apply_fields(
        active,
        Map::from_iter([(name.to_owned(), serde_json::to_value(value)?)]),
    )
}
