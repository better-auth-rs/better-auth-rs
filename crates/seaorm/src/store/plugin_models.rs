use crate::SeaOrmPluginModel;
use better_auth_core::{AuthResult, id::IdGeneration};
use serde::Serialize;
use serde_json::Map;

pub(super) type Entity<M> = <M as SeaOrmPluginModel>::Entity;

pub(super) fn set<M: SeaOrmPluginModel>(
    active: &mut M::ActiveModel,
    name: &str,
    value: impl Serialize,
    policy: &IdGeneration,
) -> AuthResult<()> {
    let fields = Map::from_iter([(name.to_owned(), serde_json::to_value(value)?)]);
    apply::<M>(active, fields, policy)
}

pub(super) fn apply<M: SeaOrmPluginModel>(
    active: &mut M::ActiveModel,
    mut fields: Map<String, serde_json::Value>,
    policy: &IdGeneration,
) -> AuthResult<()> {
    crate::reference_id::prepare_fields(&mut fields, policy, None, M::column, M::is_id_reference)?;
    M::apply_fields(active, fields)
}

pub(super) fn active<M: SeaOrmPluginModel>(
    mut fields: Map<String, serde_json::Value>,
    policy: &IdGeneration,
) -> AuthResult<M::ActiveModel> {
    crate::reference_id::prepare_fields(&mut fields, policy, None, M::column, M::is_id_reference)?;
    M::active(fields)
}
