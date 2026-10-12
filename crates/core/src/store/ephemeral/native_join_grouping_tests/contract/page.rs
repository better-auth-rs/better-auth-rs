//! Adapter-only offset cases use shared native grouping, pagination, and production projection.
//! Account and Session Store APIs do not expose an arbitrary joined page with an offset.

use super::*;
use crate::store::ephemeral::{native_joins::native_relationships, rows::RecordSource};
use crate::store::schema::EntityRole;

pub(super) async fn execute(store: &EphemeralStore, scenario: &Scenario) -> AuthResult<Value> {
    let (role, fields, relation) = match scenario.model {
        Model::Account => (
            EntityRole::Account,
            store.field_policy().account(),
            AccountOwner::resolve_schema(&store.config, &store.model_fields, |_, _| false)?,
        ),
        Model::Session => (
            EntityRole::Session,
            store
                .model_fields
                .bind(&store.config)
                .session(&FieldMap::new())
                .adapter_fields(&[]),
            SessionData::resolve_schema(&store.config, &store.model_fields, |_, _| false)?,
        ),
        Model::User => {
            return Err(AuthError::internal(
                "The joined page fixture requires Account or Session",
            ));
        }
    };
    let selected = store
        .raw(scenario.model.name(), "findMany", |op| {
            let parents = op
                .capture_table(role)?
                .snapshot_refs()?
                .into_iter()
                .map(RecordSource::Live)
                .collect();
            let groups = native_relationships(
                parents,
                &[(
                    EntityRole::User,
                    &relation,
                    store.config.advanced.database.find_many_limit(),
                )],
                |role| op.capture_join_table(role),
            )?;
            crate::query::paginate_memory(groups, scenario.limit, scenario.offset)
                .into_iter()
                .map(|group| {
                    let rows = required(group.children.into_iter().next())?;
                    let users = if relation.many {
                        JoinValue::Many(rows)
                    } else {
                        JoinValue::One(rows.into_iter().next())
                    };
                    let source = RecordSource::joined(
                        group.parent,
                        [(
                            store
                                .model_fields
                                .storage_model_name(EntityRole::User, "user")
                                .to_owned(),
                            users.raw_value(),
                        )],
                    );
                    Ok((source, users))
                })
                .collect::<AuthResult<Vec<_>>>()
        })
        .await?;
    let (sources, users): (Vec<_>, Vec<_>) = selected.into_iter().unzip();
    let users = Arc::new(users);
    let continuation = store.clone();
    let projected = store
        .project_record_sources_owned_batches_then(
            role,
            &fields,
            sources,
            |_, fields| Ok(fields),
            move |ready| {
                let users = users.clone();
                let store = continuation.clone();
                async move {
                    let selected = ready
                        .iter()
                        .map(|(index, _)| required(users.get(*index)).cloned())
                        .collect::<AuthResult<Vec<_>>>()?;
                    let projected = store.output_user_relations(selected).await?;
                    ready
                        .into_iter()
                        .zip(projected)
                        .map(|((index, mut fields), user)| {
                            let _ = fields.insert("user".into(), relation_value(user)?);
                            Ok((index, Value::from(fields)))
                        })
                        .collect()
                }
            },
        )
        .await?;
    Ok(projected.into())
}

fn relation_value(user: JoinValue<UserView>) -> AuthResult<Value> {
    relation(user, |user| Ok(FieldMap::from(user)))
}
