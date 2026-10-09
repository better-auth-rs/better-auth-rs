use super::*;

use super::super::account_joins::{native_relation, user_value};

fn selected_users(
    state: &State,
    fields: (&str, &str),
    value: &Value,
) -> AuthResult<Vec<RowRef<UserView>>> {
    state
        .users
        .select_refs(|user| user_value(user, fields.0, fields.1).strict_equals(value))
}

impl EphemeralStore {
    pub(in crate::store::ephemeral) async fn read_member_user(
        &self,
        predicate: impl Fn(&Member) -> AuthResult<bool> + Send,
        require_user: bool,
    ) -> AuthResult<Option<MemberUser>> {
        let fields = self.organization_fields()?.member;
        let join =
            MemberUser::resolve_schema(&self.config, &fields, &self.model_fields, |_, _| false)?;
        let native = self.config.advanced.database.joins == Some(true);
        let limit = self.config.advanced.database.find_many_limit();
        let selected = {
            let join = &join;
            let fields = &fields;
            self.raw("member", "findOne", move |state| {
                let mut selected = None;
                for row in state.members.select_refs(|_| true)? {
                    if row.read(|stored| {
                        predicate(&super::super::organization_rows::view(stored, fields)?)
                    })? {
                        selected = Some(row);
                        break;
                    }
                }
                let Some(member) = selected else {
                    return Ok(None);
                };
                let (source, users) = if native {
                    let parent = member.read(|row| Ok(row.clone()))?;
                    let users = native_relation(
                        selected_users(
                            state,
                            (&join.logical_to, &join.to),
                            &parent.get(&join.from).cloned().unwrap_or_default(),
                        )?,
                        join,
                        limit,
                        |user| user.id.field_value(),
                    )?;
                    let source = RecordSource::joined(
                        parent,
                        [(
                            self.model_fields
                                .storage_model_name(EntityRole::User, "user")
                                .to_owned(),
                            users.raw_value(),
                        )],
                    );
                    (source, Some(users))
                } else {
                    (RecordSource::Live(member), None)
                };
                Ok(Some((source, users)))
            })
            .await?
        };
        let Some((source, native_users)) = selected else {
            return Ok(None);
        };
        let mut parent = self
            .project_record_sources(
                EntityRole::Member,
                &self.field_config(EntityRole::Member)?,
                vec![source],
            )
            .await?
            .remove(0);
        let users = match native_users {
            Some(JoinValue::One(user)) => user.into_iter().collect(),
            Some(JoinValue::Many(users)) => users,
            None => {
                let from = join.fallback_from(
                    (
                        EntityRole::Member,
                        "member",
                        &MemberUser::field_schema(&fields),
                    ),
                    &self.model_fields,
                )?;
                let value = parent.get(&from).cloned().unwrap_or_default();
                if value.is_null() || value.is_undefined() {
                    Vec::new()
                } else {
                    let (logical, physical) = join.fallback_target(
                        (EntityRole::User, "user", &self.config.user),
                        &self.model_fields,
                    )?;
                    let value = if logical == "id" {
                        self.memory_primary_id_query(&value)?
                    } else {
                        self.memory_field_query(&self.user_schema(), &logical, value)?
                    };
                    self.raw(
                        "user",
                        if join.many { "findMany" } else { "findOne" },
                        |state| {
                            Ok(crate::query::paginate_memory(
                                selected_users(state, (&logical, &physical), &value)?,
                                Some(if join.many { limit } else { 1.0 }),
                                None,
                            ))
                        },
                    )
                    .await?
                }
            }
        };
        let mut projected = Vec::with_capacity(users.len());
        // The adapter awaits each joined user's complete projection before starting the next user.
        for user in users {
            projected.extend(
                self.output_user_refs(vec![user])
                    .await?
                    .iter()
                    .map(crate::MemberUserView::from_user),
            );
        }
        let _ = parent.shift_remove("user");
        MemberUser::finish(
            &join,
            Member::from_field_values(parent)?,
            projected,
            require_user,
        )
    }
}
