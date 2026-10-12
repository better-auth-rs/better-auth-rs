use super::*;

fn selected_users(
    op: &super::super::operation::MemoryOperation<'_>,
    field: &str,
    value: &Value,
) -> AuthResult<Vec<RowRef<FieldMap>>> {
    op.capture_table(EntityRole::User)?
        .select_refs(|user| Ok(user.field(field)?.unwrap_or_default().strict_equals(value)))
}

impl EphemeralStore {
    pub(in crate::store::ephemeral) async fn read_member_user(
        &self,
        selectors: &[(String, Value)],
        require_user: bool,
    ) -> AuthResult<Option<MemberUser>> {
        let fields = self.organization_fields()?.member;
        let join =
            MemberUser::resolve_schema(&self.config, &fields, &self.model_fields, |_, _| false)?;
        let native = self.config.advanced.database.joins == Some(true);
        let limit = self.config.advanced.database.find_many_limit();
        let selected = {
            let join = &join;
            self.raw("member", "findOne", move |op| {
                let selected = op
                    .capture_table(EntityRole::Member)?
                    .select_refs(|row| super::super::organization_rows::matches(row, selectors))?;
                let (source, users) = if native {
                    let groups = native_relationships(
                        selected.into_iter().map(RecordSource::Live).collect(),
                        &[(EntityRole::User, join, limit)],
                        |_| op.capture_join_table(EntityRole::User),
                    )?;
                    let Some(mut group) = groups.into_iter().next() else {
                        return Ok(None);
                    };
                    let users = group.children.remove(0);
                    let source = RecordSource::joined(
                        group.parent,
                        [(
                            self.model_fields
                                .storage_model_name(EntityRole::User, "user")
                                .to_owned(),
                            raw_relation(&users, join.many),
                        )],
                    );
                    let users = if join.many {
                        JoinValue::Many(users)
                    } else {
                        JoinValue::One(users.into_iter().next())
                    };
                    (source, Some(users))
                } else {
                    let Some(member) = selected.into_iter().next() else {
                        return Ok(None);
                    };
                    (RecordSource::Live(member), None)
                };
                Ok(Some((source, users)))
            })
            .await?
        };
        let Some((source, native_users)) = selected else {
            return Ok(None);
        };
        let parent = self
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
                let from = join
                    .fallback_from((EntityRole::Member, "member", &fields), &self.model_fields)?;
                let value = parent.get(&from).cloned().unwrap_or_default();
                if value.is_null() || value.is_undefined() {
                    Vec::new()
                } else {
                    let (logical, physical) = join.fallback_target(
                        (EntityRole::User, "user", &self.field_policy().user()),
                        &self.model_fields,
                    )?;
                    let value =
                        self.memory_field_query(&self.field_policy().user(), &logical, value)?;
                    self.raw(
                        "user",
                        if join.many { "findMany" } else { "findOne" },
                        |op| {
                            Ok(crate::query::paginate_memory(
                                selected_users(op, &physical, &value)?,
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
        MemberUser::finish(
            &join,
            Member::from_field_values(parent)?,
            projected,
            require_user,
        )
    }
}
