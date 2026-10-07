use super::*;

use super::super::account_joins::user_value;

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
                    if row.read(&predicate)? {
                        selected = Some(row);
                        break;
                    }
                }
                let Some(member) = selected else {
                    return Ok(None);
                };
                let native_member = native
                    .then(|| member.read(|row| Ok(row.clone())))
                    .transpose()?;
                let users = if let Some(snapshot) = &native_member {
                    let (_, storage) =
                        super::super::fields::record_fields(EntityRole::Member, snapshot, fields)?;
                    let selected = selected_users(
                        state,
                        (&join.logical_to, &join.to),
                        &storage.get(&join.from).cloned().unwrap_or_default(),
                    )?;
                    let mut page = Vec::new();
                    let mut seen = Vec::new();
                    for user in selected {
                        if page.len() as f64 >= if join.many { limit } else { 1.0 } {
                            break;
                        }
                        if join.many {
                            let id = user.read(|user| Ok(user.id.field_value()))?;
                            if seen.iter().any(|seen: &Value| seen.same_value_zero(&id)) {
                                continue;
                            }
                            seen.push(id);
                        }
                        page.push(user);
                    }
                    Some(page)
                } else {
                    None
                };
                Ok(Some((member, native_member, users)))
            })
            .await?
        };
        let Some((member, native_member, native_users)) = selected else {
            return Ok(None);
        };
        let member = match native_member {
            Some(member) => self.output_member(member).await?,
            None => self
                .output_record_refs(EntityRole::Member, vec![member])
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| AuthError::internal("Member projection lost its selected row"))?,
        };
        let users = match native_users {
            Some(users) => users,
            None => {
                let from = join.fallback_from(
                    (
                        EntityRole::Member,
                        "member",
                        &MemberUser::field_schema(&fields),
                    ),
                    &self.model_fields,
                )?;
                let value = member
                    .field_values()?
                    .get(&from)
                    .cloned()
                    .unwrap_or_default();
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
                        let value = self.memory_field_query(&self.config.user, &logical, value)?;
                        let field = crate::store::ResolvedJoin::user_field(&self.config, &logical);
                        crate::user_query::bind_filter(&field, &value)?
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
        MemberUser::finish(&join, member, projected, require_user)
    }
}
