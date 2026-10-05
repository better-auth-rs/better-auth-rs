use async_trait::async_trait;
use better_auth_core::store::{ListOrganizationMembersParams, MemberStore};
use better_auth_core::{CreateMember, Member};
use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

use crate::error::{AuthError, AuthResult};
use crate::models::MemberRow;
use crate::schema::member;
use crate::sql_types::UtcTimestampValue;

use super::{DieselStore, new_id};

/// Filter applied to organization members, parsed from
/// [`ListOrganizationMembersParams`].
enum MemberFilter<'a> {
    None,
    /// The filter can never match (for example, an unparsable timestamp).
    NeverMatches,
    Text {
        field: TextField,
        operator: &'a str,
        value: &'a str,
    },
    CreatedAt {
        operator: &'a str,
        value: chrono::DateTime<Utc>,
    },
}

#[derive(Clone, Copy)]
enum TextField {
    Id,
    OrganizationId,
    UserId,
    Role,
}

#[derive(Clone, Copy)]
enum SortField {
    Text(TextField),
    CreatedAt,
}

fn sort_field(field: &str) -> Option<SortField> {
    match field {
        "id" => Some(SortField::Text(TextField::Id)),
        "organizationId" => Some(SortField::Text(TextField::OrganizationId)),
        "userId" => Some(SortField::Text(TextField::UserId)),
        "role" => Some(SortField::Text(TextField::Role)),
        "createdAt" => Some(SortField::CreatedAt),
        _ => None,
    }
}

fn member_filter(params: &ListOrganizationMembersParams) -> MemberFilter<'_> {
    let (Some(field), Some(value)) = (
        params.filter_field.as_deref(),
        params.filter_value.as_deref(),
    ) else {
        return MemberFilter::None;
    };
    let operator = params.filter_operator.as_deref().unwrap_or("eq");

    match sort_field(field) {
        Some(SortField::Text(field)) => MemberFilter::Text {
            field,
            operator,
            value,
        },
        Some(SortField::CreatedAt) => match chrono::DateTime::parse_from_rfc3339(value) {
            Ok(parsed) => MemberFilter::CreatedAt {
                operator,
                value: parsed.with_timezone(&Utc),
            },
            Err(_) => MemberFilter::NeverMatches,
        },
        None => MemberFilter::None,
    }
}

/// Escape `LIKE` wildcards so that `value` matches literally.
fn escape_like(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(character, '\\' | '%' | '_') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

/// Build a boxed member query for the organization with the filter applied.
///
/// A macro rather than a function: the boxed query type names the backend,
/// and each backend arm of `run_query!` supplies a different one.
macro_rules! filtered_members {
    ($params:expr, $filter:expr, $select:expr) => {{
        let mut query = member::table
            .filter(member::organization_id.eq(&$params.organization_id))
            .select($select)
            .into_boxed();
        match $filter {
            MemberFilter::None => {}
            MemberFilter::NeverMatches => {
                query = query.filter(member::id.eq("__better_auth_never_matches__"));
            }
            MemberFilter::Text {
                field,
                operator,
                value,
            } => {
                let value: &str = value;
                macro_rules! apply {
                    ($column:expr) => {
                        match *operator {
                            "eq" => query = query.filter($column.eq(value)),
                            "ne" => query = query.filter($column.ne(value)),
                            "contains" => {
                                query = query.filter(
                                    $column
                                        .like(format!("%{}%", escape_like(value)))
                                        .escape('\\'),
                                )
                            }
                            "gt" => query = query.filter($column.gt(value)),
                            "gte" => query = query.filter($column.ge(value)),
                            "lt" => query = query.filter($column.lt(value)),
                            "lte" => query = query.filter($column.le(value)),
                            _ => {}
                        }
                    };
                }
                match field {
                    TextField::Id => apply!(member::id),
                    TextField::OrganizationId => apply!(member::organization_id),
                    TextField::UserId => apply!(member::user_id),
                    TextField::Role => apply!(member::role),
                }
            }
            MemberFilter::CreatedAt { operator, value } => {
                let value = UtcTimestampValue(*value);
                match *operator {
                    "eq" => query = query.filter(member::created_at.eq(value)),
                    "ne" => query = query.filter(member::created_at.ne(value)),
                    "gt" => query = query.filter(member::created_at.gt(value)),
                    "gte" => query = query.filter(member::created_at.ge(value)),
                    "lt" => query = query.filter(member::created_at.lt(value)),
                    "lte" => query = query.filter(member::created_at.le(value)),
                    _ => {}
                }
            }
        }
        query
    }};
}

#[async_trait]
impl MemberStore for DieselStore {
    async fn create_member(&self, member: CreateMember) -> AuthResult<Member> {
        let row = MemberRow {
            id: new_id(),
            organization_id: member.organization_id,
            user_id: member.user_id,
            role: member.role,
            created_at: Utc::now(),
        };

        run_query!(self, |c| {
            diesel::insert_into(member::table)
                .values(row)
                .returning(MemberRow::as_returning())
                .get_result(c)
                .await
        })
        .map(Member::from)
    }

    async fn get_member(&self, organization_id: &str, user_id: &str) -> AuthResult<Option<Member>> {
        run_query!(self, |c| {
            member::table
                .filter(member::organization_id.eq(organization_id))
                .filter(member::user_id.eq(user_id))
                .select(MemberRow::as_select())
                .first(c)
                .await
                .optional()
        })
        .map(|row| row.map(Member::from))
    }

    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<Member>> {
        run_query!(self, |c| {
            member::table
                .find(id)
                .select(MemberRow::as_select())
                .first(c)
                .await
                .optional()
        })
        .map(|row| row.map(Member::from))
    }

    async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<Member> {
        run_query!(self, |c| {
            diesel::update(member::table.find(member_id))
                .set(member::role.eq(role))
                .returning(MemberRow::as_returning())
                .get_result(c)
                .await
                .optional()
        })?
        .map(Member::from)
        .ok_or_else(|| AuthError::not_found("Member not found"))
    }

    async fn delete_member(&self, member_id: &str) -> AuthResult<()> {
        let _ = run_query!(self, |c| {
            diesel::delete(member::table.find(member_id))
                .execute(c)
                .await
        })?;
        Ok(())
    }

    async fn list_organization_members(&self, organization_id: &str) -> AuthResult<Vec<Member>> {
        run_query!(self, |c| {
            member::table
                .filter(member::organization_id.eq(organization_id))
                .order(member::created_at.asc())
                .select(MemberRow::as_select())
                .load(c)
                .await
        })
        .map(|rows| rows.into_iter().map(Member::from).collect())
    }

    async fn query_organization_members(
        &self,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<(Vec<Member>, usize)> {
        let filter = member_filter(params);
        // Without a known sort field the order is `createdAt` ascending,
        // whatever the requested direction.
        let (sort, descending) = match params.sort_by.as_deref().and_then(sort_field) {
            Some(field) => (
                field,
                matches!(params.sort_direction.as_deref(), Some("desc")),
            ),
            None => (SortField::CreatedAt, false),
        };
        let offset = params.offset.map(i64::try_from).transpose();
        let limit = params.limit.map(i64::try_from).transpose();
        let (Ok(offset), Ok(limit)) = (offset, limit) else {
            return Err(AuthError::bad_request(
                "Pagination exceeds the supported range",
            ));
        };

        let (rows, total) = run_query!(self, |c| {
            async {
                let total: i64 = filtered_members!(params, &filter, diesel::dsl::count_star())
                    .get_result(c)
                    .await?;

                let mut query = filtered_members!(params, &filter, MemberRow::as_select());
                macro_rules! order {
                    ($column:expr) => {
                        if descending {
                            query.order($column.desc())
                        } else {
                            query.order($column.asc())
                        }
                    };
                }
                query = match sort {
                    SortField::Text(TextField::Id) => order!(member::id),
                    SortField::Text(TextField::OrganizationId) => order!(member::organization_id),
                    SortField::Text(TextField::UserId) => order!(member::user_id),
                    SortField::Text(TextField::Role) => order!(member::role),
                    SortField::CreatedAt => order!(member::created_at),
                };
                if let Some(offset) = offset {
                    query = query.offset(offset);
                }
                if let Some(limit) = limit {
                    query = query.limit(limit);
                }
                let rows = query.load(c).await?;
                Ok::<_, diesel::result::Error>((rows, total))
            }
            .await
        })?;

        Ok((
            rows.into_iter().map(Member::from).collect(),
            usize::try_from(total).unwrap_or_default(),
        ))
    }

    async fn count_organization_members(&self, organization_id: &str) -> AuthResult<i64> {
        run_query!(self, |c| {
            member::table
                .filter(member::organization_id.eq(organization_id))
                .count()
                .get_result(c)
                .await
        })
    }

    async fn count_organization_owners(&self, organization_id: &str) -> AuthResult<i64> {
        run_query!(self, |c| {
            member::table
                .filter(member::organization_id.eq(organization_id))
                .filter(member::role.eq("owner"))
                .count()
                .get_result(c)
                .await
        })
    }
}
