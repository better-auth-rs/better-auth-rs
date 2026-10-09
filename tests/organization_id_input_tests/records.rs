use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Model {
    Organization,
    Member,
    Invitation,
    Team,
    Role,
}

impl Model {
    pub(super) const ALL: [Self; 5] = [
        Self::Organization,
        Self::Member,
        Self::Invitation,
        Self::Team,
        Self::Role,
    ];

    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Organization => "organization",
            Self::Member => "member",
            Self::Invitation => "invitation",
            Self::Team => "team",
            Self::Role => "organizationRole",
        }
    }

    pub(super) fn table(self) -> &'static str {
        if self == Self::Role {
            "organization_role"
        } else {
            self.name()
        }
    }

    pub(super) fn entity(self) -> EntityRole {
        match self {
            Self::Organization => EntityRole::Organization,
            Self::Member => EntityRole::Member,
            Self::Invitation => EntityRole::Invitation,
            Self::Team => EntityRole::Team,
            Self::Role => EntityRole::OrganizationRole,
        }
    }

    pub(super) fn references(self) -> &'static [&'static str] {
        match self {
            Self::Organization => &[],
            Self::Member => &["organizationId", "userId"],
            Self::Invitation => &["organizationId", "inviterId"],
            Self::Team | Self::Role => &["organizationId"],
        }
    }

    pub(super) fn columns(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::Organization => &[
                ("id", "id"),
                ("name", "name"),
                ("slug", "slug"),
                ("logo", "logo"),
                ("metadata", "metadata"),
                ("createdAt", "created_at"),
                ("auth_updated_at", "updated_at"),
            ],
            Self::Member => &[
                ("id", "id"),
                ("organizationId", "organization_id"),
                ("userId", "user_id"),
                ("role", "role"),
                ("createdAt", "created_at"),
            ],
            Self::Invitation => &[
                ("teamId", "team_id"),
                ("id", "id"),
                ("organizationId", "organization_id"),
                ("email", "email"),
                ("role", "role"),
                ("status", "status"),
                ("inviterId", "inviter_id"),
                ("expiresAt", "expires_at"),
                ("createdAt", "created_at"),
            ],
            Self::Team => &[
                ("id", "id"),
                ("name", "name"),
                ("organizationId", "organization_id"),
                ("createdAt", "created_at"),
                ("updatedAt", "updated_at"),
                ("memberCount", "member_count"),
            ],
            Self::Role => &[
                ("id", "id"),
                ("organizationId", "organization_id"),
                ("role", "role"),
                ("permission", "permission"),
                ("createdAt", "created_at"),
                ("updatedAt", "updated_at"),
            ],
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Entry {
    Create(Model),
    Insert(Model),
}

impl Entry {
    pub(super) fn model(self) -> Model {
        match self {
            Self::Create(model) | Self::Insert(model) => model,
        }
    }

    pub(super) fn all() -> Vec<Self> {
        Model::ALL
            .into_iter()
            .map(Self::Create)
            .chain([
                Self::Insert(Model::Organization),
                Self::Insert(Model::Member),
            ])
            .collect()
    }
}

pub(super) fn row(model: Model, id: FieldValue, label: &str) -> FieldMap {
    let mut fields = FieldMap::from([("id".into(), id), ("createdAt".into(), date(0).into())]);
    match model {
        Model::Organization => fields.extend([
            ("name".into(), label.into()),
            ("slug".into(), label.into()),
            ("logo".into(), FieldValue::Null),
            ("metadata".into(), "{}".into()),
        ]),
        Model::Member => fields.extend([
            ("organizationId".into(), "parent".into()),
            ("userId".into(), "owner".into()),
            ("role".into(), label.into()),
        ]),
        Model::Invitation => fields.extend([
            ("organizationId".into(), "parent".into()),
            (
                "email".into(),
                format!("{label}@organization-id-input.test").into(),
            ),
            ("role".into(), label.into()),
            ("status".into(), "pending".into()),
            ("teamId".into(), FieldValue::Null),
            ("expiresAt".into(), date(10).into()),
            ("inviterId".into(), "owner".into()),
        ]),
        Model::Team => fields.extend([
            ("name".into(), label.into()),
            ("organizationId".into(), "parent".into()),
            ("memberCount".into(), 0.into()),
            ("updatedAt".into(), FieldValue::Null),
        ]),
        Model::Role => fields.extend([
            ("organizationId".into(), "parent".into()),
            ("role".into(), label.into()),
            ("permission".into(), "{}".into()),
            ("updatedAt".into(), FieldValue::Null),
        ]),
    }
    fields
}

pub(super) async fn create_record<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    entry: Entry,
    id: Option<FieldValue>,
    label: &str,
    mut extras: FieldMap,
) -> AuthResult<FieldMap> {
    let model = entry.model();
    if let Entry::Insert(model) = entry {
        let native_id = id.clone().unwrap_or_default();
        if id.as_ref().is_some_and(FieldValue::is_undefined) {
            let _ = extras.insert("id".into(), FieldValue::Undefined);
        }
        return match model {
            Model::Organization => {
                let mut record = Organization::from_field_values(row(model, native_id, label))?;
                record.additional_fields.extend(extras);
                store.insert_organization(record).await?.field_values()
            }
            Model::Member => {
                let mut record = Member::from_field_values(row(model, native_id, label))?;
                record.additional_fields.extend(extras);
                store.insert_member(record).await?.field_values()
            }
            _ => Err(AuthError::internal(
                "Only Organization and Member have complete-record insertion",
            )),
        };
    }
    let typed_id = match id {
        Some(FieldValue::String(id))
            if matches!(model, Model::Organization | Model::Invitation | Model::Team) =>
        {
            Some(id)
        }
        Some(id) => {
            let _ = extras.insert("id".into(), id);
            None
        }
        None => None,
    };
    match model {
        Model::Organization => store
            .create_organization(CreateOrganization {
                id: typed_id,
                name: label.into(),
                slug: label.into(),
                logo: None.into(),
                metadata: Some(FieldValue::from(FieldMap::new())).into(),
                additional_fields: extras,
            })
            .await?
            .field_values(),
        Model::Member => store
            .create_member(CreateMember {
                organization_id: "parent".into(),
                user_id: "owner".into(),
                role: label.into(),
                additional_fields: extras,
            })
            .await?
            .field_values(),
        Model::Invitation => store
            .create_invitation(CreateInvitation {
                id: typed_id,
                created_at: Some(date(0)),
                status: None,
                team_id: None,
                organization_id: "parent".into(),
                email: format!("{label}@organization-id-input.test"),
                role: label.into(),
                inviter_id: "owner".into(),
                expires_at: date(10),
                additional_fields: extras,
            })
            .await?
            .field_values(),
        Model::Team => store
            .create_team(CreateTeam {
                id: typed_id,
                name: label.into(),
                organization_id: "parent".into(),
                created_at: Some(date(0)),
                updated_at: None,
                additional_fields: {
                    let _ = extras.insert("updatedAt".into(), FieldValue::Null);
                    extras
                },
            })
            .await?
            .field_values(),
        Model::Role => store
            .create_organization_role(CreateOrganizationRole {
                organization_id: "parent".into(),
                role: label.into(),
                permission: FieldMap::new().into(),
                additional_fields: {
                    let _ = extras.insert("updatedAt".into(), FieldValue::Null);
                    extras
                },
            })
            .await?
            .field_values(),
    }
}
