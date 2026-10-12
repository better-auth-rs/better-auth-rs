#![expect(
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract."
)]

use super::*;
use crate::store::schema::SchemaConfiguration;
use crate::user_fields::UserFieldConfig;

fn configuration(config: AuthConfig, secondary_storage: bool) -> SchemaConfiguration {
    SchemaConfiguration {
        config: Arc::new(config),
        plugins: Vec::new(),
        metadata: Default::default(),
        secondary_storage,
        rate_limit: Default::default(),
    }
}

fn names(fields: &ModelFields) -> Vec<&'static str> {
    fields
        .active_models()
        .into_iter()
        .map(|(_, name)| name)
        .collect()
}

#[test]
fn builtin_plugin_names_do_not_declare_plugin_models() {
    let mut settings = configuration(AuthConfig::default(), false);
    settings.plugins = vec![
        "organization",
        "api-key",
        "device-authorization",
        "passkey",
        "two-factor",
        "jwt",
        "siwe",
    ];
    settings.metadata = [
        ("organization.teams_enabled".into(), true.into()),
        ("organization.dynamic_access_control".into(), true.into()),
    ]
    .into();
    let mut fields = ModelFields::default();
    fields.set_schema_configuration(&settings);
    assert_eq!(
        names(&fields),
        ["user", "session", "account", "verification"]
    );
    for name in [
        "organization",
        "team",
        "organizationRole",
        "apikey",
        "deviceCode",
        "passkey",
        "twoFactor",
        "jwks",
        "walletAddress",
    ] {
        assert!(fields.resolve_model_name(name, &|_, _| false).is_err());
    }
}

#[test]
fn native_declarations_activate_without_a_builtin_plugin_before_or_after_configuration() {
    for configure_first in [false, true] {
        for empty in [false, true] {
            let mut fields = ModelFields::default();
            if configure_first {
                fields.set_schema_configuration(&configuration(AuthConfig::default(), false));
            }
            let declaration = if empty {
                UserConfig::default()
            } else {
                UserConfig {
                    additional_fields: Some([("label".into(), UserFieldConfig::default())].into()),
                }
            };
            fields.register(EntityRole::Passkey, declaration);
            fields
                .set_model_name(EntityRole::Passkey, Some("declared_credentials"))
                .unwrap();
            if !configure_first {
                fields.set_schema_configuration(&configuration(AuthConfig::default(), false));
            }
            assert_eq!(
                names(&fields),
                ["user", "session", "account", "verification", "passkey"]
            );
            for name in ["passkey", "declared_credentials"] {
                assert_eq!(
                    fields.resolve_model_name(name, &|_, _| false).unwrap(),
                    "passkey"
                );
            }
            let declared = fields.plugin_fields(EntityRole::Passkey);
            assert_eq!(
                declared
                    .fields()
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                if empty { vec![] } else { vec!["label"] }
            );
        }
    }
}

#[test]
fn standalone_partial_declarations_keep_native_defaults_until_runtime_configuration() {
    let mut fields = ModelFields::default();
    fields.register(
        EntityRole::Passkey,
        UserConfig {
            additional_fields: Some([("label".into(), UserFieldConfig::default())].into()),
        },
    );
    assert_eq!(
        fields.resolve_model_name("passkey", &|_, _| false).unwrap(),
        "passkey"
    );
    let standalone = fields.plugin_fields(EntityRole::Passkey);
    assert!(standalone.fields().contains_key("publicKey"));
    assert!(standalone.fields().contains_key("credentialID"));
    assert!(standalone.fields().contains_key("label"));
    fields.set_schema_configuration(&configuration(AuthConfig::default(), false));
    assert_eq!(
        fields
            .plugin_fields(EntityRole::Passkey)
            .fields()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["label"]
    );
}

#[test]
fn standalone_organization_joins_add_only_missing_declarations_and_keep_runtime_history() {
    let mut fields = ModelFields::default();
    fields.register(
        EntityRole::Team,
        UserConfig {
            additional_fields: Some(
                [(
                    "label".into(),
                    UserFieldConfig {
                        field_name: Some("stored_label".into()),
                        ..Default::default()
                    },
                )]
                .into(),
            ),
        },
    );
    fields
        .set_model_name(EntityRole::Team, Some("declared_teams"))
        .unwrap();
    fields.begin_id_query(EntityRole::Team).unwrap();
    let schema = fields.organization_join_schema();
    assert!(schema.schema_models.is_none());
    assert_eq!(
        names(&schema),
        [
            "user",
            "session",
            "account",
            "verification",
            "team",
            "organization",
            "organizationRole",
            "teamMember",
            "member",
            "invitation",
        ]
    );
    assert_eq!(
        schema
            .resolve_model_name("declared_teams", &|_, _| false)
            .unwrap(),
        "team"
    );
    let team = schema.plugin_fields(EntityRole::Team);
    assert_eq!(
        team.fields().keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "name",
            "memberCount",
            "organizationId",
            "createdAt",
            "updatedAt",
            "label",
        ]
    );
    assert_eq!(
        team.fields().get("label").unwrap().field_name.as_deref(),
        Some("stored_label")
    );
    assert_eq!(schema.user_plugin_fields(), fields.user_plugin_fields());
    assert_eq!(
        schema.session_plugin_fields(),
        fields.session_plugin_fields()
    );
    assert!(schema.id_input_active(EntityRole::Team).unwrap());
    schema.begin_id_output(EntityRole::Team).unwrap();
    assert!(!fields.id_input_active(EntityRole::Team).unwrap());
    assert_eq!(
        names(&fields),
        ["user", "session", "account", "verification", "team"]
    );
}

#[test]
fn initialized_organization_joins_preserve_context_without_adding_declarations() {
    let mut settings = configuration(AuthConfig::default(), true);
    settings.metadata = [
        ("admin.enabled".into(), true.into()),
        ("organization.teams_enabled".into(), true.into()),
    ]
    .into();
    let mut fields = ModelFields::default();
    fields.set_schema_configuration(&settings);
    fields.begin_id_query(EntityRole::Account).unwrap();
    let schema = fields.organization_join_schema();
    assert_eq!(names(&schema), ["user", "account"]);
    assert_eq!(
        schema.user_plugin_fields(),
        ["role", "banned", "banReason", "banExpires"]
    );
    assert_eq!(
        schema.session_plugin_fields(),
        ["impersonatedBy", "activeTeamId"]
    );
    assert!(schema.id_input_active(EntityRole::Account).unwrap());
}

#[test]
fn secondary_storage_hides_core_declarations_before_resolving_physical_aliases() {
    for sessions in [false, true] {
        for verifications in [false, true] {
            let mut fields = ModelFields::default();
            fields.register(EntityRole::Session, UserConfig::default());
            fields.register(EntityRole::Verification, UserConfig::default());
            fields
                .set_model_name(EntityRole::User, Some("session"))
                .unwrap();
            fields
                .set_model_name(EntityRole::Account, Some("verification"))
                .unwrap();
            fields.register(EntityRole::Passkey, UserConfig::default());
            let mut config = AuthConfig::default();
            config.session.store_session_in_database = Some(sessions);
            config.verification.store_in_database = verifications;
            fields.set_schema_configuration(&configuration(config, true));
            let mut expected = vec!["user"];
            if sessions {
                expected.push("session");
            }
            expected.push("account");
            if verifications {
                expected.push("verification");
            }
            expected.push("passkey");
            assert_eq!(names(&fields), expected);
            assert_eq!(
                fields.resolve_model_name("session", &|_, _| false).unwrap(),
                if sessions { "session" } else { "user" }
            );
            assert_eq!(
                fields
                    .resolve_model_name("verification", &|_, _| false)
                    .unwrap(),
                if verifications {
                    "verification"
                } else {
                    "account"
                }
            );
        }
    }
}

#[test]
fn organization_flags_select_declarations_in_upstream_schema_order() {
    for teams in [false, true] {
        for dynamic_roles in [false, true] {
            let mut fields = ModelFields::default();
            fields.register_organization_schema(&Default::default(), teams, dynamic_roles);
            fields.set_schema_configuration(&configuration(AuthConfig::default(), false));
            let mut expected = vec!["user", "session", "account", "verification", "organization"];
            if dynamic_roles {
                expected.push("organizationRole");
            }
            if teams {
                expected.extend(["team", "teamMember"]);
            }
            expected.extend(["member", "invitation"]);
            assert_eq!(names(&fields), expected);
            assert_eq!(
                fields
                    .resolve_model_name("organizationRole", &|_, _| false)
                    .is_ok(),
                dynamic_roles
            );
            assert_eq!(
                fields.resolve_model_name("team", &|_, _| false).is_ok(),
                teams
            );
        }
    }
}

#[test]
fn disabled_dynamic_roles_preserve_an_earlier_explicit_declaration() {
    let mut fields = ModelFields::default();
    fields.register(
        EntityRole::OrganizationRole,
        UserConfig {
            additional_fields: Some(
                [(
                    "label".into(),
                    UserFieldConfig {
                        required: Some(true),
                        ..Default::default()
                    },
                )]
                .into(),
            ),
        },
    );
    fields
        .set_model_name(EntityRole::OrganizationRole, Some("declared_roles"))
        .unwrap();
    let organization = crate::organization_fields::OrganizationFields {
        organization_role: UserConfig {
            additional_fields: Some([("phantom".into(), UserFieldConfig::default())].into()),
        },
        ..Default::default()
    };
    fields.register_organization_schema(&organization, true, false);
    fields.set_schema_configuration(&configuration(AuthConfig::default(), false));
    assert_eq!(
        names(&fields),
        [
            "user",
            "session",
            "account",
            "verification",
            "organizationRole",
            "organization",
            "team",
            "teamMember",
            "member",
            "invitation",
        ]
    );
    assert_eq!(
        fields
            .resolve_model_name("declared_roles", &|_, _| false)
            .unwrap(),
        "organizationRole"
    );
    assert_eq!(
        fields
            .plugin_fields(EntityRole::OrganizationRole)
            .fields()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["label"]
    );
    let resolved = fields.organization_fields(Default::default());
    let role = resolved.fields_for(EntityRole::OrganizationRole).unwrap();
    assert_eq!(
        role.fields().keys().map(String::as_str).collect::<Vec<_>>(),
        ["label"]
    );
    assert_eq!(role.fields().get("label").unwrap().required, Some(true));
}

#[test]
fn initialized_organization_fields_keep_explicit_empty_and_partial_declarations() {
    for role in [
        EntityRole::Organization,
        EntityRole::Team,
        EntityRole::Member,
        EntityRole::Invitation,
        EntityRole::OrganizationRole,
    ] {
        for empty in [false, true] {
            let mut fields = ModelFields::default();
            let declaration = UserConfig {
                additional_fields: Some(if empty {
                    Default::default()
                } else {
                    [(
                        "label".into(),
                        UserFieldConfig {
                            required: Some(true),
                            ..Default::default()
                        },
                    )]
                    .into()
                }),
            };
            fields.register(role, declaration);
            fields.set_schema_configuration(&configuration(AuthConfig::default(), false));
            let resolved = fields.organization_fields(Default::default());
            let actual = resolved.fields_for(role).unwrap();
            assert_eq!(
                actual
                    .fields()
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                if empty { vec![] } else { vec!["label"] }
            );
            if !empty {
                assert_eq!(actual.fields().get("label").unwrap().required, Some(true));
            }
        }
    }
}

#[test]
fn dynamic_role_partial_applies_to_own_options_before_external_declarations_merge() {
    let mut fields = ModelFields::default();
    let required = || UserFieldConfig {
        required: Some(true),
        ..Default::default()
    };
    fields.register(
        EntityRole::OrganizationRole,
        UserConfig {
            additional_fields: Some([("before".into(), required())].into()),
        },
    );
    fields.register_organization_schema(
        &crate::organization_fields::OrganizationFields {
            organization_role: UserConfig {
                additional_fields: Some([("own".into(), required())].into()),
            },
            ..Default::default()
        },
        false,
        true,
    );
    assert_eq!(
        fields
            .fields(EntityRole::OrganizationRole)
            .fields()
            .get("own")
            .unwrap()
            .required,
        Some(false)
    );
    assert_eq!(
        fields
            .fields(EntityRole::OrganizationRole)
            .fields()
            .get("before")
            .unwrap()
            .required,
        Some(true)
    );
    fields.register(
        EntityRole::OrganizationRole,
        UserConfig {
            additional_fields: Some(
                [("after".into(), required()), ("own".into(), required())].into(),
            ),
        },
    );
    fields.set_schema_configuration(&configuration(AuthConfig::default(), false));
    let resolved = fields.organization_fields(Default::default());
    let role = resolved.fields_for(EntityRole::OrganizationRole).unwrap();
    for name in [
        "before",
        "after",
        "own",
        "organizationId",
        "role",
        "permission",
        "createdAt",
    ] {
        assert_eq!(
            role.fields().get(name).unwrap().required,
            Some(true),
            "{name}"
        );
    }
    assert_eq!(
        role.fields().get("updatedAt").unwrap().required,
        Some(false)
    );
}
