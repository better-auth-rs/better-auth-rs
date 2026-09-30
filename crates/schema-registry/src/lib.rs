//! Authoritative field registry for better-auth entity schemas.
//!
//! Shared by the `AuthEntity` proc macro (for compile-time validation)
//! and the CLI (for code generation). This is the single source of truth
//! for which fields belong to core vs which are plugin-provided.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntityRole {
    User,
    Session,
    Account,
    Verification,
}

#[derive(Clone, Copy, Debug)]
pub struct FieldDef {
    pub name: &'static str,
    /// Rust type as it appears in a SeaORM `Model` struct,
    /// e.g. `"Option<String>"`, `"bool"`, `"DateTimeUtc"`, `"Json"`.
    pub ty: &'static str,
    pub is_primary_key: bool,
    pub column_name: Option<&'static str>,
}

#[derive(Clone, Copy, Debug)]
pub struct PluginSchema {
    pub name: &'static str,
    pub user_fields: &'static [FieldDef],
    pub session_fields: &'static [FieldDef],
    pub extra_entities: &'static [ExtraEntitySchema],
}

#[derive(Clone, Copy, Debug)]
pub struct ExtraEntitySchema {
    pub mod_name: &'static str,
    pub table_name: &'static str,
    pub role: Option<EntityRole>,
    pub fields: &'static [FieldDef],
}

macro_rules! f {
    ($name:expr, $ty:expr) => {
        FieldDef {
            name: $name,
            ty: $ty,
            is_primary_key: false,
            column_name: None,
        }
    };
}

macro_rules! pk {
    ($name:expr, $ty:expr) => {
        FieldDef {
            name: $name,
            ty: $ty,
            is_primary_key: true,
            column_name: None,
        }
    };
}

macro_rules! f_col {
    ($name:expr, $ty:expr, $column_name:expr) => {
        FieldDef {
            name: $name,
            ty: $ty,
            is_primary_key: false,
            column_name: Some($column_name),
        }
    };
}

// ── Core fields ──────────────────────────────────────────────────────

static USER_CORE: &[FieldDef] = &[
    pk!("id", "String"),
    f!("name", "Option<String>"),
    f!("email", "Option<String>"),
    f!("email_verified", "bool"),
    f!("image", "Option<String>"),
    f!("created_at", "DateTimeUtc"),
    f!("updated_at", "DateTimeUtc"),
];

static SESSION_CORE: &[FieldDef] = &[
    pk!("id", "String"),
    f!("expires_at", "DateTimeUtc"),
    f!("token", "String"),
    f!("created_at", "DateTimeUtc"),
    f!("updated_at", "DateTimeUtc"),
    f!("ip_address", "Option<String>"),
    f!("user_agent", "Option<String>"),
    f!("user_id", "String"),
    f!("active", "bool"),
];

static ACCOUNT_CORE: &[FieldDef] = &[
    pk!("id", "String"),
    f!("account_id", "String"),
    f!("provider_id", "String"),
    f!("user_id", "String"),
    f!("access_token", "Option<String>"),
    f!("refresh_token", "Option<String>"),
    f!("id_token", "Option<String>"),
    f!("access_token_expires_at", "Option<DateTimeUtc>"),
    f!("refresh_token_expires_at", "Option<DateTimeUtc>"),
    f!("scope", "Option<String>"),
    f!("password", "Option<String>"),
    f!("created_at", "DateTimeUtc"),
    f!("updated_at", "DateTimeUtc"),
];

static VERIFICATION_CORE: &[FieldDef] = &[
    pk!("id", "String"),
    f!("identifier", "String"),
    f!("value", "String"),
    f!("expires_at", "DateTimeUtc"),
    f!("created_at", "DateTimeUtc"),
    f!("updated_at", "DateTimeUtc"),
];

/// Core fields that are always required for a given entity role.
pub fn core_fields(role: EntityRole) -> &'static [FieldDef] {
    match role {
        EntityRole::User => USER_CORE,
        EntityRole::Session => SESSION_CORE,
        EntityRole::Account => ACCOUNT_CORE,
        EntityRole::Verification => VERIFICATION_CORE,
    }
}

// ── Plugin schemas ───────────────────────────────────────────────────

static PLUGINS: &[PluginSchema] = &[
    PluginSchema {
        name: "jwt",
        user_fields: &[],
        session_fields: &[],
        extra_entities: &[ExtraEntitySchema {
            mod_name: "jwk",
            table_name: "jwks",
            role: None,
            fields: &[
                pk!("id", "String"),
                f!("public_key", "String"),
                f!("private_key", "String"),
                f!("created_at", "DateTimeUtc"),
                f!("expires_at", "Option<DateTimeUtc>"),
                f!("alg", "Option<String>"),
                f!("crv", "Option<String>"),
            ],
        }],
    },
    PluginSchema {
        name: "anonymous",
        user_fields: &[f!("is_anonymous", "Option<bool>")],
        session_fields: &[],
        extra_entities: &[],
    },
    PluginSchema {
        name: "phone-number",
        user_fields: &[
            f!("phone_number", "Option<String>"),
            f!("phone_number_verified", "Option<bool>"),
        ],
        session_fields: &[],
        extra_entities: &[],
    },
    PluginSchema {
        name: "siwe",
        user_fields: &[],
        session_fields: &[],
        extra_entities: &[ExtraEntitySchema {
            mod_name: "wallet_address",
            table_name: "wallet_address",
            role: None,
            fields: &[
                pk!("id", "String"),
                f!("user_id", "String"),
                f!("address", "String"),
                f!("chain_id", "i64"),
                f!("is_primary", "bool"),
                f!("created_at", "DateTimeUtc"),
            ],
        }],
    },
    PluginSchema {
        name: "username",
        user_fields: &[
            f!("username", "Option<String>"),
            f!("display_username", "Option<String>"),
        ],
        session_fields: &[],
        extra_entities: &[],
    },
    PluginSchema {
        name: "two-factor",
        user_fields: &[f!("two_factor_enabled", "bool")],
        session_fields: &[],
        extra_entities: &[ExtraEntitySchema {
            mod_name: "two_factor",
            table_name: "two_factor",
            role: None,
            fields: &[
                pk!("id", "String"),
                f!("secret", "String"),
                f!("backup_codes", "String"),
                f!("user_id", "String"),
                f!("verified", "bool"),
                f!("failed_verification_count", "i64"),
                f!("locked_until", "Option<DateTimeUtc>"),
                f!("created_at", "DateTimeUtc"),
                f!("updated_at", "DateTimeUtc"),
            ],
        }],
    },
    PluginSchema {
        name: "device-authorization",
        user_fields: &[],
        session_fields: &[],
        extra_entities: &[ExtraEntitySchema {
            mod_name: "device_code",
            table_name: "device_code",
            role: None,
            fields: &[
                pk!("id", "String"),
                f!("device_code", "String"),
                f!("user_code", "String"),
                f!("user_id", "Option<String>"),
                f!("expires_at", "DateTimeUtc"),
                f!("status", "String"),
                f!("last_polled_at", "Option<DateTimeUtc>"),
                f!("polling_interval", "Option<i64>"),
                f!("client_id", "Option<String>"),
                f!("scope", "Option<String>"),
            ],
        }],
    },
    PluginSchema {
        name: "admin",
        user_fields: &[
            f!("role", "Option<String>"),
            f!("banned", "bool"),
            f!("ban_reason", "Option<String>"),
            f!("ban_expires", "Option<DateTimeUtc>"),
            f!("metadata", "Json"),
        ],
        session_fields: &[f!("impersonated_by", "Option<String>")],
        extra_entities: &[],
    },
    PluginSchema {
        name: "organization",
        user_fields: &[],
        session_fields: &[f!("active_organization_id", "Option<String>")],
        extra_entities: &[
            ExtraEntitySchema {
                mod_name: "organization",
                table_name: "organization",
                role: None,
                fields: &[
                    pk!("id", "String"),
                    f!("name", "String"),
                    f!("slug", "String"),
                    f!("logo", "Option<String>"),
                    f!("metadata", "Json"),
                    f!("created_at", "DateTimeUtc"),
                    f!("updated_at", "DateTimeUtc"),
                ],
            },
            ExtraEntitySchema {
                mod_name: "member",
                table_name: "member",
                role: None,
                fields: &[
                    pk!("id", "String"),
                    f!("organization_id", "String"),
                    f!("user_id", "String"),
                    f!("role", "String"),
                    f!("created_at", "DateTimeUtc"),
                ],
            },
            ExtraEntitySchema {
                mod_name: "invitation",
                table_name: "invitation",
                role: None,
                fields: &[
                    pk!("id", "String"),
                    f!("organization_id", "String"),
                    f!("email", "String"),
                    f!("role", "String"),
                    f!("status", "String"),
                    f!("inviter_id", "String"),
                    f!("expires_at", "DateTimeUtc"),
                    f!("created_at", "DateTimeUtc"),
                ],
            },
        ],
    },
    PluginSchema {
        name: "api-key",
        user_fields: &[],
        session_fields: &[],
        extra_entities: &[ExtraEntitySchema {
            mod_name: "api_key",
            table_name: "api_keys",
            role: None,
            fields: &[
                pk!("id", "String"),
                f!("name", "Option<String>"),
                f!("start", "Option<String>"),
                f!("prefix", "Option<String>"),
                f_col!("key_hash", "String", "key"),
                f!("reference_id", "String"),
                f!("config_id", "String"),
                f!("refill_interval", "Option<f64>"),
                f!("refill_amount", "Option<f64>"),
                f!("last_refill_at", "Option<DateTimeUtc>"),
                f!("enabled", "bool"),
                f!("rate_limit_enabled", "bool"),
                f!("rate_limit_time_window", "Option<f64>"),
                f!("rate_limit_max", "Option<f64>"),
                f!("request_count", "Option<f64>"),
                f!("remaining", "Option<f64>"),
                f!("last_request", "Option<DateTimeUtc>"),
                f!("expires_at", "Option<DateTimeUtc>"),
                f!("created_at", "DateTimeUtc"),
                f!("updated_at", "DateTimeUtc"),
                f!("permissions", "Option<String>"),
                f!("metadata", "Option<String>"),
            ],
        }],
    },
    PluginSchema {
        name: "passkey",
        user_fields: &[],
        session_fields: &[],
        extra_entities: &[ExtraEntitySchema {
            mod_name: "passkey",
            table_name: "passkeys",
            role: None,
            fields: &[
                pk!("id", "String"),
                f!("name", "Option<String>"),
                f!("public_key", "String"),
                f!("user_id", "String"),
                f!("credential_id", "String"),
                f!("counter", "i64"),
                f!("device_type", "String"),
                f!("backed_up", "bool"),
                f!("transports", "Option<String>"),
                f!("credential", "String"),
                f!("aaguid", "Option<String>"),
                f!("created_at", "DateTimeUtc"),
                f!("updated_at", "DateTimeUtc"),
            ],
        }],
    },
];

/// Plugin schemas — each plugin can add fields to user and/or session entities.
pub fn plugin_schemas() -> &'static [PluginSchema] {
    PLUGINS
}

/// All plugin field names for a given role (convenience for the macro).
pub fn plugin_field_names(role: EntityRole) -> Vec<&'static str> {
    plugin_schemas()
        .iter()
        .flat_map(|p| match role {
            EntityRole::User => p.user_fields.iter(),
            EntityRole::Session => p.session_fields.iter(),
            EntityRole::Account | EntityRole::Verification => [].iter(),
        })
        .map(|f| f.name)
        .collect()
}

/// Core field names only (convenience for the macro).
pub fn core_field_names(role: EntityRole) -> Vec<&'static str> {
    core_fields(role).iter().map(|f| f.name).collect()
}

/// Database index required by an auth entity.
pub struct IndexDef {
    /// Database columns in index order.
    pub columns: &'static [&'static str],
    /// Whether the index rejects duplicate column values.
    pub unique: bool,
}

macro_rules! index {
    ($($column:literal),+) => { IndexDef { columns: &[$($column),+], unique: false } };
}

macro_rules! unique {
    ($($column:literal),+) => { IndexDef { columns: &[$($column),+], unique: true } };
}

/// Index definitions use database column names. Omit absent plugin columns.
pub fn entity_indexes(table: &str) -> &'static [IndexDef] {
    match table {
        "users" => &[
            unique!("email"),
            unique!("username"),
            unique!("phone_number"),
        ],
        "sessions" => &[unique!("token"), index!("user_id"), index!("expires_at")],
        "accounts" => &[unique!("provider_id", "account_id"), index!("user_id")],
        "verifications" => &[index!("identifier")],
        "two_factor" => &[unique!("user_id")],
        "device_code" => &[
            unique!("device_code"),
            unique!("user_code"),
            index!("user_id"),
            index!("expires_at"),
        ],
        "organization" => &[unique!("slug")],
        "member" => &[unique!("organization_id", "user_id"), index!("user_id")],
        "invitation" => &[index!("organization_id"), index!("email"), index!("status")],
        "api_keys" => &[unique!("key"), index!("reference_id"), index!("config_id")],
        "passkeys" => &[unique!("credential_id"), index!("user_id")],
        "wallet_address" => &[index!("user_id")],
        _ => &[],
    }
}

/// Cascading foreign keys from a column to another entity's primary key.
pub fn entity_foreign_keys(table: &str) -> &'static [(&'static str, &'static str)] {
    match table {
        "sessions" | "accounts" | "two_factor" | "device_code" | "passkeys" | "wallet_address" => {
            &[("user_id", "users")]
        }
        "member" => &[("organization_id", "organization"), ("user_id", "users")],
        "invitation" => &[("organization_id", "organization"), ("inviter_id", "users")],
        // API key references can identify either users or organizations.
        _ => &[],
    }
}
