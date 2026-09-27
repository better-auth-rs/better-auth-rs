//! Diesel table definitions for the Better Auth tables.
//!
//! Applications can join these tables with their own schema, for example:
//!
//! ```ignore
//! diesel::joinable!(posts -> better_auth::diesel::schema::users (author_id));
//! diesel::allow_tables_to_appear_in_same_query!(posts, better_auth::diesel::schema::users);
//! ```

diesel::table! {
    use diesel::sql_types::*;
    use crate::sql_types::*;

    users (id) {
        id -> Text,
        name -> Nullable<Text>,
        email -> Nullable<Text>,
        email_verified -> Bool,
        image -> Nullable<Text>,
        username -> Nullable<Text>,
        display_username -> Nullable<Text>,
        two_factor_enabled -> Bool,
        role -> Nullable<Text>,
        banned -> Bool,
        ban_reason -> Nullable<Text>,
        ban_expires -> Nullable<UtcTimestamp>,
        metadata -> JsonDocument,
        created_at -> UtcTimestamp,
        updated_at -> UtcTimestamp,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use crate::sql_types::*;

    sessions (id) {
        id -> Text,
        expires_at -> UtcTimestamp,
        token -> Text,
        ip_address -> Nullable<Text>,
        user_agent -> Nullable<Text>,
        user_id -> Text,
        impersonated_by -> Nullable<Text>,
        active_organization_id -> Nullable<Text>,
        active -> Bool,
        created_at -> UtcTimestamp,
        updated_at -> UtcTimestamp,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use crate::sql_types::*;

    accounts (id) {
        id -> Text,
        account_id -> Text,
        provider_id -> Text,
        user_id -> Text,
        access_token -> Nullable<Text>,
        refresh_token -> Nullable<Text>,
        id_token -> Nullable<Text>,
        access_token_expires_at -> Nullable<UtcTimestamp>,
        refresh_token_expires_at -> Nullable<UtcTimestamp>,
        scope -> Nullable<Text>,
        password -> Nullable<Text>,
        created_at -> UtcTimestamp,
        updated_at -> UtcTimestamp,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use crate::sql_types::*;

    verifications (id) {
        id -> Text,
        identifier -> Text,
        value -> Text,
        expires_at -> UtcTimestamp,
        created_at -> UtcTimestamp,
        updated_at -> UtcTimestamp,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use crate::sql_types::*;

    organization (id) {
        id -> Text,
        name -> Text,
        slug -> Text,
        logo -> Nullable<Text>,
        metadata -> JsonDocument,
        created_at -> UtcTimestamp,
        updated_at -> UtcTimestamp,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use crate::sql_types::*;

    member (id) {
        id -> Text,
        organization_id -> Text,
        user_id -> Text,
        role -> Text,
        created_at -> UtcTimestamp,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use crate::sql_types::*;

    invitation (id) {
        id -> Text,
        organization_id -> Text,
        email -> Text,
        role -> Text,
        status -> Text,
        inviter_id -> Text,
        expires_at -> UtcTimestamp,
        created_at -> UtcTimestamp,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use crate::sql_types::*;

    two_factor (id) {
        id -> Text,
        secret -> Text,
        backup_codes -> Text,
        user_id -> Text,
        created_at -> UtcTimestamp,
        updated_at -> UtcTimestamp,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use crate::sql_types::*;

    api_keys (id) {
        id -> Text,
        name -> Nullable<Text>,
        start -> Nullable<Text>,
        prefix -> Nullable<Text>,
        #[sql_name = "key"]
        key_hash -> Text,
        reference_id -> Text,
        config_id -> Text,
        refill_interval -> Nullable<Integer>,
        refill_amount -> Nullable<Integer>,
        last_refill_at -> Nullable<UtcTimestamp>,
        enabled -> Bool,
        rate_limit_enabled -> Bool,
        rate_limit_time_window -> Nullable<Integer>,
        rate_limit_max -> Nullable<Integer>,
        request_count -> Nullable<Integer>,
        remaining -> Nullable<Integer>,
        last_request -> Nullable<UtcTimestamp>,
        expires_at -> Nullable<UtcTimestamp>,
        created_at -> UtcTimestamp,
        updated_at -> UtcTimestamp,
        permissions -> Nullable<Text>,
        metadata -> Nullable<Text>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use crate::sql_types::*;

    passkeys (id) {
        id -> Text,
        name -> Nullable<Text>,
        public_key -> Text,
        user_id -> Text,
        credential_id -> Text,
        counter -> BigInt,
        device_type -> Text,
        backed_up -> Bool,
        transports -> Nullable<Text>,
        credential -> Text,
        aaguid -> Nullable<Text>,
        created_at -> UtcTimestamp,
        updated_at -> UtcTimestamp,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use crate::sql_types::*;

    #[sql_name = "device_code"]
    device_codes (id) {
        id -> Text,
        device_code -> Text,
        user_code -> Text,
        user_id -> Nullable<Text>,
        expires_at -> UtcTimestamp,
        status -> Text,
        last_polled_at -> Nullable<UtcTimestamp>,
        polling_interval -> Nullable<BigInt>,
        client_id -> Nullable<Text>,
        scope -> Nullable<Text>,
    }
}

diesel::joinable!(sessions -> users (user_id));
diesel::joinable!(accounts -> users (user_id));
diesel::joinable!(member -> organization (organization_id));
diesel::joinable!(member -> users (user_id));
diesel::joinable!(invitation -> organization (organization_id));
diesel::joinable!(two_factor -> users (user_id));
diesel::joinable!(passkeys -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    users,
    sessions,
    accounts,
    verifications,
    organization,
    member,
    invitation,
    two_factor,
    api_keys,
    passkeys,
    device_codes,
);
