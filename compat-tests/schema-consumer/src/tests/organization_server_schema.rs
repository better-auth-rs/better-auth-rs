pub(super) mod postgres {
    include!(env!(
        "BETTER_AUTH_ORGANIZATION_SERVER_POSTGRES_DEFAULT_SCHEMA"
    ));
}

pub(super) mod mysql {
    include!(env!("BETTER_AUTH_ORGANIZATION_SERVER_MYSQL_DEFAULT_SCHEMA"));
}
