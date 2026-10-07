use super::server_catalog_support::TestResult;
use better_auth::{
    AuthConfig, AuthSchema,
    prelude::{CreateUser, CreateWalletAddress, WalletAddress},
    seaorm::{
        __private_chrono as chrono, DatabaseConnection, SeaOrmAccountModel, SeaOrmPluginModel,
        SeaOrmPluginSchema, SeaOrmSessionModel, SeaOrmStore, SeaOrmUserModel,
        SeaOrmVerificationModel,
        sea_orm::{
            ColumnTrait, ConnectionTrait, DbBackend, EntityName, EntityTrait, Iden, QueryFilter,
            QueryOrder, Statement,
        },
    },
    store::AuthStore,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    address: String,
    wallets: Vec<WalletInput>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WalletInput {
    chain_id: i64,
    is_primary: bool,
    created_at: String,
}

fn date(value: chrono::DateTime<chrono::Utc>) -> String {
    assert_eq!(value.timestamp_subsec_nanos() % 1_000_000, 0);
    value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn public(row: WalletAddress) -> TestResult<Value> {
    let WalletAddress {
        id,
        user_id,
        address,
        chain_id,
        is_primary,
        created_at,
        additional_fields,
    } = row;
    assert!(additional_fields.is_empty());
    Ok(json!({
        "id": id.typed()?, "userId": user_id, "address": address,
        "chainId": chain_id, "isPrimary": is_primary,
        "createdAt": date(created_at.to_datetime()?.ok_or("Expected a valid Wallet creation date")?),
    }))
}

fn visible(mut row: Value, ids: &BTreeMap<String, String>, owner: &str) -> TestResult<Value> {
    let object = row.as_object_mut().ok_or("Expected a Wallet row object")?;
    assert_eq!(object.get("userId"), Some(&json!(owner)));
    let id = object
        .get("id")
        .and_then(Value::as_str)
        .ok_or("Missing Wallet ID")?;
    let marker = ids.get(id).ok_or("Wallet query returned an unknown ID")?;
    object.insert("id".into(), json!(marker));
    object.insert("userId".into(), json!("<owner-id>"));
    Ok(row)
}

fn quote(backend: DbBackend, value: &str) -> String {
    if backend == DbBackend::MySql {
        format!("`{}`", value.replace('`', "``"))
    } else {
        format!("\"{}\"", value.replace('"', "\"\""))
    }
}

async fn raw<M: SeaOrmPluginModel>(
    database: &DatabaseConnection,
    backend: DbBackend,
) -> TestResult<Vec<Value>> {
    let columns = [
        ("id", "id"),
        ("user_id", "userId"),
        ("address", "address"),
        ("chain_id", "chainId"),
        ("is_primary", "isPrimary"),
        ("created_at", "createdAt"),
    ]
    .into_iter()
    .map(|(field, alias)| {
        Ok(format!(
            "{} AS {}",
            quote(backend, &M::column(field)?.to_string()),
            quote(backend, alias)
        ))
    })
    .collect::<TestResult<Vec<_>>>()?
    .join(", ");
    let table = quote(backend, M::Entity::default().table_name());
    let chain = quote(backend, &M::column("chain_id")?.to_string());
    let mut values = Vec::new();
    for row in database
        .query_all_raw(Statement::from_string(
            backend,
            format!("SELECT {columns} FROM {table} ORDER BY {chain}"),
        ))
        .await?
    {
        let chain_id = if backend == DbBackend::Sqlite {
            row.try_get::<i64>("", "chainId")?
        } else {
            i64::from(row.try_get::<i32>("", "chainId")?)
        };
        let is_primary = match backend {
            DbBackend::Postgres => json!(row.try_get::<bool>("", "isPrimary")?),
            DbBackend::MySql => json!(row.try_get::<i8>("", "isPrimary")?),
            DbBackend::Sqlite => json!(row.try_get::<i64>("", "isPrimary")?),
            _ => return Err("Unsupported Wallet storage backend".into()),
        };
        let created_at = if backend == DbBackend::Sqlite {
            row.try_get::<String>("", "createdAt")?
        } else {
            date(row.try_get::<chrono::DateTime<chrono::Utc>>("", "createdAt")?)
        };
        values.push(json!({
            "id": row.try_get::<String>("", "id")?,
            "userId": row.try_get::<String>("", "userId")?,
            "address": row.try_get::<String>("", "address")?,
            "chainId": chain_id, "isPrimary": is_primary, "createdAt": created_at,
        }));
    }
    Ok(values)
}

pub(super) async fn observe<S: AuthSchema, P: SeaOrmPluginSchema>(
    database: &DatabaseConnection,
    backend: DbBackend,
    input: &Input,
) -> TestResult<Value>
where
    S::User: SeaOrmUserModel,
    S::Session: SeaOrmSessionModel,
    S::Account: SeaOrmAccountModel,
    S::Verification: SeaOrmVerificationModel,
{
    assert_eq!(
        input
            .wallets
            .iter()
            .map(|wallet| wallet.chain_id)
            .collect::<Vec<_>>(),
        [1, 137]
    );
    let first = input.wallets.first().ok_or("Missing Wallet input")?;
    let mut owner_input = CreateUser::new()
        .with_name("Wallet catalog owner")
        .with_email("owner@wallet-catalog.test")
        .with_email_verified(false);
    owner_input.created_at = Some(
        first
            .created_at
            .parse::<chrono::DateTime<chrono::Utc>>()?
            .into(),
    );
    owner_input.updated_at = owner_input.created_at.clone();
    let store =
        SeaOrmStore::<S>::new(AuthConfig::default(), database.clone()).with_plugin_schema::<P>();
    let store: &dyn AuthStore<S> = &store;
    let owner = store.create_user(owner_input).await?;
    let owner_id = owner.id.typed()?;
    assert!(!owner_id.is_empty());
    let mut created = Vec::new();
    let mut by_address = None;
    let mut ids = BTreeMap::new();
    for input_wallet in &input.wallets {
        let wallet = store
            .create_wallet_address(CreateWalletAddress {
                user_id: owner_id.clone(),
                address: input.address.clone(),
                chain_id: input_wallet.chain_id,
                is_primary: input_wallet.is_primary,
                created_at: input_wallet
                    .created_at
                    .parse::<chrono::DateTime<chrono::Utc>>()?
                    .into(),
                additional_fields: Default::default(),
            })
            .await?;
        let id = wallet.id.typed()?.clone();
        assert!(!id.is_empty());
        assert!(
            ids.insert(id, format!("<wallet-{}-id>", input_wallet.chain_id))
                .is_none()
        );
        created.push(public(wallet)?);
        if created.len() == 1 {
            by_address = Some(public(
                store
                    .get_wallet_address(&input.address, None)
                    .await?
                    .ok_or("Missing Wallet by address")?,
            )?);
        }
    }
    let mut by_chain = Vec::new();
    for input_wallet in &input.wallets {
        by_chain.push(public(
            store
                .get_wallet_address(&input.address, Some(input_wallet.chain_id))
                .await?
                .ok_or("Missing Wallet by address and chain")?,
        )?);
    }
    let by_owner = <P::WalletAddress as SeaOrmPluginModel>::Entity::find()
        .filter(P::WalletAddress::column("user_id")?.eq(owner_id.clone()))
        .order_by_asc(P::WalletAddress::column("chain_id")?)
        .all(database)
        .await?
        .into_iter()
        .map(|row| public(row.record()?))
        .collect::<TestResult<Vec<_>>>()?;
    let retained_owner = store
        .get_user_by_id(owner_id)
        .await?
        .ok_or("Missing Wallet owner")?;
    let owner_retained = retained_owner.id.typed()? == owner_id;
    assert!(owner_retained);
    let normalize = |rows: Vec<Value>| {
        rows.into_iter()
            .map(|row| visible(row, &ids, owner_id))
            .collect::<TestResult<Vec<_>>>()
    };
    Ok(json!({
        "created": normalize(created)?,
        "byAddress": visible(by_address.ok_or("Missing address-only observation")?, &ids, owner_id)?,
        "byAddressAndChain": normalize(by_chain)?, "byOwner": normalize(by_owner)?,
        "raw": normalize(raw::<P::WalletAddress>(database, backend).await?)?,
        "ownerRetained": owner_retained,
    }))
}
