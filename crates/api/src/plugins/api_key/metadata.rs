use better_auth_core::{
    ApiKeyView, AuthContext, AuthResult, AuthSchema, SchemaValue, UpdateApiKey,
    background::run_or_await, observability::LogArgument,
};
use serde_json::Value;

use super::{ApiKeyConfig, storage::ApiKeyStorage};

pub(super) fn uses_database(config: &ApiKeyConfig) -> bool {
    config.storage == ApiKeyStorage::Database || config.fallback_to_database
}

fn decode(key: &mut ApiKeyView) -> Option<(SchemaValue<String>, Value)> {
    let Value::String(text) = key.metadata.as_ref()? else {
        return None;
    };
    let metadata = better_auth_core::utils::json::safe_json_parse(text);
    key.metadata = Some(metadata.clone());
    Some((key.id.clone(), metadata))
}

async fn write(
    ctx: &AuthContext<impl AuthSchema>,
    (id, metadata): (SchemaValue<String>, Value),
) -> AuthResult<()> {
    // The upstream migration updates only the database, including fallback mode.
    // A failed legacy repair is logged per key and does not reject verification.
    if let Err(error) = ctx
        .database
        .update_api_key_optional(
            &id,
            UpdateApiKey {
                metadata: Some(metadata.to_string()),
                ..Default::default()
            },
        )
        .await
    {
        ctx.config.logger.warn(
            &format!(
                "Failed to migrate double-stringified metadata for API key {}:",
                id.display_string()?
            ),
            &[LogArgument::Error(&error)],
        );
    }
    Ok(())
}

pub(super) async fn single(
    mut key: ApiKeyView,
    config: &ApiKeyConfig,
    ctx: &AuthContext<impl AuthSchema>,
) -> AuthResult<ApiKeyView> {
    if let Some(migration) = decode(&mut key)
        && uses_database(config)
    {
        write(ctx, migration).await?;
    }
    Ok(key)
}

pub(super) async fn batch(
    keys: &mut [ApiKeyView],
    configurations: &[ApiKeyConfig],
    ctx: &AuthContext<impl AuthSchema>,
) {
    let migrations: Vec<_> = keys
        .iter()
        .filter_map(|key| {
            key.metadata
                .as_ref()?
                .as_str()
                .map(|text| (key.id.clone(), text.to_owned()))
        })
        .collect();
    for key in keys {
        let _ = decode(key);
    }
    if !configurations.iter().any(uses_database) {
        return;
    }
    let context = ctx.clone();
    // Even an empty page supplies a promise to the upstream application handler.
    run_or_await(
        Some(Box::pin(async move {
            for result in
                futures_util::future::join_all(migrations.into_iter().map(|(id, text)| {
                    let context = &context;
                    async move {
                        write(
                            context,
                            (id, better_auth_core::utils::json::safe_json_parse(&text)),
                        )
                        .await
                    }
                }))
                .await
            {
                result?;
            }
            Ok(())
        })),
        ctx.config.advanced.background_tasks.as_ref(),
        &ctx.config.logger,
    )
    .await;
}
