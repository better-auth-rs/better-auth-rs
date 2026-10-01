use super::{AuthRequest, AuthResult, BetterAuth, configuration, oracle};
use async_trait::async_trait;
use better_auth::__private_core::{TrustedValues, TrustedValuesResolver};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Resolver {
    calls: Arc<AtomicUsize>,
    values: Vec<String>,
}

#[async_trait]
impl TrustedValuesResolver for Resolver {
    async fn resolve(&self, _: Option<&AuthRequest>) -> AuthResult<Vec<String>> {
        let _ = self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.values.clone())
    }
}

#[tokio::test]
async fn trusted_values_keep_input_presence_and_resolve_only_in_the_runtime_phase() -> AuthResult<()>
{
    for name in ["omitted", "trustedEmpty", "trustedStatic", "trustedDynamic"] {
        let (mut config, reports) = configuration();
        let origin_calls = Arc::new(AtomicUsize::new(0));
        let provider_calls = Arc::new(AtomicUsize::new(0));
        let configured_origins = if matches!(name, "trustedStatic" | "trustedDynamic") {
            vec![
                "https://first.test".to_owned(),
                "https://second.test".to_owned(),
            ]
        } else {
            Vec::new()
        };
        let configured_providers = if matches!(name, "trustedStatic" | "trustedDynamic") {
            vec!["provider-one".to_owned(), "provider-two".to_owned()]
        } else {
            Vec::new()
        };
        if name == "trustedDynamic" {
            config.trusted_origins = Some(TrustedValues::Dynamic(Arc::new(Resolver {
                calls: origin_calls.clone(),
                values: configured_origins.clone(),
            })));
            config.account.account_linking.trusted_providers =
                Some(TrustedValues::Dynamic(Arc::new(Resolver {
                    calls: provider_calls.clone(),
                    values: configured_providers.clone(),
                })));
        } else if name != "omitted" {
            config = config.trusted_origins(configured_origins.clone());
            config.account.account_linking.trusted_providers =
                Some(configured_providers.clone().into());
        }
        let auth = BetterAuth::stateless(config).build().await?;
        let actual = reports.config()?;
        let expected = oracle(name)?;
        for path in [
            "/trustedOrigins",
            "/account/accountLinking/trustedProviders",
        ] {
            assert_eq!(
                actual.pointer(path),
                expected.pointer(path),
                "{name}: {path}"
            );
        }
        assert_eq!(
            origin_calls.load(Ordering::SeqCst),
            usize::from(name == "trustedDynamic")
        );
        assert_eq!(
            provider_calls.load(Ordering::SeqCst),
            usize::from(name == "trustedDynamic")
        );
        let mut origins = vec!["https://example.test".to_owned()];
        origins.extend(configured_origins);
        assert_eq!(auth.context().trusted_origins(), origins);
        assert_eq!(auth.context().trusted_providers(), configured_providers);
    }
    Ok(())
}
