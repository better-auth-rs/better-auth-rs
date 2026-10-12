#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Frozen JWT contracts require exact callback binding and complete source observations."
)]

use super::native_test_support::{ObservedFields, Trace};
use super::*;
use crate::plugins::test_helpers::native_sort_contract::{Harness, assert_case, jwk_cases};
use better_auth_core::{
    FieldFunction, SchemaValue,
    store::{AuthStore, EphemeralStore, JwksStore, StatelessSchema},
};
use std::sync::{Arc, Weak};

struct KeyringStore {
    harness: Harness,
    owner: Weak<Self>,
}

#[async_trait::async_trait]
impl JwksStore for KeyringStore {
    async fn list_jwk_values(&self) -> AuthResult<FieldValue> {
        self.harness.read_keyring(
            "default",
            FieldMap::from([("model".into(), "jwks".into())]).into(),
            std::ptr::eq(self, self.owner.upgrade().unwrap().as_ref()),
        )
    }

    async fn create_jwk_record(&self, _: FieldMap) -> AuthResult<Option<FieldMap>> {
        Err(AuthError::internal("Selection must not create a key"))
    }
    async fn get_jwk_record(&self, _: &SchemaValue<String>) -> AuthResult<Option<FieldMap>> {
        Err(AuthError::internal(
            "Latest selection must not read one key",
        ))
    }
    async fn update_jwk_record(
        &self,
        _: &SchemaValue<String>,
        _: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        Err(AuthError::internal("Selection must not update a key"))
    }
    async fn delete_jwk_record(&self, _: &SchemaValue<String>) -> AuthResult<()> {
        Err(AuthError::internal("Selection must not delete a key"))
    }
    async fn list_jwk_records(&self) -> AuthResult<Vec<FieldMap>> {
        Err(AuthError::internal(
            "Native keyring selection must retain logical handles",
        ))
    }
}

#[tokio::test]
async fn jwk_native_sort_replays_real_keyring_reads_and_complete_native_graphs() -> AuthResult<()> {
    let config = Arc::new(crate::plugins::test_helpers::create_test_config());
    let database: Arc<dyn AuthStore<StatelessSchema>> =
        Arc::new(EphemeralStore::new(config.clone()));
    let context = Arc::new(AuthContext::new(config, database)?);
    for case in jwk_cases() {
        let harness = if case["access"] == "getters" {
            Harness::new_getters(case)?
        } else {
            Harness::new(case)?
        };
        let before = harness.before()?;
        let store = Arc::new_cyclic(|owner| KeyringStore {
            harness: harness.clone(),
            owner: owner.clone(),
        });
        let marker: FieldValue = FieldMap::from([("marker".into(), "sort-context".into())]).into();
        let endpoint = EndpointContext::native(None, None, FieldValue::Null, &context)
            .with_native_root(marker.clone());
        let receiver = ObservedFields::new(FieldMap::new(), Arc::new(Trace::default()), None);
        let expected_receiver = Arc::downgrade(&receiver);
        let observed = harness.clone();
        receiver.fields.set(
            "getJwks",
            FieldFunction::asynchronous_contextual(move |receiver, arguments| {
                assert_eq!(arguments.len(), 1);
                let root = arguments.first().unwrap();
                assert!(root.strict_equals(&marker));
                let result = observed.read_keyring(
                    "custom",
                    root.clone(),
                    receiver.strict_equals(&expected_receiver.upgrade().unwrap().value()),
                );
                async move { result }
            })
            .into(),
        )?;
        let mut fields = FieldMap::new();
        if case["lane"] == "custom" {
            let _ = fields.insert("adapter".into(), receiver.value());
        }
        let options = overrides::NativeOptions(fields.into());
        let keyring = adapter::Keyring::new(store.as_ref(), &options, &endpoint);
        let result = keyring
            .latest(case["algorithm"].as_str().map(FieldValue::from))
            .await;
        assert_case(&harness.finish(before, result)?, case);
    }
    Ok(())
}
