use super::{contract, raw, write};
use better_auth::{
    BetterAuth,
    plugins::username::{UsernameConfig, UsernameNormalization, UsernamePlugin, UsernameValidator},
};
use better_auth_core::{AuthResult, FieldMap, FieldValue, store::UserStore};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

type Events = Arc<Mutex<Vec<Value>>>;

struct Validator(Events);

#[async_trait::async_trait]
impl UsernameValidator for Validator {
    async fn validate(&self, value: &FieldValue) -> AuthResult<bool> {
        self.0
            .lock()
            .unwrap()
            .push(json!(["validate", contract::observe(value)?]));
        Ok(true)
    }
}

#[tokio::test]
async fn username_hooks_preserve_dynamic_values_and_fail_before_mutating_storage() -> AuthResult<()>
{
    let cases: Value =
        serde_json::from_str(include_str!("../fixtures/user-runtime-input-cases.json"))?;
    for create in [true, false] {
        for case in cases["usernames"].as_array().unwrap() {
            let config = contract::config()?;
            let raw = raw(&config, create).await?;
            let before = raw
                .get_user_by_id(contract::OWNER)
                .await?
                .map(FieldMap::from);
            let events = Events::default();
            let normalization = match case["mode"].as_str().unwrap() {
                "disabled" => UsernameNormalization::Disabled,
                "custom" => {
                    let events = events.clone();
                    UsernameNormalization::Custom(Arc::new(move |value| {
                        events
                            .lock()
                            .unwrap()
                            .push(json!(["normalize", contract::observe(value)?]));
                        Ok(FieldMap::from([
                            ("length".into(), 5.into()),
                            ("label".into(), "normalized".into()),
                        ])
                        .into())
                    }))
                }
                _ => UsernameNormalization::Default,
            };
            let auth = BetterAuth::stateless(config)
                .store_arc(raw.clone())
                .plugin(UsernamePlugin::new(UsernameConfig {
                    username_normalization: normalization,
                    username_validator: Some(Arc::new(Validator(events.clone()))),
                    ..Default::default()
                }))
                .build()
                .await?;
            let mut input = contract::native_user();
            let _ = input.remove("displayUsername");
            let _ = input.insert("username".into(), contract::revive(&case["value"])?);
            let result = write(auth.store().as_ref(), create, input).await;
            let expected = case["events"]
                .as_array()
                .unwrap()
                .iter()
                .map(|phase| json!([phase, case["value"]]))
                .collect::<Vec<_>>();
            assert_eq!(
                *events.lock().unwrap(),
                expected,
                "create={create}, {}",
                case["name"]
            );
            if let Some(error) = case.get("error") {
                assert!(
                    result
                        .unwrap_err()
                        .instrumentation_message()
                        .contains(error.as_str().unwrap())
                );
                assert_eq!(
                    raw.get_user_by_id(contract::OWNER)
                        .await?
                        .map(FieldMap::from),
                    before
                );
            } else {
                let result = FieldMap::from(result?);
                let stored = FieldMap::from(raw.get_user_by_id(contract::OWNER).await?.unwrap());
                assert_eq!(contract::observe(&result["username"])?, case["expected"]);
                assert_eq!(contract::observe(&stored["username"])?, case["expected"]);
            }
        }
    }
    Ok(())
}
