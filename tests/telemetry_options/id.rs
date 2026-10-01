use super::{AuthResult, BetterAuth, configuration, oracle};
use better_auth::__private_core::CreateUser;
use better_auth::config::{IdGeneration, IdGenerator};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[tokio::test]
async fn id_policy_metadata_preserves_configured_values_without_calling_generators()
-> AuthResult<()> {
    for name in [
        "omitted",
        "random",
        "idDatabase",
        "idSerial",
        "idUuid",
        "idCustom",
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let (mut config, reports) = configuration();
        config.advanced.database.generate_id = match name {
            "omitted" => None,
            "random" => Some(IdGeneration::Random),
            "idDatabase" => Some(IdGeneration::Database),
            "idSerial" => Some(IdGeneration::Serial),
            "idUuid" => Some(IdGeneration::Uuid),
            _ => {
                let calls = calls.clone();
                Some(IdGeneration::Custom(IdGenerator::new(move |request| {
                    let _ = calls.fetch_add(1, Ordering::SeqCst);
                    Ok(Some(format!("configured-{}", request.model)))
                })))
            }
        };
        let auth = BetterAuth::stateless(config).build().await?;
        assert_eq!(
            reports.config()?.pointer("/advanced/database"),
            oracle(if name == "random" { "omitted" } else { name })?.pointer("/advanced/database"),
            "{name}",
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        if matches!(name, "omitted" | "random" | "idCustom") {
            let user = auth
                .store()
                .create_user(CreateUser::new().with_email("id-option@example.test"))
                .await?;
            let id = user.id.typed()?;
            if name == "idCustom" {
                assert_eq!(id, "configured-user");
                assert_eq!(calls.load(Ordering::SeqCst), 1);
            } else {
                assert_eq!(id.len(), 32);
                assert!(id.bytes().all(|byte| byte.is_ascii_alphanumeric()));
            }
        }
    }
    Ok(())
}
