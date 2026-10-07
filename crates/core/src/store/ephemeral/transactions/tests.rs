use super::*;
use crate::store::database_hooks::{DatabaseHookContext, DatabaseHooks};
use crate::store::transaction;
use std::sync::atomic::{AtomicUsize, Ordering};

struct AfterCreate {
    calls: Arc<AtomicUsize>,
    fail: bool,
}

#[crate::database_hooks()]
impl DatabaseHooks<StatelessSchema> for AfterCreate {
    async fn after_create_user(
        &self,
        _user: &UserView,
        context: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        assert!(context.transaction.is_none());
        let _ = self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            Err(AuthError::bad_request("after create failure"))
        } else {
            Ok(())
        }
    }
}

fn account(id: &str, password: &str) -> AccountView {
    AccountView {
        additional_fields: Default::default(),
        id: id.into(),
        account_id: id.into(),
        provider_id: "credential".into(),
        user_id: "owner".into(),
        access_token: None.into(),
        refresh_token: None.into(),
        id_token: None.into(),
        access_token_expires_at: None.into(),
        refresh_token_expires_at: None.into(),
        scope: None.into(),
        password: Some(password.into()).into(),
        created_at: Utc::now().into(),
        updated_at: Utc::now().into(),
    }
}

#[test]
fn merge_preserves_private_changes_and_concurrent_rows_without_resurrecting_deletes() {
    let base = IndexMap::from([
        ("private".into(), account("private", "before")),
        ("untouched".into(), account("untouched", "before")),
        ("removed".into(), account("removed", "before")),
    ]);
    let mut live = base.clone();
    live.get_mut("untouched").unwrap().password = Some("concurrent".into()).into();
    let _ = live.shift_remove("removed");
    let _ = live.insert("new-live".into(), account("new-live", "concurrent"));
    let mut working = base.clone();
    working.get_mut("private").unwrap().password = Some("committed".into()).into();
    working.get_mut("removed").unwrap().password = Some("must-not-resurrect".into()).into();
    let _ = working.insert(
        "new-transaction".into(),
        account("new-transaction", "committed"),
    );

    // Wire serialization omits password; transaction comparison must include it.
    assert_eq!(
        serde_json::to_value(&base["private"]).unwrap(),
        serde_json::to_value(&working["private"]).unwrap()
    );
    merge_map(&mut live, &base, working).unwrap();
    assert_eq!(
        live["private"].password.typed().unwrap().as_deref(),
        Some("committed")
    );
    assert_eq!(
        live["untouched"].password.typed().unwrap().as_deref(),
        Some("concurrent")
    );
    assert!(!live.contains_key("removed"));
    assert_eq!(
        live.keys().map(String::as_str).collect::<Vec<_>>(),
        ["private", "untouched", "new-live", "new-transaction"]
    );
}

#[test]
fn merge_keeps_private_passkey_credential_updates() {
    let key = Passkey {
        additional_fields: Default::default(),
        id: "key".into(),
        name: None.into(),
        public_key: "public".into(),
        user_id: "owner".into(),
        credential_id: "credential".into(),
        counter: 0,
        device_type: "singleDevice".into(),
        backed_up: false,
        transports: None,
        created_at: Some(crate::FieldDate::from(Utc::now())).into(),
        updated_at: Utc::now().into(),
        aaguid: None.into(),
        credential: "private-before".into(),
    };
    let base = IndexMap::from([("key".into(), key)]);
    let mut working = base.clone();
    working.get_mut("key").unwrap().credential = "private-after".into();
    assert_eq!(
        serde_json::to_value(&base["key"]).unwrap(),
        serde_json::to_value(&working["key"]).unwrap()
    );
    let mut live = base.clone();
    merge_map(&mut live, &base, working).unwrap();
    assert_eq!(live["key"].credential, "private-after");
}

#[tokio::test]
async fn failed_transaction_discards_rows_and_preserves_concurrent_writes() {
    let store = Arc::new(EphemeralStore::new(test_config()));
    let other = store.clone();
    let result: AuthResult<()> = transaction(store.as_ref(), move |tx| {
        Box::pin(async move {
            let _ = tx
                .create_user(CreateUser::new().with_email("rolled-back@example.com"))
                .await?;
            let _ = other
                .create_user(CreateUser::new().with_email("concurrent@example.com"))
                .await?;
            Err(AuthError::bad_request("abort"))
        })
    })
    .await;
    assert!(result.is_err());
    assert!(
        store
            .get_user_by_email("rolled-back@example.com")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get_user_by_email("concurrent@example.com")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn successful_transaction_hides_uncommitted_rows_and_merges_concurrent_writes() {
    let store = Arc::new(EphemeralStore::new(test_config()));
    let other = store.clone();
    transaction(store.as_ref(), move |tx| {
        Box::pin(async move {
            let _ = tx
                .create_user(CreateUser::new().with_email("committed@example.com"))
                .await?;
            assert!(
                other
                    .get_user_by_email("committed@example.com")
                    .await?
                    .is_none()
            );
            let _ = other
                .create_user(CreateUser::new().with_email("concurrent@example.com"))
                .await?;
            Ok(())
        })
    })
    .await
    .unwrap();
    assert!(
        store
            .get_user_by_email("committed@example.com")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .get_user_by_email("concurrent@example.com")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn after_hook_waits_for_commit_and_rollback_discards_the_queue() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = EphemeralStore::new(test_config()).with_hooks(vec![Arc::new(AfterCreate {
        calls: calls.clone(),
        fail: false,
    })]);
    let during = calls.clone();
    let result: AuthResult<()> = transaction(&store, move |tx| {
        Box::pin(async move {
            let _ = tx
                .create_user(CreateUser::new().with_email("rollback@example.com"))
                .await?;
            assert_eq!(during.load(Ordering::SeqCst), 0);
            Err(AuthError::bad_request("rollback"))
        })
    })
    .await;
    assert!(result.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(
        store
            .get_user_by_email("rollback@example.com")
            .await
            .unwrap()
            .is_none()
    );
    let during = calls.clone();
    transaction(&store, move |tx| {
        Box::pin(async move {
            let _ = tx
                .create_user(CreateUser::new().with_email("commit@example.com"))
                .await?;
            assert_eq!(during.load(Ordering::SeqCst), 0);
            Ok(())
        })
    })
    .await
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn after_hook_failure_preserves_committed_data() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = EphemeralStore::new(test_config()).with_hooks(vec![Arc::new(AfterCreate {
        calls: calls.clone(),
        fail: true,
    })]);
    let result: AuthResult<()> = transaction(&store, move |tx| {
        Box::pin(async move {
            let _ = tx
                .create_user(CreateUser::new().with_email("committed@example.com"))
                .await?;
            Ok(())
        })
    })
    .await;
    assert!(result.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(
        store
            .get_user_by_email("committed@example.com")
            .await
            .unwrap()
            .is_some()
    );
}
