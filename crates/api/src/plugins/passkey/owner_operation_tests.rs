use super::*;

async fn rejected<S: AuthSchema>(
    ctx: &AuthContext<S>,
    cookie: &str,
    id: &str,
    expected: (u16, Option<Value>),
) -> TestResult {
    for path in ["/passkey/update-passkey", "/passkey/delete-passkey"] {
        let response = response(
            ctx,
            &request(
                path,
                None,
                Some(json!({"id": id, "name": "Unauthorized"})),
                Some(cookie),
            ),
        )
        .await;
        assert_eq!(response.status, expected.0);
        if let Some(expected) = &expected.1 {
            assert_eq!(
                serde_json::from_slice::<Value>(&response.body.bytes()?)?,
                *expected
            );
        } else {
            assert!(response.body.bytes()?.is_empty());
        }
    }
    Ok(())
}

async fn owner_operations<S: AuthSchema>(ctx: AuthContext<S>, sqlite: bool) -> TestResult {
    let token = owner_session(&ctx).await?;
    let original = existing_passkey(&ctx).await?;
    for sample in cases()? {
        if sqlite && !sample.contains_key("sqliteMatches") {
            continue;
        }
        let owner = replacement(&sample);
        if owner.strict_equals(&FieldValue::from("7")) {
            continue;
        }
        let (projected, cookie) = project(&ctx, owner.clone(), &token, None).await?;
        if !owner.is_truthy() {
            for id in [original.id.typed()?, "missing", ""] {
                rejected(&projected, &cookie, id, (401, None)).await?;
            }
        } else {
            let update = response(
                &projected,
                &request(
                    "/passkey/update-passkey",
                    None,
                    Some(json!({"id": original.id, "name": "Unauthorized"})),
                    Some(&cookie),
                ),
            )
            .await;
            assert_eq!(update.status, 401, "{sample:?}");
            assert_eq!(
                serde_json::from_slice::<Value>(&update.body.bytes()?)?,
                json!({
                    "code": "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY",
                    "message": "You are not allowed to register this passkey"
                })
            );
            let delete = response(
                &projected,
                &request(
                    "/passkey/delete-passkey",
                    None,
                    Some(json!({"id": original.id})),
                    Some(&cookie),
                ),
            )
            .await;
            assert_eq!(delete.status, 401, "{sample:?}");
            assert!(delete.body.bytes()?.is_empty());
        }
        assert_eq!(
            ctx.database.get_passkey_by_id(original.id.typed()?).await?,
            Some(original.clone())
        );
    }
    let (projected, cookie) = project(&ctx, "7".into(), &token, None).await?;
    rejected(
        &projected,
        &cookie,
        "",
        (
            400,
            Some(json!({
                "message": "Missing required parameter: id"
            })),
        ),
    )
    .await?;
    rejected(
        &projected,
        &cookie,
        "missing",
        (
            404,
            Some(json!({
                "code": "PASSKEY_NOT_FOUND", "message": "Passkey not found"
            })),
        ),
    )
    .await?;
    let updated = response(
        &projected,
        &request(
            "/passkey/update-passkey",
            None,
            Some(json!({"id": original.id, "name": "Renamed"})),
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(updated.status, 200);
    let mut expected = original.clone();
    expected.name = Some("Renamed".to_owned()).into();
    assert_eq!(
        serde_json::from_slice::<Value>(&updated.body.bytes()?)?,
        json!({"passkey": PasskeyView::from(&expected)})
    );
    assert_eq!(
        ctx.database.get_passkey_by_id(original.id.typed()?).await?,
        Some(expected)
    );
    let deleted = response(
        &projected,
        &request(
            "/passkey/delete-passkey",
            None,
            Some(json!({"id": original.id})),
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(deleted.status, 200);
    assert_eq!(
        serde_json::from_slice::<Value>(&deleted.body.bytes()?)?,
        json!({"status": true})
    );
    assert!(
        ctx.database
            .get_passkey_by_id(original.id.typed()?)
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn memory_owner_operations_enforce_truthiness_and_strict_equality() -> TestResult {
    owner_operations(memory(), false).await
}

#[tokio::test]
async fn sqlite_owner_operations_compare_returned_owner_without_coercion() -> TestResult {
    owner_operations(
        test_helpers::create_test_context_with_config(
            test_helpers::create_test_config().base_url(ORIGIN),
        )
        .await,
        true,
    )
    .await
}

#[tokio::test]
async fn equal_object_contents_do_not_authorize_passkey_mutations() -> TestResult {
    let ctx = memory();
    let token = owner_session(&ctx).await?;
    let original = existing_passkey(&ctx).await?;
    let owner = FieldValue::from(FieldMap::from([("owner".into(), 7.0.into())]));
    let (projected, cookie) = project(&ctx, owner.clone(), &token, Some(owner)).await?;
    let update = response(
        &projected,
        &request(
            "/passkey/update-passkey",
            None,
            Some(json!({"id": original.id, "name": "Unauthorized"})),
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(update.status, 401);
    assert_eq!(
        serde_json::from_slice::<Value>(&update.body.bytes()?)?,
        json!({
            "code": "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY",
            "message": "You are not allowed to register this passkey"
        })
    );
    let delete = response(
        &projected,
        &request(
            "/passkey/delete-passkey",
            None,
            Some(json!({"id": original.id})),
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(delete.status, 401);
    assert!(delete.body.bytes()?.is_empty());
    assert_eq!(
        ctx.database.get_passkey_by_id(original.id.typed()?).await?,
        Some(original)
    );
    Ok(())
}
