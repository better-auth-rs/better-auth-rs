use super::*;
use fixture::Operation;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Expected {
    version: String,
    kind: String,
    user_fields: serde_json::Map<String, Value>,
    member: Value,
    users: serde_json::Map<String, Value>,
    cases: Vec<Selection>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Selection {
    name: String,
    #[serde(default)]
    user_seeds: serde_json::Map<String, Value>,
    #[serde(default)]
    missing_child: bool,
    first: Option<String>,
    native_sql: Option<String>,
}

fn required<'a>(value: &'a Value, name: &str) -> AuthResult<&'a Value> {
    value
        .get(name)
        .ok_or_else(|| AuthError::internal(format!("Missing handwritten expectation: {name}")))
}

impl Expected {
    #[expect(
        clippy::panic_in_result_fn,
        reason = "The loader propagates parse errors and asserts the handwritten contract coverage."
    )]
    fn read() -> AuthResult<Self> {
        let expected: Self = serde_json::from_str(include_str!(
            "../fixtures/organization-member-singular-existing-contract.json"
        ))?;
        assert_eq!(expected.version, "1.7.6");
        assert_eq!(expected.kind, "handwritten-expectations");
        assert_eq!(
            expected
                .cases
                .iter()
                .map(|case| case.name.as_str())
                .collect::<Vec<_>>(),
            ["ordinary", "existing-duplicates", "missing"]
        );
        Ok(expected)
    }

    fn scenario(&self, selection: &Selection) -> AuthResult<Scenario> {
        Ok(serde_json::from_value(json!({
            "name": selection.name,
            "userFields": self.user_fields,
            "userSeeds": selection.user_seeds,
            "missingChild": selection.missing_child,
        }))?)
    }

    fn case(&self, selection: &Selection, backend: &str, joins: bool) -> AuthResult<Case> {
        let selected = if backend == "sqlite" && joins {
            &selection.native_sql
        } else {
            &selection.first
        };
        let user = selected
            .as_ref()
            .map(|id| {
                self.users.get(id).ok_or_else(|| {
                    AuthError::internal(format!("Missing handwritten User expectation: {id}"))
                })
            })
            .transpose()?;
        let mut member = self.member.clone();
        if selection.missing_child {
            let _ = member
                .as_object_mut()
                .ok_or_else(|| AuthError::internal("Expected handwritten Member fields"))?
                .insert("ownerRef".into(), json!("missing-user"));
        }
        let mut events = vec![json!(["query", "findOne", "member"])];
        for name in ["role", "label", "detail", "ownerRef"] {
            events.push(json!([
                "output",
                format!("member.{name}"),
                required(&member, name)?
            ]));
        }
        if !joins {
            events.push(json!(["query", "findOne", "user"]));
        }
        let result = if let Some(user) = user {
            for name in ["name", "image", "memberRef"] {
                events.push(json!([
                    "output",
                    format!("user.{name}"),
                    required(user, name)?
                ]));
            }
            let summary = ["id", "name", "email", "image"]
                .into_iter()
                .map(|name| Ok((name.into(), required(user, name)?.clone())))
                .collect::<AuthResult<serde_json::Map<String, Value>>>()?;
            let _ = member
                .as_object_mut()
                .ok_or_else(|| AuthError::internal("Expected handwritten Member fields"))?
                .insert("user".into(), Value::Object(summary));
            member
        } else {
            Value::Null
        };
        let serialized = values::revive(&result)?.json()?;
        let operations = ["by-org", "by-id"]
            .into_iter()
            .map(|path| {
                let missing_error = selected.is_none() && path == "by-id";
                Operation {
                    surface: "organization".into(),
                    path: path.into(),
                    events: events.clone(),
                    returned: !missing_error,
                    result: (!missing_error).then(|| result.clone()),
                    json: if missing_error {
                        None
                    } else {
                        serialized.clone()
                    },
                    key_order: (!missing_error).then(|| {
                        if selected.is_some() {
                            vec![
                                json!({"path": ["user"], "keys": ["id", "name", "email", "image"]}),
                            ]
                        } else {
                            Vec::new()
                        }
                    }),
                    error: missing_error.then(|| {
                        json!({
                            "name": "TypeError",
                            "sameCallbackError": false,
                        })
                    }),
                    storage_unchanged: true,
                }
            })
            .collect();
        Ok(Case {
            backend: backend.into(),
            scenario: selection.name.clone(),
            joins,
            populated: true,
            before: Value::Null,
            operations,
            after: Value::Null,
        })
    }
}

#[tokio::test]
async fn memory_singular_member_joins_select_the_first_existing_user() -> AuthResult<()> {
    let expected = Expected::read()?;
    for selection in &expected.cases {
        for joins in [false, true] {
            let scenario = expected.scenario(selection)?;
            let raw = Arc::new(EphemeralStore::new(Arc::new(policies::config(
                &scenario.storage(),
                joins,
                None,
            )?)));
            contract(
                raw,
                None,
                &scenario,
                &expected.case(selection, "memory", joins)?,
            )
            .await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_singular_member_joins_select_the_last_native_or_first_fallback_user()
-> AuthResult<()> {
    let expected = Expected::read()?;
    for selection in &expected.cases {
        for joins in [false, true] {
            let scenario = expected.scenario(selection)?;
            let database = storage::sqlite().await?;
            let raw = Arc::new(
                SeaOrmStore::<models::Core>::new(
                    policies::config(&scenario.storage(), joins, None)?,
                    database.clone(),
                )
                .with_organization_schema::<models::Organizations>(),
            );
            contract(
                raw,
                Some(&database),
                &scenario,
                &expected.case(selection, "sqlite", joins)?,
            )
            .await?;
            database
                .close()
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
        }
    }
    Ok(())
}
