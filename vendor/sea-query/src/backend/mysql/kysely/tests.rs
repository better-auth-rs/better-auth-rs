use super::*;
use serde_json::{Value as Json, json};

fn parameter(value: Value) -> Json {
    match value {
        Value::String(Some(value)) => value.into(),
        Value::Bool(Some(value)) => value.into(),
        Value::Int(Some(value)) => value.into(),
        Value::BigUnsigned(Some(value)) => value.into(),
        value => panic!("Unexpected compiler contract parameter: {value:?}"),
    }
}

fn observe(name: &str, (sql, parameters): (String, Values)) -> Json {
    json!({"name": name, "sql": sql, "parameters": parameters.0.into_iter().map(parameter).collect::<Vec<_>>()})
}

fn column(name: &str) -> Expr {
    Expr::col((Alias::new("MiX`ed"), Alias::new(name)))
}

fn select() -> SelectStatement {
    Query::select()
        .column(Asterisk)
        .from(Alias::new("MiX`ed"))
        .to_owned()
}

#[test]
#[ignore = "requires the pinned Kysely/mysql2 source observation from GitHub Actions"]
fn pinned_mysql_compiler_templates_and_parameters() {
    let fixture = std::env::var("BETTER_AUTH_MYSQL_TEXT_FIXTURE").expect("source observation path");
    let expected: Json =
        serde_json::from_slice(&std::fs::read(fixture).expect("source observation"))
            .expect("valid source JSON");
    let builder = KyselyMysqlQueryBuilder;
    let insert = Query::insert()
        .into_table(Alias::new("MiX`ed"))
        .columns([Alias::new("id"), Alias::new("Name"), Alias::new("enabled")])
        .values(["a?".into(), "O'Reilly".into(), true.into()])
        .expect("matching insert columns")
        .to_owned();
    let nested = select().and_where(column("id").eq("ID")).to_owned();
    let cases = vec![
        observe("insert", insert.build_any(&builder)),
        observe(
            "select",
            select()
                .and_where(column("id").eq("ID"))
                .order_by(Alias::new("Name"), Order::Desc)
                .limit(2)
                .offset(1)
                .build_any(&builder),
        ),
        observe(
            "update",
            Query::update()
                .table(Alias::new("MiX`ed"))
                .values([
                    (Alias::new("Name"), Expr::val("NEW")),
                    (Alias::new("count"), Expr::col(Alias::new("count")).add(1)),
                ])
                .and_where(column("id").eq("ID"))
                .build_any(&builder),
        ),
        observe(
            "delete",
            Query::delete()
                .from_table(Alias::new("MiX`ed"))
                .and_where(column("id").is_in(["A", "B"]))
                .build_any(&builder),
        ),
        observe(
            "empty-in",
            select()
                .and_where(column("id").is_in(Vec::<String>::new()))
                .build_any(&builder),
        ),
        observe(
            "null",
            select()
                .and_where(column("Name").is_null())
                .build_any(&builder),
        ),
        observe(
            "raw",
            select()
                .and_where(Expr::cust_with_exprs(
                    "LOWER(?) LIKE LOWER(?)",
                    [column("Name"), Expr::val("A?")],
                ))
                .build_any(&builder),
        ),
        observe(
            "lock",
            Query::select()
                .column(Alias::new("id"))
                .from(Alias::new("MiX`ed"))
                .and_where(column("id").eq("ID"))
                .limit(1)
                .lock_with_behavior(LockType::Update, LockBehavior::SkipLocked)
                .build_any(&builder),
        ),
        observe(
            "join",
            Query::select()
                .column((Alias::new("primary"), Asterisk))
                .expr_as(
                    Expr::col((Alias::new("child"), Alias::new("Name"))),
                    Alias::new("childName"),
                )
                .from_subquery(nested, Alias::new("primary"))
                .join_as(
                    JoinType::LeftJoin,
                    Alias::new("Child"),
                    Alias::new("child"),
                    Expr::col((Alias::new("child"), Alias::new("parent")))
                        .equals((Alias::new("primary"), Alias::new("id"))),
                )
                .build_any(&builder),
        ),
        observe(
            "immediate",
            Query::select()
                .from(Alias::new("MiX`ed"))
                .expr_as(Expr::Constant("A\\'B".into()), Alias::new("Value"))
                .expr_as(Expr::Constant(true.into()), Alias::new("Bool"))
                .expr_as(Expr::Constant(Value::String(None)), Alias::new("Null"))
                .build_any(&builder),
        ),
        observe(
            "count",
            Query::select()
                .from(Alias::new("MiX`ed"))
                .expr_as(Expr::col(Alias::new("id")).count(), Alias::new("count"))
                .build_any(&builder),
        ),
    ];
    assert_eq!(cases.len(), 11);
    assert_eq!(json!(cases), expected["compiled"]);
}
