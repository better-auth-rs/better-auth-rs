use super::*;

pub(super) fn observation(fields: Value) -> Value {
    let keys = fields
        .as_object()
        .expect("observed row")
        .keys()
        .collect::<Vec<_>>();
    json!({"keys": keys, "fields": fields})
}

pub(super) struct Check {
    pub(super) started: i64,
    pub(super) created: OnceLock<chrono::DateTime<chrono::Utc>>,
}

impl Check {
    fn timestamp(&self, created: chrono::DateTime<chrono::Utc>) {
        assert!(created.timestamp_millis() >= self.started && created <= chrono::Utc::now());
        assert_eq!(&created, self.created.get_or_init(|| created));
    }

    pub(super) fn visible(&self, row: &Passkey) -> AuthResult<Value> {
        let created = row
            .created_at
            .typed()?
            .as_ref()
            .expect("Passkey createdAt")
            .to_datetime()?
            .expect("Valid Passkey createdAt");
        self.timestamp(created);
        assert_eq!(row.id.typed()?, ID);
        assert_eq!(row.user_id.typed()?, OWNER);
        let mut fields = serde_json::to_value(PasskeyView::from(row))?;
        fields["createdAt"] = json!({"type":"date", "value":"<created-at>"});
        Ok(observation(fields))
    }

    pub(super) async fn stored<S: AuthSchema>(
        &self,
        reader: &dyn AuthStore<S>,
        database: Option<&DatabaseConnection>,
    ) -> TestResult<Value> {
        let row = reader
            .get_passkey_by_id(ID)
            .await?
            .ok_or("Stored Passkey must exist")?;
        let created = row
            .created_at
            .typed()?
            .as_ref()
            .ok_or("Stored createdAt")?
            .to_datetime()?
            .ok_or("Valid stored createdAt")?;
        self.timestamp(created);
        if let Some(database) = database {
            let rows = database.query_all_raw(Statement::from_string(DbBackend::Sqlite,
                "SELECT *, json_object('id',id,'display',display,'publicKey',publicKey,'userId',userId,'credentialID',credentialID,'counter',counter,'deviceType',deviceType,'backedUp',backedUp,'transports',transports,'createdAt',createdAt) AS observed_row FROM shared_display_passkey".to_owned()
            )).await?;
            assert_eq!(rows.len(), 1);
            let stored = &rows[0];
            assert_eq!(
                stored.try_get::<chrono::DateTime<chrono::Utc>>("", "createdAt")?,
                created
            );
            let mut fields: Value =
                serde_json::from_str(&stored.try_get::<String>("", "observed_row")?)?;
            assert_eq!(fields["id"], ID);
            assert_eq!(fields["display"], serde_json::to_value(&row.name)?);
            assert!(fields["createdAt"].is_string());
            fields["createdAt"] = json!("<created-at>");
            Ok(json!([observation(fields)]))
        } else {
            assert_eq!(row.name, row.aaguid);
            assert_eq!(row.credential.typed()?, "ordinary-private-record");
            let updated = row
                .updated_at
                .typed()?
                .to_datetime()?
                .ok_or("Valid stored updatedAt")?;
            assert!(updated >= created && updated <= chrono::Utc::now());
            let mut fields = serde_json::to_value(PasskeyView::from(&row))?;
            let object = fields.as_object_mut().expect("Memory Passkey fields");
            let display = object.remove("name").expect("stored name");
            assert_eq!(object.remove("aaguid"), Some(display.clone()));
            let _ = object.insert("display".into(), display);
            let _ = object.insert(
                "createdAt".into(),
                json!({"type":"date","value":"<created-at>"}),
            );
            Ok(json!([observation(fields)]))
        }
    }

    pub(super) fn http_row(&self, mut row: Value) -> TestResult<Value> {
        let created = row["createdAt"]
            .as_str()
            .ok_or("HTTP Passkey createdAt")?
            .parse::<chrono::DateTime<chrono::Utc>>()?;
        self.timestamp(created);
        row["createdAt"] = json!("<created-at>");
        Ok(row)
    }
}

pub(super) fn normalized(mut value: Value) -> Value {
    match &mut value {
        Value::Array(values) => {
            for value in values {
                *value = normalized(value.take());
            }
        }
        Value::Object(fields) => {
            if let Some(created) = fields.get_mut("createdAt") {
                if created.is_string() {
                    *created = json!("<created-at>");
                } else {
                    created["value"] = json!("<created-at>");
                }
            }
            if let Some(keys) = fields.get_mut("keys").and_then(Value::as_array_mut) {
                keys.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
            }
            for value in fields.values_mut() {
                *value = normalized(value.take());
            }
        }
        _ => {}
    }
    value
}
