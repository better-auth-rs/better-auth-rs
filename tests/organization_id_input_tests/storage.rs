use super::*;

pub(super) enum Storage {
    Memory(EphemeralStore),
    Sqlite(DatabaseConnection),
}

impl Storage {
    pub(super) fn is_memory(&self) -> bool {
        matches!(self, Self::Memory(_))
    }

    pub(super) async fn read(&self, model: Model) -> AuthResult<Vec<FieldMap>> {
        match self {
            Self::Memory(store) => store.storage_rows(model.entity()),
            Self::Sqlite(database) => database
                .query_all_raw(Statement::from_string(
                    DbBackend::Sqlite,
                    format!("SELECT * FROM {} ORDER BY rowid", model.table()),
                ))
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?
                .into_iter()
                .map(|row| {
                    model
                        .columns()
                        .iter()
                        .map(|(name, column)| {
                            let value = if *name == "memberCount" {
                                row.try_get::<i64>("", column).map(FieldValue::from)
                            } else {
                                row.try_get::<Option<String>>("", column)
                                    .map(|value| value.map_or(FieldValue::Null, FieldValue::from))
                            }
                            .map_err(|error| AuthError::internal(error.to_string()))?;
                            Ok(((*name).into(), value))
                        })
                        .collect()
                })
                .collect(),
        }
    }

    fn expected(&self, mut fields: FieldMap) -> AuthResult<FieldMap> {
        fields.retain(|_, value| !value.is_undefined());
        if !self.is_memory() {
            for name in ["createdAt", "updatedAt", "expiresAt"] {
                if let Some(FieldValue::Date(date)) = fields.get(name) {
                    let text = date
                        .to_datetime()?
                        .ok_or_else(|| AuthError::internal("Expected valid Organization date"))?
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                    let _ = fields.insert(name.into(), text.into());
                }
            }
            if let Some(FieldValue::Number(value)) = fields.get("id") {
                let id = value.to_string();
                let _ = fields.insert("id".into(), id.into());
            }
        }
        Ok(fields)
    }

    pub(super) async fn assert_appended(
        &self,
        model: Model,
        baseline: &[FieldMap],
        appended: &[FieldMap],
        started: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Vec<FieldMap>> {
        let finished = chrono::Utc::now();
        let actual = self.read(model).await?;
        let mut expected = baseline.to_vec();
        for (index, row) in appended.iter().enumerate() {
            let mut row = self.expected(row.clone())?;
            if model == Model::Organization && !self.is_memory() {
                let value = actual
                    .get(baseline.len() + index)
                    .and_then(|row| row.get("auth_updated_at"))
                    .ok_or_else(|| {
                        AuthError::internal("Organization storage lacks its internal update time")
                    })?;
                let text = value.as_str().ok_or_else(|| {
                    AuthError::internal("Organization update time must be stored as text")
                })?;
                let date = chrono::DateTime::parse_from_rfc3339(text)
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                // This bundled Rust column has no upstream field. Its complete value must remain in later snapshots.
                assert!(
                    date.timestamp_millis() >= started.timestamp_millis()
                        && date.timestamp_millis() <= finished.timestamp_millis(),
                    "{text} outside {started}..{finished}"
                );
                let _ = row.insert("auth_updated_at".into(), value.clone());
            }
            expected.push(row);
        }
        assert_eq!(actual, expected, "{model:?}: complete physical rows");
        Ok(actual)
    }

    pub(super) async fn seed<S: AuthSchema>(
        &self,
        store: &dyn AuthStore<S>,
        model: Model,
    ) -> AuthResult<Vec<FieldMap>> {
        let _ = store
            .create_user(CreateUser {
                id: Some("owner".into()),
                ..CreateUser::new()
                    .with_email("owner@organization-id-input.test")
                    .with_name("Owner")
            })
            .await?;
        if model != Model::Organization {
            store.configure_organization_fields(configured(
                Model::Organization,
                UserConfig::default(),
                false,
            ))?;
            let _ = create_record(
                store,
                Entry::Create(Model::Organization),
                Some("parent".into()),
                "parent",
                FieldMap::new(),
            )
            .await?;
        }
        store.configure_organization_fields(configured(model, UserConfig::default(), false))?;
        let started = chrono::Utc::now();
        let actual = create_record(
            store,
            Entry::Create(model),
            Some("retained".into()),
            "retained",
            FieldMap::new(),
        )
        .await?;
        let expected = row(model, "retained".into(), "retained");
        assert_eq!(actual, expected, "{model:?}: seed output");
        self.assert_appended(model, &[], &[expected], started).await
    }
}
