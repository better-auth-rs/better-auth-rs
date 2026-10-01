use super::AccountView;
use serde_json::{Map, Value, json};

const OPTIONAL_FIELDS: &[&str] = &[
    "accessToken",
    "refreshToken",
    "idToken",
    "accessTokenExpiresAt",
    "refreshTokenExpiresAt",
    "scope",
    "password",
];

impl From<AccountView> for Map<String, Value> {
    fn from(account: AccountView) -> Self {
        let date = |value: chrono::DateTime<chrono::Utc>| {
            value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        };
        let mut result = Map::from_iter([
            ("id".into(), json!(account.id)),
            ("accountId".into(), json!(account.account_id)),
            ("providerId".into(), json!(account.provider_id)),
            ("userId".into(), json!(account.user_id)),
            ("createdAt".into(), json!(date(account.created_at))),
            ("updatedAt".into(), json!(date(account.updated_at))),
        ]);
        for (name, value) in [
            ("accessToken", json!(account.access_token)),
            ("refreshToken", json!(account.refresh_token)),
            ("idToken", json!(account.id_token)),
            (
                "accessTokenExpiresAt",
                json!(account.access_token_expires_at.map(date)),
            ),
            (
                "refreshTokenExpiresAt",
                json!(account.refresh_token_expires_at.map(date)),
            ),
            ("scope", json!(account.scope)),
        ] {
            if account
                .visible_fields
                .as_ref()
                .is_none_or(|fields| fields.contains(name))
            {
                let _ = result.insert(name.into(), value);
            }
        }
        result
    }
}

impl TryFrom<Map<String, Value>> for AccountView {
    type Error = serde_json::Error;
    fn try_from(mut fields: Map<String, Value>) -> Result<Self, Self::Error> {
        fn take<T: serde::de::DeserializeOwned>(
            fields: &mut Map<String, Value>,
            name: &str,
        ) -> Result<T, serde_json::Error> {
            serde_json::from_value(fields.remove(name).unwrap_or(Value::Null))
        }
        let visible_fields = Some(
            OPTIONAL_FIELDS
                .iter()
                .filter(|name| fields.contains_key(**name))
                .map(|name| (*name).to_owned())
                .collect(),
        );
        Ok(Self {
            visible_fields,
            id: take(&mut fields, "id")?,
            account_id: take(&mut fields, "accountId")?,
            provider_id: take(&mut fields, "providerId")?,
            user_id: take(&mut fields, "userId")?,
            access_token: take(&mut fields, "accessToken")?,
            refresh_token: take(&mut fields, "refreshToken")?,
            id_token: take(&mut fields, "idToken")?,
            access_token_expires_at: take(&mut fields, "accessTokenExpiresAt")?,
            refresh_token_expires_at: take(&mut fields, "refreshTokenExpiresAt")?,
            scope: take(&mut fields, "scope")?,
            password: take(&mut fields, "password")?,
            created_at: take(&mut fields, "createdAt")?,
            updated_at: take(&mut fields, "updatedAt")?,
        })
    }
}
