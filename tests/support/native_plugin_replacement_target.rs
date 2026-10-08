use super::*;
use better_auth::__private_core::{store::schema::EntityRole, user_fields::UserFieldType};

#[derive(Clone, Debug)]
pub(crate) struct Target {
    pub name: String,
    pub model: String,
    pub role: EntityRole,
    pub field: String,
    pub field_type: UserFieldType,
    pub column: String,
}

impl Target {
    pub(crate) fn from_fixture(value: &Value) -> TestResult<Self> {
        let text = |name| {
            value[name]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("Missing native replacement {name}"))
        };
        let model = text("model")?;
        let role = match model.as_str() {
            "apikey" => EntityRole::ApiKey,
            "passkey" => EntityRole::Passkey,
            "deviceCode" => EntityRole::DeviceCode,
            "twoFactor" => EntityRole::TwoFactor,
            "jwks" => EntityRole::Jwk,
            "walletAddress" => EntityRole::WalletAddress,
            _ => return Err(format!("Unknown native replacement model {model}").into()),
        };
        let field_type = match text("type")?.as_str() {
            "number" => UserFieldType::Number,
            "boolean" => UserFieldType::Boolean,
            "string" => UserFieldType::String,
            "string[]" => UserFieldType::StringArray,
            "date" => UserFieldType::Date,
            name => return Err(format!("Unknown native replacement type {name}").into()),
        };
        assert_eq!(value["declaration"]["replacement"]["type"], value["type"]);
        assert_eq!(
            value["declaration"]["replacement"]["fieldName"],
            value["column"]
        );
        assert_eq!(value["declaration"]["replacement"]["required"], false);
        assert!(
            value["declaration"]["replacement"]
                .get("defaultValue")
                .is_none()
        );
        assert!(
            value["declaration"]["replacement"]
                .get("references")
                .is_none()
        );
        Ok(Self {
            name: text("name")?,
            model,
            role,
            field: text("field")?,
            field_type,
            column: text("column")?,
        })
    }

    pub(super) fn value(&self, phase: usize) -> AuthResult<FieldValue> {
        let label = ["create", "update", "default", "onUpdate", "transformed"]
            .get(phase)
            .ok_or_else(|| AuthError::internal("Unknown native replacement phase"))?;
        Ok(match &self.field_type {
            UserFieldType::Number => (5.25 + phase as f64).into(),
            UserFieldType::Boolean => (phase % 2 == 0).into(),
            UserFieldType::String => format!("replacement-{label}").into(),
            UserFieldType::StringArray => vec!["replacement".into(), (*label).into()].into(),
            UserFieldType::Date => {
                let fixed = "2030-01-02T03:04:05.000Z"
                    .parse::<better_auth::seaorm::__private_chrono::DateTime<
                        better_auth::seaorm::__private_chrono::Utc,
                    >>()
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                better_auth::__private_core::FieldDate::from_milliseconds(
                    fixed.timestamp_millis() as f64 + (phase + 1) as f64 * 86_400_000.0,
                )
                .into()
            }
            _ => return Err(AuthError::internal("Unsupported native replacement type")),
        })
    }
}
