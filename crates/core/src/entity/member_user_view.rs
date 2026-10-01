use super::MemberUserView;
use serde_json::{Map, Value, json};

impl From<MemberUserView> for Map<String, Value> {
    fn from(user: MemberUserView) -> Self {
        let mut fields = Map::new();
        if !user.id.is_undefined() {
            let _ = fields.insert("id".into(), json!(user.id));
        }
        for (name, value) in [
            ("email", user.email),
            ("name", user.name),
            ("image", user.image),
        ] {
            if user
                .visible_fields
                .as_ref()
                .is_none_or(|fields| fields.contains(name))
            {
                let _ = fields.insert(name.into(), json!(value));
            }
        }
        fields
    }
}

impl TryFrom<Map<String, Value>> for MemberUserView {
    type Error = serde_json::Error;

    fn try_from(mut fields: Map<String, Value>) -> Result<Self, Self::Error> {
        let visible_fields = Some(fields.keys().cloned().collect());
        Ok(Self {
            visible_fields,
            id: crate::SchemaValue::from_json(fields.remove("id")),
            email: serde_json::from_value(fields.remove("email").unwrap_or(Value::Null))?,
            name: serde_json::from_value(fields.remove("name").unwrap_or(Value::Null))?,
            image: serde_json::from_value(fields.remove("image").unwrap_or(Value::Null))?,
        })
    }
}
