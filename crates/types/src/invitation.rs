use serde::{Deserialize, Serialize};

/// Invitation status
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InvitationStatus {
    #[default]
    Pending,
    Accepted,
    Rejected,
    Canceled,
}

impl From<String> for InvitationStatus {
    fn from(s: String) -> Self {
        match s.to_lowercase().as_str() {
            "accepted" => Self::Accepted,
            "rejected" => Self::Rejected,
            "canceled" => Self::Canceled,
            _ => Self::Pending,
        }
    }
}

impl std::fmt::Display for InvitationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Accepted => write!(f, "accepted"),
            Self::Rejected => write!(f, "rejected"),
            Self::Canceled => write!(f, "canceled"),
        }
    }
}
