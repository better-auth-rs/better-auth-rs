use async_trait::async_trait;
use std::sync::{Arc, Mutex};

use crate::error::AuthResult;

#[derive(Debug, Clone)]
pub struct EmailMessage {
    pub to: String,
    pub subject: String,
    pub body: String,
}

/// Mailer adapter trait for sending emails.
#[async_trait]
pub trait MailerAdapter: Send + Sync {
    async fn send(&self, to: &str, subject: &str, body: &str) -> AuthResult<()>;
}

/// In-memory mailer for testing and development.
pub struct MemoryMailerAdapter {
    sent: Arc<Mutex<Vec<EmailMessage>>>,
}

impl MemoryMailerAdapter {
    pub fn new() -> Self {
        Self {
            sent: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn sent_messages(&self) -> Vec<EmailMessage> {
        self.sent.lock().unwrap().clone()
    }
}

impl Default for MemoryMailerAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MailerAdapter for MemoryMailerAdapter {
    async fn send(&self, to: &str, subject: &str, body: &str) -> AuthResult<()> {
        let mut sent = self.sent.lock().unwrap();
        sent.push(EmailMessage {
            to: to.to_string(),
            subject: subject.to_string(),
            body: body.to_string(),
        });
        Ok(())
    }
}
