use async_trait::async_trait;

use crate::error::AuthResult;

/// Trait for sending emails. Implement this to integrate with your
/// email service (SMTP, SendGrid, SES, etc.).
#[async_trait]
pub trait EmailProvider: Send + Sync {
    /// Send an email.
    ///
    /// - `to`: recipient email address
    /// - `subject`: email subject line
    /// - `html`: HTML body (may be empty)
    /// - `text`: plain-text body (may be empty)
    async fn send(&self, to: &str, subject: &str, html: &str, text: &str) -> AuthResult<()>;
}

/// Development email provider that logs emails to stderr.
///
/// Useful for local development and testing — no external dependencies.
pub struct ConsoleEmailProvider;

#[async_trait]
impl EmailProvider for ConsoleEmailProvider {
    async fn send(&self, to: &str, subject: &str, _html: &str, text: &str) -> AuthResult<()> {
        eprintln!("[EMAIL] To: {to} | Subject: {subject} | Body: {text}");
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::type_complexity)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Mock email provider for testing.
    struct MockEmailProvider {
        sent: Arc<Mutex<Vec<(String, String, String, String)>>>,
    }

    impl MockEmailProvider {
        fn new() -> (Self, Arc<Mutex<Vec<(String, String, String, String)>>>) {
            let sent = Arc::new(Mutex::new(Vec::new()));
            (Self { sent: sent.clone() }, sent)
        }
    }

    #[async_trait]
    impl EmailProvider for MockEmailProvider {
        async fn send(&self, to: &str, subject: &str, html: &str, text: &str) -> AuthResult<()> {
            self.sent.lock().unwrap().push((
                to.to_string(),
                subject.to_string(),
                html.to_string(),
                text.to_string(),
            ));
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_console_email_provider_send() {
        let provider = ConsoleEmailProvider;
        let result = provider
            .send("user@example.com", "Test Subject", "<h1>Hi</h1>", "Hi")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mock_email_provider_records_sends() {
        let (provider, sent) = MockEmailProvider::new();
        provider
            .send("a@b.com", "Sub", "<p>html</p>", "text")
            .await
            .unwrap();
        provider.send("c@d.com", "Sub2", "", "text2").await.unwrap();

        let messages = sent.lock().unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].0, "a@b.com");
        assert_eq!(messages[1].0, "c@d.com");
    }

    #[tokio::test]
    async fn test_trait_object_works() {
        let provider: Box<dyn EmailProvider> = Box::new(ConsoleEmailProvider);
        let result = provider.send("user@example.com", "Test", "", "body").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_missing_provider_returns_error() {
        use crate::adapters::MemoryDatabaseAdapter;
        use crate::config::AuthConfig;
        use crate::plugin::AuthContext;

        let config = Arc::new(AuthConfig::new("test-secret-key-at-least-32-chars-long"));
        let database = Arc::new(MemoryDatabaseAdapter::new());
        let ctx = AuthContext::new(config, database);

        let result = ctx.email_provider();
        assert!(result.is_err());
    }
}
