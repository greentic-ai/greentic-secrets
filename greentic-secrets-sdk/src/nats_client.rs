use crate::wire;
use crate::{
    decode_list, decode_rotate, decode_secret, PutSecretRequest, Result, RotateSummary, SdkError,
    Secret,
};
use async_nats::Client;
use secrets_core::types::Scope;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

/// NATS client for the Secrets Broker subjects.
#[derive(Clone)]
pub struct NatsClient {
    client: Arc<Client>,
    token: Option<String>,
    timeout: Duration,
}

impl NatsClient {
    /// Construct a client from an existing NATS connection.
    pub fn new(client: Client) -> Self {
        Self {
            client: Arc::new(client),
            token: None,
            timeout: Duration::from_secs(5),
        }
    }

    /// Attach a bearer token that will be forwarded with requests.
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Override the request timeout (default 5 seconds).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Store a secret via NATS.
    pub async fn put_secret(
        &self,
        scope: &Scope,
        category: &str,
        name: &str,
        request: &PutSecretRequest,
    ) -> Result<Secret> {
        let subject = format!(
            "secrets.put.req.{}.{}.{}",
            scope.tenant(),
            scope.env(),
            team_segment(scope)
        );
        let payload = wire::PutCommand {
            category: category.to_string(),
            name: name.to_string(),
            token: self.token.clone(),
            body: request.to_wire()?,
        };
        let message = self.request_json(&subject, &payload).await?;
        self.parse_secret(message).await
    }

    /// Retrieve a secret via NATS.
    pub async fn get_secret(
        &self,
        scope: &Scope,
        category: &str,
        name: &str,
        version: Option<u64>,
    ) -> Result<Option<Secret>> {
        let subject = format!(
            "secrets.get.req.{}.{}.{}",
            scope.tenant(),
            scope.env(),
            team_segment(scope)
        );
        let payload = wire::GetCommand {
            category: category.to_string(),
            name: name.to_string(),
            version,
            token: self.token.clone(),
        };
        let message = self.request_json(&subject, &payload).await?;
        match self.parse_secret(message).await {
            Ok(secret) => Ok(Some(secret)),
            Err(SdkError::Broker(msg)) => {
                if msg.to_ascii_lowercase().contains("not found") {
                    Ok(None)
                } else {
                    Err(SdkError::Broker(msg))
                }
            }
            Err(err) => Err(err),
        }
    }

    /// List secrets for the provided scope.
    pub async fn list_secrets(
        &self,
        scope: &Scope,
        category_prefix: Option<&str>,
        name_prefix: Option<&str>,
    ) -> Result<Vec<crate::ListEntry>> {
        let subject = format!(
            "secrets.list.req.{}.{}.{}",
            scope.tenant(),
            scope.env(),
            team_segment(scope)
        );
        let payload = wire::ListCommand {
            prefix: build_prefix(category_prefix, name_prefix),
            token: self.token.clone(),
        };
        let message = self.request_json(&subject, &payload).await?;
        let bytes = message.payload.as_ref();
        if let Some(error) = try_parse_error(bytes) {
            return Err(SdkError::Broker(error));
        }
        let payload = serde_json::from_slice::<wire::ListSecretsResponse>(bytes)?;
        decode_list(payload.items)
    }

    /// Delete a secret via NATS.
    pub async fn delete_secret(&self, scope: &Scope, category: &str, name: &str) -> Result<()> {
        let subject = format!(
            "secrets.del.req.{}.{}.{}",
            scope.tenant(),
            scope.env(),
            team_segment(scope)
        );
        let payload = wire::DeleteCommand {
            category: category.to_string(),
            name: name.to_string(),
            token: self.token.clone(),
        };
        let message = self.request_json(&subject, &payload).await?;
        let bytes = message.payload.as_ref();
        if let Some(error) = try_parse_error(bytes) {
            return Err(SdkError::Broker(error));
        }
        Ok(())
    }

    /// Trigger a rotation job via NATS.
    pub async fn rotate_category(
        &self,
        scope: &Scope,
        category: &str,
        job_id: Option<&str>,
    ) -> Result<RotateSummary> {
        let subject = format!(
            "secrets.rotate.req.{}.{}.{}.{}",
            scope.tenant(),
            scope.env(),
            team_segment(scope),
            category
        );
        let payload = wire::RotateCommand {
            job_id: job_id.map(|value| value.to_string()),
            token: self.token.clone(),
        };
        let message = self.request_json(&subject, &payload).await?;
        let bytes = message.payload.as_ref();
        if let Some(error) = try_parse_error(bytes) {
            return Err(SdkError::Broker(error));
        }
        let payload = serde_json::from_slice::<wire::RotateResponse>(bytes)?;
        Ok(decode_rotate(payload))
    }

    async fn request_json(
        &self,
        subject: &str,
        payload: &impl serde::Serialize,
    ) -> Result<async_nats::Message> {
        let body = serde_json::to_vec(payload)?;
        let fut = self.client.request(subject.to_string(), body.into());
        match time::timeout(self.timeout, fut).await {
            Ok(Ok(message)) => Ok(message),
            Ok(Err(err)) => Err(SdkError::Nats(err.into())),
            Err(_) => Err(SdkError::Broker("nats request timed out".into())),
        }
    }

    async fn parse_secret(&self, message: async_nats::Message) -> Result<Secret> {
        let bytes = message.payload.as_ref();
        if let Some(error) = try_parse_error(bytes) {
            return Err(SdkError::Broker(error));
        }
        let payload = serde_json::from_slice::<wire::SecretResponse>(bytes)?;
        decode_secret(payload)
    }
}

fn team_segment(scope: &Scope) -> &str {
    scope.team().unwrap_or("_")
}

fn build_prefix(category: Option<&str>, name: Option<&str>) -> Option<String> {
    match (category, name) {
        (None, None) => None,
        (Some(category), None) => Some(category.to_string()),
        (Some(category), Some(name)) => Some(format!("{category}/{name}")),
        (None, Some(name)) => Some(format!("/{name}")),
    }
}

fn try_parse_error(bytes: &[u8]) -> Option<String> {
    match serde_json::from_slice::<wire::ErrorResponse>(bytes) {
        Ok(err) if !err.error.is_empty() => Some(err.message),
        _ => None,
    }
}
