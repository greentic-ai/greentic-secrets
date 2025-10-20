//! Kubernetes secrets provider stub.

use anyhow::{bail, Result};
use secrets_core::{Result as CoreResult, SecretIdentifier};

#[tracing::instrument]
pub fn is_supported(identifier: &SecretIdentifier) -> CoreResult<()> {
    identifier.validate()
}

#[tracing::instrument]
pub async fn fetch_secret(_identifier: &SecretIdentifier) -> Result<String> {
    bail!("kubernetes provider not implemented");
}
