//! Client stubs for interacting with the secrets broker.

use anyhow::{bail, Result};
use secrets_core::SecretIdentifier;

#[tracing::instrument(skip_all)]
pub async fn fetch_secret(_id: &SecretIdentifier) -> Result<String> {
    bail!("SDK fetch_secret stubbed out");
}
