//! Helper utilities for events/messaging provider secrets.
//!
//! The canonical naming convention maps `greentic_types::TenantCtx` into
//! `secrets://<env>/<tenant>/<team|_>/<category>/<name>` with:
//! - Events providers: `category = "events"`, `name = "{provider}__credentials"`.
//! - Messaging adapters: `category = "messaging"`, `name = "{adapter}__api-key"`.
//!   Optional suffixes follow the same pattern (e.g. `nats-core__endpoint`).
//!
//! Examples:
//! ```
//! # tokio::runtime::Runtime::new().unwrap().block_on(async {
//! use greentic_types::{EnvId, TenantCtx, TenantId};
//! use secrets_core::{
//!     get_events_provider_secret, messaging_adapter_secret_uri, ttl_duration, SecretsCore,
//! };
//!
//! let tenant = TenantCtx::new(
//!     EnvId::try_from("dev").unwrap(),
//!     TenantId::try_from("acme").unwrap(),
//! );
//! let core = SecretsCore::builder().tenant("acme").build().await.unwrap();
//! // Secrets can be written via put_json or your backend of choice.
//! let uri = messaging_adapter_secret_uri(&tenant, "teams-main").unwrap();
//! // let secret = get_events_provider_secret(&core, &tenant, "nats-core").await?;
//! // let ttl = ttl_duration(&secret.meta);
//! # let _ = uri;
//! # });
//! ```
use crate::embedded::{SecretsCore, SecretsError};
use crate::spec_compat::{Scope, SecretUri};
use crate::{BrokerSecret, SecretMeta};
use greentic_types::TenantCtx;
use std::time::Duration;

/// Canonical secret payload+metadata representation for provider/adapters.
pub type ProviderSecret = BrokerSecret;

/// Build the canonical URI for an events provider credential.
pub fn events_provider_secret_uri(
    tenant: &TenantCtx,
    provider_name: &str,
) -> Result<SecretUri, SecretsError> {
    let scope = scope_from_tenant(tenant)?;
    let name = format!("{provider_name}__credentials");
    SecretUri::new(scope, "events", name).map_err(SecretsError::from)
}

/// Build the canonical URI for a messaging adapter API key/token.
pub fn messaging_adapter_secret_uri(
    tenant: &TenantCtx,
    adapter_name: &str,
) -> Result<SecretUri, SecretsError> {
    let scope = scope_from_tenant(tenant)?;
    let name = format!("{adapter_name}__api-key");
    SecretUri::new(scope, "messaging", name).map_err(SecretsError::from)
}

/// Fetch the events provider secret for the given tenant/provider.
pub async fn get_events_provider_secret(
    core: &SecretsCore,
    tenant: &TenantCtx,
    provider_name: &str,
) -> Result<ProviderSecret, SecretsError> {
    let uri = events_provider_secret_uri(tenant, provider_name)?;
    core.get_secret_with_meta(&uri.to_string()).await
}

/// Fetch the messaging adapter secret for the given tenant/adapter.
pub async fn get_messaging_adapter_secret(
    core: &SecretsCore,
    tenant: &TenantCtx,
    adapter_name: &str,
) -> Result<ProviderSecret, SecretsError> {
    let uri = messaging_adapter_secret_uri(tenant, adapter_name)?;
    core.get_secret_with_meta(&uri.to_string()).await
}

/// Extract `ttl_seconds` from secret metadata when present.
pub fn ttl_seconds(meta: &SecretMeta) -> Option<u64> {
    meta.tags
        .get("ttl_seconds")
        .and_then(|value| value.parse::<u64>().ok())
}

/// TTL expressed as a `Duration`, if present and valid.
pub fn ttl_duration(meta: &SecretMeta) -> Option<Duration> {
    ttl_seconds(meta).map(Duration::from_secs)
}

fn scope_from_tenant(ctx: &TenantCtx) -> Result<Scope, SecretsError> {
    let env = ctx.env.as_ref();
    let tenant = ctx.tenant_id.as_ref();
    let team = ctx
        .team
        .as_ref()
        .or(ctx.team_id.as_ref())
        .map(|team| team.as_ref().to_string());
    Scope::new(env, tenant, team).map_err(SecretsError::from)
}
