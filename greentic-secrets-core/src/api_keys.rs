//! Helpers for store/distributor/billing API key references (opaque refs only; no secrets).
//!
//! URIs follow `secrets://<env>/<tenant>/<team|_>/<category>/<name>`:
//! - Store → Repo API keys: category `store`, name `repo__{repo_ref}__api-key`
//! - Distributor API keys: category `distributor`, name `{distributor_ref}__api-key`
//! - Billing provider API keys: category `billing`, name `{billing_provider_id}__api-key`

use crate::embedded::{SecretsCore, SecretsError};
use crate::spec_compat::SecretUri;
use crate::types::Scope;
use greentic_types::{ApiKeyRef, DistributorRef, RepoRef, TenantCtx};
use tracing::info;

/// Build the canonical URI for a repo API key reference.
pub fn repo_api_key_uri(tenant: &TenantCtx, repo_ref: &RepoRef) -> Result<SecretUri, SecretsError> {
    let scope = scope_from_tenant(tenant)?;
    let name = format!("repo__{}__api-key", repo_ref.as_str());
    SecretUri::new(scope, "store", name).map_err(SecretsError::from)
}

/// Build the canonical URI for a distributor API key reference.
pub fn distributor_api_key_uri(
    tenant: &TenantCtx,
    distributor_ref: &DistributorRef,
) -> Result<SecretUri, SecretsError> {
    let scope = scope_from_tenant(tenant)?;
    let name = format!("{}__api-key", distributor_ref.as_str());
    SecretUri::new(scope, "distributor", name).map_err(SecretsError::from)
}

/// Build the canonical URI for a billing provider API key reference.
pub fn billing_api_key_uri(
    tenant: &TenantCtx,
    billing_provider_id: &str,
) -> Result<SecretUri, SecretsError> {
    let scope = scope_from_tenant(tenant)?;
    let name = format!("{billing_provider_id}__api-key");
    SecretUri::new(scope, "billing", name).map_err(SecretsError::from)
}

/// Retrieve a repo API key reference.
pub async fn get_repo_api_key_ref(
    core: &SecretsCore,
    tenant: &TenantCtx,
    repo_ref: &RepoRef,
) -> Result<ApiKeyRef, SecretsError> {
    let uri = repo_api_key_uri(tenant, repo_ref)?;
    fetch_api_key_ref(core, tenant, "store", repo_ref.as_str(), &uri).await
}

/// Retrieve a distributor API key reference.
pub async fn get_distributor_api_key_ref(
    core: &SecretsCore,
    tenant: &TenantCtx,
    distributor_ref: &DistributorRef,
) -> Result<ApiKeyRef, SecretsError> {
    let uri = distributor_api_key_uri(tenant, distributor_ref)?;
    fetch_api_key_ref(core, tenant, "distributor", distributor_ref.as_str(), &uri).await
}

/// Retrieve a billing provider API key reference.
pub async fn get_billing_provider_api_key_ref(
    core: &SecretsCore,
    tenant: &TenantCtx,
    billing_provider_id: &str,
) -> Result<ApiKeyRef, SecretsError> {
    let uri = billing_api_key_uri(tenant, billing_provider_id)?;
    fetch_api_key_ref(core, tenant, "billing", billing_provider_id, &uri).await
}

async fn fetch_api_key_ref(
    core: &SecretsCore,
    tenant: &TenantCtx,
    category: &str,
    subject: &str,
    uri: &SecretUri,
) -> Result<ApiKeyRef, SecretsError> {
    let res = core.get_json::<ApiKeyRef>(&uri.to_string()).await;
    match &res {
        Ok(value) => info!(
            tenant = %tenant.tenant_id,
            team = ?tenant.team,
            category,
            subject,
            api_key_ref = %value.0,
            "retrieved api key reference",
        ),
        Err(err) => info!(
            tenant = %tenant.tenant_id,
            team = ?tenant.team,
            category,
            subject,
            error = %err,
            "failed to retrieve api key reference",
        ),
    }
    res
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
