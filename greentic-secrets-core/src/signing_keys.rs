//! Helpers for storing and retrieving signing key references (no signing logic).
//!
//! URIs follow the shared scheme:
//! `secrets://<env>/<tenant>/<team|_>/signing/{purpose}__key-ref`
//! where `purpose` is one of build/attestation/sbom/generic.

use crate::embedded::{SecretsCore, SecretsError};
use crate::spec_compat::SecretUri;
use crate::types::Scope;
use greentic_types::{SigningKeyRef, TeamId, TenantCtx};
use tracing::info;

/// Supported signing purposes for key references.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigningPurpose {
    Build,
    Attestation,
    Sbom,
    Generic,
}

impl SigningPurpose {
    fn as_name(self) -> &'static str {
        match self {
            SigningPurpose::Build => "build",
            SigningPurpose::Attestation => "attestation",
            SigningPurpose::Sbom => "sbom",
            SigningPurpose::Generic => "generic",
        }
    }
}

/// Build the canonical URI for the given purpose.
pub fn signing_key_ref_uri(
    tenant: &TenantCtx,
    purpose: SigningPurpose,
) -> Result<SecretUri, SecretsError> {
    let scope = scope_from_tenant(tenant)?;
    let name = format!("{}__key-ref", purpose.as_name());
    SecretUri::new(scope, "signing", name).map_err(SecretsError::from)
}

/// Fetch a signing key reference for the given tenant and purpose.
pub async fn get_signing_key_ref(
    core: &SecretsCore,
    tenant: &TenantCtx,
    purpose: SigningPurpose,
) -> Result<SigningKeyRef, SecretsError> {
    let uri = signing_key_ref_uri(tenant, purpose)?;
    let res = core.get_json::<SigningKeyRef>(&uri.to_string()).await;
    match &res {
        Ok(value) => info!(
            tenant = %tenant.tenant_id,
            team = ?tenant.team,
            purpose = %purpose.as_name(),
            signing_key_ref = %value,
            "retrieved signing key reference",
        ),
        Err(err) => info!(
            tenant = %tenant.tenant_id,
            team = ?tenant.team,
            purpose = %purpose.as_name(),
            error = %err,
            "failed to retrieve signing key reference",
        ),
    }
    res
}

fn scope_from_tenant(ctx: &TenantCtx) -> Result<Scope, SecretsError> {
    let env = ctx.env.as_ref();
    let tenant = ctx.tenant_id.as_ref();
    let team = ctx.team.as_ref().or(ctx.team_id.as_ref()).map(|team| {
        let t: &TeamId = team;
        t.as_ref().to_string()
    });
    Scope::new(env, tenant, team).map_err(SecretsError::from)
}
