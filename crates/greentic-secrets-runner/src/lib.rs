//! Host bridge utilities for environment-backed secrets with policy enforcement.

pub mod bindings;
pub mod env_provider;
pub mod error;
pub mod policy;
pub mod tenant;

pub use bindings::{Bindings, TenantBinding};
pub use env_provider::EnvProvider;
pub use error::SecretError;
pub use policy::Policy;
pub use tenant::{ScopeKind, TenantCtx};

/// Convenience helper that wires bindings, policy, and the environment provider together.
///
/// The provided `bindings` describe the allowlist per tenant.  The optional `tenant` context
/// narrows the lookup scope; when omitted the global allowlist is consulted.
pub fn secrets_get(
    bindings: &Bindings,
    key: &str,
    tenant: Option<&TenantCtx>,
) -> Result<String, SecretError> {
    let policy = Policy::from_bindings(bindings);
    EnvProvider::new(policy).get(key, tenant)
}
