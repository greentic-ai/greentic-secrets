use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Representation of bindings supplied by the host.
///
/// Each tenant can declare an allowlist of environment-backed secret names.
/// A separate global allowlist applies when no tenant context is provided.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Bindings {
    #[serde(default)]
    tenants: HashMap<String, TenantBinding>,
    #[serde(default)]
    global: TenantBinding,
}

impl Bindings {
    /// Build bindings from JSON data.
    pub fn from_json<T: AsRef<[u8]>>(data: T) -> serde_json::Result<Self> {
        serde_json::from_slice(data.as_ref())
    }

    /// Returns the binding for the specified tenant (if any).
    pub fn tenant_binding(&self, tenant: &str) -> Option<&TenantBinding> {
        self.tenants.get(tenant)
    }

    /// Returns the global binding.
    pub fn global_binding(&self) -> &TenantBinding {
        &self.global
    }

    pub(crate) fn tenants_iter(&self) -> impl Iterator<Item = (&String, &TenantBinding)> {
        self.tenants.iter()
    }

    /// Builder helper for programmatic configuration.
    pub fn with_tenant(mut self, tenant: impl Into<String>, binding: TenantBinding) -> Self {
        self.tenants.insert(tenant.into(), binding);
        self
    }

    pub fn with_global(mut self, binding: TenantBinding) -> Self {
        self.global = binding;
        self
    }
}

/// Allowlist for a tenant (or the global scope).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantBinding {
    #[serde(default)]
    allow_env: Vec<String>,
}

impl TenantBinding {
    /// Create a binding from a list of allowed environment variables.
    pub fn new<I, S>(allow: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let allow_env = allow.into_iter().map(Into::into).collect();
        Self { allow_env }
    }

    /// Returns the allowlist of environment entries.
    pub fn allow_env(&self) -> &[String] {
        &self.allow_env
    }
}
