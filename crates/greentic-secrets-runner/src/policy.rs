use std::collections::{HashMap, HashSet};

use crate::bindings::Bindings;
use crate::tenant::{ScopeKind, TenantCtx};

/// Policy enforcing an allowlist of environment backed secrets per tenant.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    tenants: HashMap<String, HashSet<String>>,
    global: HashSet<String>,
}

impl Policy {
    pub fn from_bindings(bindings: &Bindings) -> Self {
        let tenants = bindings
            .tenants_iter()
            .map(|(tenant, binding)| {
                let set = binding
                    .allow_env()
                    .iter()
                    .map(|key| normalise(key))
                    .collect();
                (tenant.to_ascii_lowercase(), set)
            })
            .collect();

        let global = bindings
            .global_binding()
            .allow_env()
            .iter()
            .map(|key| normalise(key))
            .collect();

        Self { tenants, global }
    }

    pub fn is_allowed(&self, key: &str, tenant: Option<&TenantCtx>) -> bool {
        let key = normalise(key);
        match tenant.map(|ctx| ctx.kind()) {
            Some(ScopeKind::Tenant { tenant, .. })
            | Some(ScopeKind::Team { tenant, .. })
            | Some(ScopeKind::User { tenant, .. }) => self
                .tenants
                .get(&tenant.to_ascii_lowercase())
                .map(|set| set.contains(&key))
                .unwrap_or(false),
            Some(ScopeKind::Global { .. }) | None => self.global.contains(&key),
        }
    }
}

fn normalise(key: &str) -> String {
    key.trim().to_ascii_uppercase()
}
