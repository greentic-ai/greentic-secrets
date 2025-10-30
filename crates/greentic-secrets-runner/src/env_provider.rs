use crate::error::SecretError;
use crate::policy::Policy;
use crate::tenant::TenantCtx;

/// Environment-backed provider enforcing the configured policy.
pub struct EnvProvider {
    policy: Policy,
}

impl EnvProvider {
    pub fn new(policy: Policy) -> Self {
        Self { policy }
    }

    pub fn get(&self, key: &str, tenant: Option<&TenantCtx>) -> Result<String, SecretError> {
        if !self.policy.is_allowed(key, tenant) {
            return Err(SecretError::Denied {
                key: key.to_string(),
            });
        }

        std::env::var(key).map_err(|_| SecretError::NotFound {
            key: key.to_string(),
        })
    }
}
