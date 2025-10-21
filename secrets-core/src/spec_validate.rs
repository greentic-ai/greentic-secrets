use crate::{SecretSpec, SecretsCore, SecretsError};

/// Result produced when validating a set of specs against the runtime core.
pub struct SecretValidationResult {
    /// Secret names that were missing or empty.
    pub missing: Vec<&'static str>,
    /// Secret names that were present (non-empty).
    pub present: Vec<&'static str>,
}

impl SecretsCore {
    /// Validate that every secret in `specs` exists under the provided prefix.
    ///
    /// Example: base prefix `secrets://dev/example/_/` would test URIs such as
    /// `secrets://dev/example/_/configs/TELEGRAM_TOKEN`.
    pub async fn validate_specs_at_prefix(
        &self,
        base_prefix: &str,
        specs: &[SecretSpec],
    ) -> Result<SecretValidationResult, SecretsError> {
        let mut missing = Vec::new();
        let mut present = Vec::new();
        for spec in specs {
            let uri = format!("{base}configs/{name}", base = base_prefix, name = spec.name);
            match self.get_bytes(&uri).await {
                Ok(bytes) if !bytes.is_empty() => present.push(spec.name),
                _ => missing.push(spec.name),
            }
        }
        Ok(SecretValidationResult { missing, present })
    }
}
