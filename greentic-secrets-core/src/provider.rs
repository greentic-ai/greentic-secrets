use std::fmt;
use std::str::FromStr;

/// Supported secret providers that can be resolved at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    /// Auto-detect the provider using environment metadata.
    Auto,
    /// Use the in-process/local backends.
    Local,
    /// Use the AWS Secrets Manager backend.
    Aws,
    /// Use the Azure Key Vault backend.
    Azure,
    /// Use the Google Secret Manager backend.
    Gcp,
    /// Use the Kubernetes secrets backend.
    K8s,
}

impl Provider {
    /// Parse a provider from its environment representation.
    pub fn from_env_value(value: &str) -> Option<Self> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }
        trimmed.parse().ok()
    }

    /// Returns a static string identifier for the provider.
    pub fn as_str(&self) -> &'static str {
        match self {
            Provider::Auto => "auto",
            Provider::Local => "local",
            Provider::Aws => "aws",
            Provider::Azure => "azure",
            Provider::Gcp => "gcp",
            Provider::K8s => "k8s",
        }
    }
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Provider {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Ok(Provider::Auto),
            "local" | "dev" => Ok(Provider::Local),
            "aws" => Ok(Provider::Aws),
            "azure" => Ok(Provider::Azure),
            "gcp" => Ok(Provider::Gcp),
            "k8s" | "kubernetes" => Ok(Provider::K8s),
            _ => Err(()),
        }
    }
}
