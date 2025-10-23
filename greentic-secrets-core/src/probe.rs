#![allow(dead_code)]

#[cfg(feature = "k8s")]
const SERVICE_ACCOUNT_DIR: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

#[cfg(feature = "k8s")]
fn service_account_exists() -> bool {
    #[cfg(test)]
    {
        if let Some(override_path) = SERVICE_ACCOUNT_OVERRIDE
            .lock()
            .expect("service account override mutex poisoned")
            .clone()
        {
            return override_path.exists();
        }
    }

    std::path::Path::new(SERVICE_ACCOUNT_DIR).exists()
}

#[cfg(feature = "k8s")]
#[cfg(test)]
static SERVICE_ACCOUNT_OVERRIDE: once_cell::sync::Lazy<
    std::sync::Mutex<Option<std::path::PathBuf>>,
> = once_cell::sync::Lazy::new(|| std::sync::Mutex::new(None));

#[cfg(feature = "k8s")]
pub async fn is_kubernetes() -> bool {
    if std::env::var_os("KUBERNETES_SERVICE_HOST").is_some() {
        return service_account_exists();
    }
    false
}

#[cfg(not(feature = "k8s"))]
pub async fn is_kubernetes() -> bool {
    false
}

#[cfg(feature = "aws")]
pub async fn is_aws() -> bool {
    super::imds::head(
        "http://169.254.169.254/latest/meta-data/instance-id",
        &[],
        probe_timeout(),
    )
    .await
}

#[cfg(not(feature = "aws"))]
pub async fn is_aws() -> bool {
    false
}

#[cfg(feature = "gcp")]
pub async fn is_gcp() -> bool {
    super::imds::head(
        "http://169.254.169.254",
        &[("Metadata-Flavor", "Google")],
        probe_timeout(),
    )
    .await
}

#[cfg(not(feature = "gcp"))]
pub async fn is_gcp() -> bool {
    false
}

#[cfg(feature = "azure")]
pub async fn is_azure() -> bool {
    super::imds::head(
        "http://169.254.169.254/metadata/instance",
        &[("Metadata", "true")],
        probe_timeout(),
    )
    .await
}

#[cfg(not(feature = "azure"))]
pub async fn is_azure() -> bool {
    false
}

#[cfg(all(test, feature = "k8s"))]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn set_service_account_override(path: Option<PathBuf>) {
        let mut guard = SERVICE_ACCOUNT_OVERRIDE
            .lock()
            .expect("service account override mutex poisoned");
        *guard = path;
    }

    #[tokio::test]
    async fn detects_kubernetes_when_env_and_service_account_present() {
        let tmp = tempdir().expect("temp dir");
        let sa_dir = tmp.path().join("serviceaccount");
        std::fs::create_dir_all(&sa_dir).expect("create service account dir");

        std::env::set_var("KUBERNETES_SERVICE_HOST", "10.0.0.1");
        set_service_account_override(Some(sa_dir));
        assert!(is_kubernetes().await);

        set_service_account_override(None);
        std::env::remove_var("KUBERNETES_SERVICE_HOST");
    }
}

#[cfg(all(test, feature = "aws"))]
mod aws_tests {
    use super::*;

    #[tokio::test]
    async fn aws_probe_fails_closed_without_metadata() {
        let detected = is_aws().await;
        assert!(
            !detected,
            "aws probe should fail closed when metadata unavailable"
        );
    }
}

#[cfg(all(test, feature = "gcp"))]
mod gcp_tests {
    use super::*;

    #[tokio::test]
    async fn gcp_probe_fails_closed_without_metadata() {
        assert!(!is_gcp().await);
    }
}

#[cfg(all(test, feature = "azure"))]
mod azure_tests {
    use super::*;

    #[tokio::test]
    async fn azure_probe_fails_closed_without_metadata() {
        assert!(!is_azure().await);
    }
}

fn probe_timeout() -> std::time::Duration {
    let ms = std::env::var("GREENTIC_SECRETS_PROBE_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(50);
    std::time::Duration::from_millis(ms)
}
