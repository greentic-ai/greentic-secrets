use crate::spec_compat::{
    Error as CoreError, Result as CoreResult, Scope, SecretListItem, SecretRecord, SecretUri,
    SecretVersion, SecretsBackend, VersionedSecret,
};

/// Kubernetes-backed secrets store (feature-gated).
///
/// URIs are mapped to Kubernetes resources as follows:
///
/// * Namespace: `gtsec-<env>-<tenant>` (team appended as `-<team>` when present).
/// * Secret name: `<category>-<name>` (sanitised to DNS-1123 compatible form).
/// * Secret `data` key: `"payload"`.
///
/// The `SecretRecord` is serialised to JSON and the resulting bytes are
/// base64-encoded when stored in `data.payload`, matching the behaviour of the
/// Kubernetes API.
#[derive(Debug, Clone, Default)]
pub struct K8sBackend;

impl K8sBackend {
    /// Construct a placeholder backend. Full runtime integration is implemented
    /// in PR-EMB-06.
    pub fn new() -> Self {
        Self
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn namespace_for(uri: &SecretUri) -> String {
        let mut ns = format!(
            "gtsec-{}-{}",
            sanitize(uri.scope().env()),
            sanitize(uri.scope().tenant())
        );
        if let Some(team) = uri.scope().team() {
            ns.push('-');
            ns.push_str(&sanitize(team));
        }
        ns
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn secret_name_for(uri: &SecretUri) -> String {
        format!("{}-{}", sanitize(uri.category()), sanitize(uri.name()))
    }
}

impl SecretsBackend for K8sBackend {
    fn put(&self, _record: SecretRecord) -> CoreResult<SecretVersion> {
        Err(CoreError::Storage(
            "k8s backend requires runtime integration (feature placeholder)".into(),
        ))
    }

    fn get(&self, _uri: &SecretUri, _version: Option<u64>) -> CoreResult<Option<VersionedSecret>> {
        Ok(None)
    }

    fn list(
        &self,
        _scope: &Scope,
        _category_prefix: Option<&str>,
        _name_prefix: Option<&str>,
    ) -> CoreResult<Vec<SecretListItem>> {
        Ok(Vec::new())
    }

    fn delete(&self, _uri: &SecretUri) -> CoreResult<SecretVersion> {
        Err(CoreError::Storage(
            "k8s backend requires runtime integration (feature placeholder)".into(),
        ))
    }

    fn versions(&self, _uri: &SecretUri) -> CoreResult<Vec<SecretVersion>> {
        Ok(Vec::new())
    }

    fn exists(&self, _uri: &SecretUri) -> CoreResult<bool> {
        Ok(false)
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn sanitize(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            'a'..='z' | '0'..='9' => c,
            'A'..='Z' => c.to_ascii_lowercase(),
            '-' => '-',
            _ => '-',
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec_compat::{ContentType, Envelope, SecretMeta, Visibility};
    use greentic_secrets_spec::{record_from_plain, with_ttl};

    fn sample_uri(team: Option<&str>) -> SecretUri {
        let scope = Scope::new("prod", "tenant", team.map(|t| t.to_string())).unwrap();
        SecretUri::new(scope, "configs", "service").unwrap()
    }

    #[test]
    fn namespace_and_name_mapping() {
        let uri = sample_uri(Some("payments"));
        assert_eq!(
            K8sBackend::namespace_for(&uri),
            "gtsec-prod-tenant-payments"
        );
        assert_eq!(K8sBackend::secret_name_for(&uri), "configs-service");

        let uri_no_team = sample_uri(None);
        assert_eq!(K8sBackend::namespace_for(&uri_no_team), "gtsec-prod-tenant");
    }

    #[test]
    #[ignore = "requires in-cluster or kubeconfig access"]
    fn integration_placeholder() {
        let backend = K8sBackend::new();
        let uri = sample_uri(None);
        let mut record = record_from_plain(String::new());
        let mut meta = SecretMeta::new(uri.clone(), Visibility::Team, ContentType::Json);
        meta.description = Some("placeholder".into());
        record.meta = meta;
        record.envelope = Envelope {
            algorithm: crate::spec_compat::EncryptionAlgorithm::Aes256Gcm,
            nonce: vec![],
            hkdf_salt: vec![],
            wrapped_dek: vec![],
        };
        let _ = backend
            .put(with_ttl(record, 120))
            .err()
            .expect("backend placeholder");
    }
}
