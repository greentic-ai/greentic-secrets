use crate::spec_compat::{
    Error as CoreError, Result as CoreResult, Scope, SecretListItem, SecretRecord, SecretUri,
    SecretVersion, SecretsBackend, VersionedSecret,
};

/// AWS Secrets Manager backend (feature-gated placeholder).
///
/// Secret IDs are derived as `"gtsec/<env>/<tenant>/<team|_>/<category>"` with
/// an optional `/<name>` suffix. The default version stage is `AWSCURRENT`.
#[derive(Debug, Clone, Default)]
pub struct AwsSecretsManagerBackend;

impl AwsSecretsManagerBackend {
    pub fn new() -> Self {
        Self
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn secret_id(uri: &SecretUri) -> String {
        format!(
            "gtsec/{}/{}/{}/{}/{}",
            sanitize(uri.scope().env()),
            sanitize(uri.scope().tenant()),
            uri.scope()
                .team()
                .map(sanitize)
                .unwrap_or_else(|| "_".into()),
            sanitize(uri.category()),
            sanitize(uri.name())
        )
    }
}

impl SecretsBackend for AwsSecretsManagerBackend {
    fn put(&self, _record: SecretRecord) -> CoreResult<SecretVersion> {
        Err(CoreError::Storage(
            "aws secrets manager backend requires runtime integration (feature placeholder)".into(),
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
            "aws secrets manager backend requires runtime integration (feature placeholder)".into(),
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
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => c,
            '/' => '_',
            _ => '-',
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_id_mapping() {
        let scope = Scope::new("prod", "tenant", Some("payments".into())).unwrap();
        let uri = SecretUri::new(scope, "configs", "service").unwrap();
        assert_eq!(
            AwsSecretsManagerBackend::secret_id(&uri),
            "gtsec/prod/tenant/payments/configs/service"
        );
    }

    #[test]
    #[ignore = "requires AWS credentials and network access"]
    fn integration_placeholder() {
        let backend = AwsSecretsManagerBackend::new();
        let scope = Scope::new("prod", "tenant", None).unwrap();
        let uri = SecretUri::new(scope, "configs", "service").unwrap();
        let _ = backend.get(&uri, None).unwrap();
    }
}
