use crate::spec_compat::{
    Error as CoreError, Result as CoreResult, Scope, SecretListItem, SecretRecord, SecretUri,
    SecretVersion, SecretsBackend, VersionedSecret,
};

/// Read-only backend that fetches secrets from process environment variables.
#[derive(Debug, Default, Clone, Copy)]
pub struct EnvBackend;

impl EnvBackend {
    /// Construct a new [`EnvBackend`].
    pub fn new() -> Self {
        Self
    }

    fn var_name(uri: &SecretUri) -> String {
        format!(
            "GTSEC_{}_{}_{}_{}_{}",
            sanitize_segment(uri.scope().env()),
            sanitize_segment(uri.scope().tenant()),
            uri.scope()
                .team()
                .map(sanitize_segment)
                .unwrap_or_else(|| "_".to_string()),
            sanitize_segment(uri.category()),
            sanitize_segment(uri.name())
        )
    }

    fn load_record(&self, uri: &SecretUri) -> CoreResult<Option<SecretRecord>> {
        let var = Self::var_name(uri);
        match std::env::var(&var) {
            Ok(value) => {
                let record: SecretRecord = serde_json::from_str(&value)
                    .map_err(|err| CoreError::Storage(err.to_string()))?;
                Ok(Some(record))
            }
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(err) => Err(CoreError::Storage(err.to_string())),
        }
    }
}

impl SecretsBackend for EnvBackend {
    fn put(&self, _record: SecretRecord) -> CoreResult<SecretVersion> {
        Err(CoreError::Storage("env backend is read-only".to_string()))
    }

    fn get(&self, uri: &SecretUri, version: Option<u64>) -> CoreResult<Option<VersionedSecret>> {
        if version.is_some() {
            return Ok(None);
        }
        match self.load_record(uri)? {
            Some(record) => Ok(Some(VersionedSecret {
                version: 1,
                deleted: false,
                record: Some(record),
            })),
            None => Ok(None),
        }
    }

    fn list(
        &self,
        _scope: &Scope,
        _category_prefix: Option<&str>,
        _name_prefix: Option<&str>,
    ) -> CoreResult<Vec<SecretListItem>> {
        Err(CoreError::Storage(
            "env backend does not support listing".to_string(),
        ))
    }

    fn delete(&self, _uri: &SecretUri) -> CoreResult<SecretVersion> {
        Err(CoreError::Storage("env backend is read-only".to_string()))
    }

    fn versions(&self, _uri: &SecretUri) -> CoreResult<Vec<SecretVersion>> {
        Ok(vec![])
    }

    fn exists(&self, uri: &SecretUri) -> CoreResult<bool> {
        Ok(self.load_record(uri)?.is_some())
    }
}

fn sanitize_segment(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' => c.to_ascii_uppercase(),
            _ => '_',
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec_compat::{ContentType, Envelope, SecretMeta, Visibility};
    use greentic_secrets_support::{record_from_plain, with_ttl};

    fn sample_record(uri: SecretUri) -> SecretRecord {
        let mut record = record_from_plain(r#"{"token":"value"}"#);
        let mut meta = SecretMeta::new(uri, Visibility::Team, ContentType::Json);
        meta.description = Some("env backend".into());
        record.meta = meta;
        record.envelope = Envelope {
            algorithm: crate::spec_compat::EncryptionAlgorithm::Aes256Gcm,
            nonce: vec![1, 2, 3],
            hkdf_salt: vec![4, 5, 6],
            wrapped_dek: vec![7, 8, 9],
        };
        with_ttl(record, 1800)
    }

    #[test]
    fn env_backend_get_and_missing() {
        let backend = EnvBackend::new();
        let scope = Scope::new("dev", "tenant", Some("team".into())).unwrap();
        let uri = SecretUri::new(scope, "configs", "service").unwrap();
        let record = sample_record(uri.clone());
        let var = EnvBackend::var_name(&uri);
        std::env::set_var(&var, serde_json::to_string(&record).unwrap());

        let fetched = backend.get(&uri, None).unwrap().unwrap();
        assert_eq!(fetched.record.unwrap().meta.uri, record.meta.uri);

        let missing_scope = Scope::new("dev", "tenant", Some("other".into())).unwrap();
        let missing_uri = SecretUri::new(missing_scope, "configs", "service").unwrap();
        assert!(backend.get(&missing_uri, None).unwrap().is_none());
    }
}
