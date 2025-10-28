use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    #[cfg(feature = "provider-dev")]
    tests::run_dev().await?;

    Ok(())
}

mod tests {
    use anyhow::Result;

    #[cfg(feature = "provider-dev")]
    pub async fn run_dev() -> Result<()> {
        use greentic_secrets_provider_dev::DevBackend;
        use greentic_secrets_spec::{
            ContentType, Scope, SecretUri, SecretVersion, SecretsBackend, SecretsError, Visibility,
        };
        use greentic_secrets_support::constructors::record_from_plain;

        let backend = DevBackend::new();

        let scope = Scope::new("dev", "example", None)?;
        let uri = SecretUri::new(scope.clone(), "configs", "db_url")?;

        let mut record = record_from_plain("postgres://user:pass@localhost/db");
        record.meta.uri = uri.clone();
        record.meta.content_type = ContentType::Opaque;
        record.meta.visibility = Visibility::Team;

        let put_version = backend.put(record.clone())?;
        assert_eq!(put_version.version, 1);
        assert!(!put_version.deleted);

        let fetched = backend
            .get(&uri, None)?
            .expect("secret should exist after put");
        let fetched_record = fetched
            .record()
            .expect("versioned secret should contain a record");
        assert_eq!(fetched_record.value, record.value);

        let list = backend.list(&scope, Some("configs"), Some("db_"))?;
        assert!(
            list.iter().any(|item| item.uri == uri),
            "expected list to contain inserted secret"
        );

        let versions = backend.versions(&uri)?;
        assert_eq!(versions.len(), 1);
        assert_eq!(
            versions[0],
            SecretVersion {
                version: 1,
                deleted: false
            }
        );

        assert!(backend.exists(&uri)?);

        let deleted = backend.delete(&uri)?;
        assert_eq!(deleted.version, 2);
        assert!(deleted.deleted);

        // After deletion the secret should not be retrievable
        assert!(
            backend.get(&uri, None)?.is_none(),
            "secret should be gone after delete"
        );

        // Listing should now omit the deleted secret
        let list_after_delete = backend.list(&scope, None, None)?;
        assert!(
            list_after_delete.iter().all(|item| item.uri != uri),
            "deleted secret should not appear in listings"
        );

        // Versions should now include both live and tombstone entries
        let versions_after_delete = backend.versions(&uri)?;
        assert_eq!(versions_after_delete.len(), 2);
        assert!(
            versions_after_delete
                .iter()
                .any(|version| version.version == 2 && version.deleted),
            "missing tombstone entry"
        );

        match backend.list(&scope, Some("missing"), None) {
            Ok(items) => assert!(items.is_empty()),
            Err(SecretsError::Backend(_)) => {}
            Err(err) => return Err(err.into()),
        }

        Ok(())
    }
}
