use anyhow::Result;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<()> {
    let raw_prefix = std::env::var("GTS_PREFIX")
        .unwrap_or_else(|_| format!("gtconf-{}", Uuid::new_v4().simple()));
    let base_prefix = tests::sanitize(&raw_prefix);

    #[cfg(feature = "provider-dev")]
    tests::run_dev(&base_prefix).await?;

    #[cfg(feature = "provider-aws")]
    tests::run_aws(&base_prefix).await?;

    #[cfg(feature = "provider-azure")]
    tests::run_azure(&base_prefix).await?;

    #[cfg(feature = "provider-gcp")]
    tests::run_gcp(&base_prefix).await?;

    #[cfg(feature = "provider-k8s")]
    tests::run_k8s(&base_prefix).await?;

    #[cfg(feature = "provider-vault")]
    tests::run_vault(&base_prefix).await?;

    #[cfg(not(any(
        feature = "provider-dev",
        feature = "provider-aws",
        feature = "provider-azure",
        feature = "provider-gcp",
        feature = "provider-k8s",
        feature = "provider-vault"
    )))]
    {
        let _ = base_prefix;
    }

    Ok(())
}

#[allow(dead_code, unused_imports)]
mod tests {
    use anyhow::{Context, Result};
    use greentic_secrets_spec::{
        ContentType, EncryptionAlgorithm, Envelope, SecretMeta, SecretRecord, SecretUri,
        SecretsBackend, SecretsResult, Visibility,
    };
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::runtime::Runtime;

    const CATEGORY: &str = "conformance";

    pub(crate) fn sanitize(value: &str) -> String {
        let mut out = String::new();
        for ch in value.chars() {
            match ch {
                'a'..='z' | '0'..='9' | '-' | '_' | '.' => out.push(ch),
                'A'..='Z' => out.push(ch.to_ascii_lowercase()),
                _ => out.push('-'),
            }
        }
        if out.is_empty() {
            "default".into()
        } else {
            out
        }
    }

    fn combine_tag(base: &str, provider: &str) -> String {
        sanitize(&format!("{}-{}", base, provider))
    }

    fn make_scope(tag: &str) -> SecretsResult<greentic_secrets_spec::Scope> {
        greentic_secrets_spec::Scope::new(
            sanitize(&format!("{}-env", tag)),
            sanitize(&format!("{}-tenant", tag)),
            Some(sanitize(&format!("{}-team", tag))),
        )
    }

    fn make_uri(scope: &greentic_secrets_spec::Scope, tag: &str) -> SecretsResult<SecretUri> {
        SecretUri::new(
            scope.clone(),
            CATEGORY,
            sanitize(&format!("{}-secret", tag)),
        )
    }

    fn make_payload(tag: &str) -> String {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!("payload::{tag}::{ts}")
    }

    fn build_record(uri: SecretUri, value: &str) -> SecretRecord {
        let mut meta = SecretMeta::new(uri.clone(), Visibility::Team, ContentType::Opaque);
        meta.description = Some("conformance test secret".into());
        let envelope = Envelope {
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            nonce: vec![0u8; 12],
            hkdf_salt: vec![1u8; 16],
            wrapped_dek: vec![2u8; 32],
        };
        SecretRecord::new(meta, value.as_bytes().to_vec(), envelope)
    }

    fn convert<T>(res: SecretsResult<T>) -> Result<T> {
        res.map_err(anyhow::Error::from)
    }

    struct Cleanup {
        backend: Box<dyn SecretsBackend>,
        uri: SecretUri,
        delete_on_drop: bool,
    }

    impl Cleanup {
        fn new(backend: Box<dyn SecretsBackend>, uri: SecretUri) -> Self {
            Self {
                backend,
                uri,
                delete_on_drop: true,
            }
        }

        fn backend_mut(&mut self) -> &mut dyn SecretsBackend {
            &mut *self.backend
        }

        fn disarm(&mut self) {
            self.delete_on_drop = false;
        }
    }

    impl Drop for Cleanup {
        fn drop(&mut self) {
            if self.delete_on_drop {
                let _ = self.backend.delete(&self.uri);
            }
        }
    }

    fn run_cycle(
        backend: Box<dyn SecretsBackend>,
        scope: greentic_secrets_spec::Scope,
        uri: SecretUri,
        payload: String,
    ) -> Result<()> {
        let mut cleanup = Cleanup::new(backend, uri.clone());
        let backend = cleanup.backend_mut();

        let record = build_record(uri.clone(), &payload);
        let put = convert(backend.put(record.clone()))?;
        assert!(put.version >= 1, "put should return a positive version");

        let fetched =
            convert(backend.get(&uri, None))?.expect("secret should exist immediately after put");
        let fetched_record = fetched
            .record()
            .expect("versioned secret must include record");
        assert_eq!(fetched_record.value, record.value);

        let listed = convert(backend.list(&scope, Some(CATEGORY), None))?;
        assert!(listed.iter().any(|item| item.uri == uri));

        let versions = convert(backend.versions(&uri))?;
        assert!(versions
            .iter()
            .any(|v| v.version == put.version && !v.deleted));
        assert!(convert(backend.exists(&uri))?);

        let deleted = convert(backend.delete(&uri))?;
        assert!(deleted.deleted);

        assert!(convert(backend.get(&uri, None))?.is_none());
        assert!(!convert(backend.exists(&uri))?);

        let versions_after = convert(backend.versions(&uri))?;
        assert!(versions_after.iter().any(|v| v.deleted));

        let listed_after = convert(backend.list(&scope, Some(CATEGORY), None))?;
        assert!(listed_after.iter().all(|item| item.uri != uri));

        cleanup.disarm();
        Ok(())
    }

    #[cfg(feature = "provider-dev")]
    pub async fn run_dev(base: &str) -> Result<()> {
        use greentic_secrets_provider_dev::DevBackend;

        let tag = combine_tag(base, "dev");
        let scope = convert(make_scope(&tag))?;
        let uri = convert(make_uri(&scope, &tag))?;
        let payload = make_payload(&tag);
        let backend: Box<dyn SecretsBackend> = Box::new(DevBackend::new());
        run_cycle(backend, scope, uri, payload)
    }

    #[cfg(feature = "provider-aws")]
    pub async fn run_aws(base: &str) -> Result<()> {
        use greentic_secrets_provider_aws_sm::{build_backend, BackendComponents};

        run_provider_async(base, "aws", || async {
            let BackendComponents {
                backend,
                key_provider,
            } = build_backend().await?;
            drop(key_provider);
            Ok(backend)
        })
        .await
    }

    #[cfg(feature = "provider-azure")]
    pub async fn run_azure(base: &str) -> Result<()> {
        use greentic_secrets_provider_azure_kv::{build_backend, BackendComponents};

        run_provider_async(base, "azure", || async {
            let BackendComponents {
                backend,
                key_provider,
            } = build_backend().await?;
            drop(key_provider);
            Ok(backend)
        })
        .await
    }

    #[cfg(feature = "provider-gcp")]
    pub async fn run_gcp(base: &str) -> Result<()> {
        use greentic_secrets_provider_gcp_sm::{build_backend, BackendComponents};

        run_provider_async(base, "gcp", || async {
            let BackendComponents {
                backend,
                key_provider,
            } = build_backend().await?;
            drop(key_provider);
            Ok(backend)
        })
        .await
    }

    #[cfg(feature = "provider-k8s")]
    pub async fn run_k8s(base: &str) -> Result<()> {
        use greentic_secrets_provider_k8s::{build_backend, BackendComponents};

        run_provider_async(base, "k8s", || async {
            let BackendComponents {
                backend,
                key_provider,
            } = build_backend().await?;
            drop(key_provider);
            Ok(backend)
        })
        .await
    }

    #[cfg(feature = "provider-vault")]
    pub async fn run_vault(base: &str) -> Result<()> {
        use greentic_secrets_provider_vault_kv::{build_backend, BackendComponents};

        run_provider_async(base, "vault", || async {
            let BackendComponents {
                backend,
                key_provider,
            } = build_backend().await?;
            drop(key_provider);
            Ok(backend)
        })
        .await
    }

    async fn run_provider_async<B, Fut>(base: &str, provider: &str, builder: B) -> Result<()>
    where
        B: Send + 'static + FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Box<dyn SecretsBackend>>> + Send + 'static,
    {
        let tag = combine_tag(base, provider);
        let scope = convert(make_scope(&tag))?;
        let uri = convert(make_uri(&scope, &tag))?;
        let payload = make_payload(&tag);

        tokio::task::spawn_blocking(move || -> Result<()> {
            let runtime = Runtime::new().context("failed to create helper runtime")?;
            let backend = runtime.block_on(builder())?;
            drop(runtime);
            run_cycle(backend, scope, uri, payload)
        })
        .await??;

        Ok(())
    }
}
