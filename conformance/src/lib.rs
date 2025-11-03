use anyhow::Result;
use uuid::Uuid;

pub async fn run() -> Result<()> {
    let raw_prefix = std::env::var("GTS_PREFIX").unwrap_or_else(|_| {
        let id = Uuid::new_v4().simple();
        format!("gtconf-{id}")
    });
    let base_prefix = suite::sanitize(&raw_prefix);

    #[cfg(feature = "provider-dev")]
    suite::run_dev(&base_prefix).await?;

    #[cfg(feature = "provider-aws")]
    suite::run_aws(&base_prefix).await?;

    #[cfg(feature = "provider-azure")]
    suite::run_azure(&base_prefix).await?;

    #[cfg(feature = "provider-gcp")]
    suite::run_gcp(&base_prefix).await?;

    #[cfg(feature = "provider-k8s")]
    suite::run_k8s(&base_prefix).await?;

    #[cfg(feature = "provider-vault")]
    suite::run_vault(&base_prefix).await?;

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

mod suite {
    use anyhow::{Result, anyhow};
    use greentic_secrets_spec::{
        ContentType, EncryptionAlgorithm, Envelope, SecretMeta, SecretRecord, SecretUri,
        SecretsBackend, SecretsResult, Visibility,
    };
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::task;

    const CATEGORY: &str = "conformance";

    pub(super) fn sanitize(value: &str) -> String {
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
        sanitize(&format!("{base}-{provider}"))
    }

    fn make_scope(tag: &str) -> SecretsResult<greentic_secrets_spec::Scope> {
        greentic_secrets_spec::Scope::new(
            sanitize(&format!("{tag}-env")),
            sanitize(&format!("{tag}-tenant")),
            Some(sanitize(&format!("{tag}-team"))),
        )
    }

    fn make_uri(scope: &greentic_secrets_spec::Scope, tag: &str) -> SecretsResult<SecretUri> {
        SecretUri::new(scope.clone(), CATEGORY, sanitize(&format!("{tag}-secret")))
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

    #[allow(dead_code)]
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
        assert!(
            versions
                .iter()
                .any(|v| v.version == put.version && !v.deleted)
        );
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
    pub(super) async fn run_dev(base: &str) -> Result<()> {
        use greentic_secrets_provider_dev::DevBackend;

        let tag = combine_tag(base, "dev");
        let scope = convert(make_scope(&tag))?;
        let uri = convert(make_uri(&scope, &tag))?;
        let payload = make_payload(&tag);
        let backend: Box<dyn SecretsBackend> = Box::new(DevBackend::new());
        run_cycle(backend, scope, uri, payload)
    }

    #[cfg(feature = "provider-aws")]
    pub(super) async fn run_aws(base: &str) -> Result<()> {
        use greentic_secrets_provider_aws_sm::{BackendComponents, build_backend};

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
    pub(super) async fn run_azure(base: &str) -> Result<()> {
        use greentic_secrets_provider_azure_kv::{BackendComponents, build_backend};

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
    pub(super) async fn run_gcp(base: &str) -> Result<()> {
        use greentic_secrets_provider_gcp_sm::{BackendComponents, build_backend};

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
    pub(super) async fn run_k8s(base: &str) -> Result<()> {
        use greentic_secrets_provider_k8s::{BackendComponents, build_backend};

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
    pub(super) async fn run_vault(base: &str) -> Result<()> {
        use greentic_secrets_provider_vault_kv::{BackendComponents, build_backend};

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

    #[allow(dead_code)]
    async fn run_provider_async<B, Fut>(base: &str, provider: &str, builder: B) -> Result<()>
    where
        B: Send + 'static + FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Box<dyn SecretsBackend>>> + Send + 'static,
    {
        let tag = combine_tag(base, provider);
        let scope = convert(make_scope(&tag))?;
        let uri = convert(make_uri(&scope, &tag))?;
        let payload = make_payload(&tag);

        let backend = builder().await?;

        task::spawn_blocking(move || run_cycle(backend, scope, uri, payload))
            .await
            .map_err(|err| anyhow!("provider task panicked: {err}"))??;

        Ok(())
    }
}
