use secrets_core::embedded::{MemoryBackend, MemoryKeyProvider, SecretsCore};
use secrets_core::types::SecretRecord;
use secrets_core::{SecretUri, SecretVersion, SecretsBackend, VersionedSecret};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

#[derive(Clone, Default)]
struct CountingBackend {
    inner: Arc<MemoryBackend>,
    gets: Arc<AtomicUsize>,
}

impl CountingBackend {
    fn new() -> Self {
        Self::default()
    }

    fn get_calls(&self) -> usize {
        self.gets.load(Ordering::SeqCst)
    }
}

impl SecretsBackend for CountingBackend {
    fn put(&self, record: SecretRecord) -> secrets_core::Result<SecretVersion> {
        self.inner.put(record)
    }

    fn get(
        &self,
        uri: &SecretUri,
        version: Option<u64>,
    ) -> secrets_core::Result<Option<VersionedSecret>> {
        self.gets.fetch_add(1, Ordering::SeqCst);
        self.inner.get(uri, version)
    }

    fn list(
        &self,
        scope: &secrets_core::Scope,
        category_prefix: Option<&str>,
        name_prefix: Option<&str>,
    ) -> secrets_core::Result<Vec<secrets_core::SecretListItem>> {
        self.inner.list(scope, category_prefix, name_prefix)
    }

    fn delete(&self, uri: &SecretUri) -> secrets_core::Result<SecretVersion> {
        self.inner.delete(uri)
    }

    fn versions(&self, uri: &SecretUri) -> secrets_core::Result<Vec<SecretVersion>> {
        self.inner.versions(uri)
    }

    fn exists(&self, uri: &SecretUri) -> secrets_core::Result<bool> {
        self.inner.exists(uri)
    }
}

fn build_core_with_backend(backend: CountingBackend, ttl: Duration) -> SecretsCore {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let previous = std::env::var("GREENTIC_SECRETS_DEV").ok();
    unsafe {
        std::env::set_var("GREENTIC_SECRETS_DEV", "0");
    }
    let builder = secrets_core::SecretsCore::builder()
        .default_ttl(ttl)
        .tenant("example-tenant")
        .backend(backend, MemoryKeyProvider::default());

    let core = rt.block_on(builder.build()).unwrap();

    if let Some(prev) = previous {
        unsafe {
            std::env::set_var("GREENTIC_SECRETS_DEV", prev);
        }
    } else {
        unsafe {
            std::env::remove_var("GREENTIC_SECRETS_DEV");
        }
    }

    core
}

#[test]
fn cache_hit_avoids_backend() {
    let backend = CountingBackend::new();
    let core = build_core_with_backend(backend.clone(), Duration::from_secs(300));

    let uri = "secrets://dev/example-tenant/_/configs/cache-hit";
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async {
        core.put_json(uri, &json!({"value": 1})).await.unwrap();
        core.purge_cache(&[uri.to_string()]);
        core.get_bytes(uri).await.unwrap();
        core.get_bytes(uri).await.unwrap();
    });

    assert_eq!(backend.get_calls(), 1);
}

#[test]
fn cache_expiry_triggers_backend() {
    let backend = CountingBackend::new();
    let core = build_core_with_backend(backend.clone(), Duration::from_millis(50));

    let uri = "secrets://dev/example-tenant/_/configs/cache-ttl";
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async {
        core.put_json(uri, &json!({"value": 1})).await.unwrap();
        core.purge_cache(&[uri.to_string()]);
        core.get_bytes(uri).await.unwrap();
        tokio::time::sleep(Duration::from_millis(75)).await;
        core.get_bytes(uri).await.unwrap();
    });

    assert!(backend.get_calls() >= 2);
}
