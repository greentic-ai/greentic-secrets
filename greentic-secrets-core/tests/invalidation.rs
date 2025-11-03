use secrets_core::embedded::{MemoryBackend, MemoryKeyProvider, SecretsCore};
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
    fn put(&self, record: secrets_core::SecretRecord) -> secrets_core::Result<SecretVersion> {
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

fn build_core(backend: CountingBackend) -> SecretsCore {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let previous = std::env::var("GREENTIC_SECRETS_DEV").ok();
    unsafe {
        std::env::set_var("GREENTIC_SECRETS_DEV", "0");
    }

    let builder = secrets_core::SecretsCore::builder()
        .tenant("example-tenant")
        .default_ttl(Duration::from_secs(300))
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
fn purge_cache_clears_entries() {
    let backend = CountingBackend::new();
    let core = build_core(backend.clone());
    let uri = "secrets://dev/example-tenant/_/configs/demo";
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async {
        core.put_json(uri, &json!({"value": 1})).await.unwrap();
        core.purge_cache(&[uri.to_string()]);
        core.get_bytes(uri).await.unwrap();
    });

    assert_eq!(backend.get_calls(), 1);
    core.purge_cache(&[uri.to_string()]);

    rt.block_on(async {
        core.get_bytes(uri).await.unwrap();
    });

    assert_eq!(backend.get_calls(), 2);
}

#[test]
fn purge_prefix_clears_matching_entries() {
    let backend = CountingBackend::new();
    let core = build_core(backend.clone());
    let uri_a = "secrets://dev/example-tenant/_/configs/a";
    let uri_b = "secrets://dev/example-tenant/_/configs/b";
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async {
        core.put_json(uri_a, &json!({"value": 1})).await.unwrap();
        core.put_json(uri_b, &json!({"value": 2})).await.unwrap();
        core.purge_cache(&["secrets://dev/example-tenant/_/configs/*".to_string()]);
        core.get_bytes(uri_a).await.unwrap();
        core.get_bytes(uri_b).await.unwrap();
    });

    assert_eq!(backend.get_calls(), 2);

    core.purge_cache(&["secrets://dev/example-tenant/_/configs/*".to_string()]);

    rt.block_on(async {
        core.get_bytes(uri_a).await.unwrap();
        core.get_bytes(uri_b).await.unwrap();
    });

    assert!(backend.get_calls() >= 4);
}
