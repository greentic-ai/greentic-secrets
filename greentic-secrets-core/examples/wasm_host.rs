use once_cell::sync::OnceCell;
use secrets_core::SecretsCore;
use std::sync::Arc;
use std::time::Duration;

wit_bindgen::generate!({
    path: "../greentic-secrets-wit/wit",
    world: "host",
});

static CORE: OnceCell<Arc<SecretsCore>> = OnceCell::new();
static RUNTIME: OnceCell<tokio::runtime::Runtime> = OnceCell::new();

struct SecretsHost;

impl exports::greentic::secrets::secrets::Guest for SecretsHost {
    fn get(uri: String) -> Vec<u8> {
        let runtime = RUNTIME.get().expect("runtime initialised");
        let core = CORE.get().expect("core initialised");
        let core = Arc::clone(core);
        runtime
            .block_on(async move { core.get_bytes(&uri).await })
            .unwrap_or_default()
    }
}

export!(SecretsHost);

fn main() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let core = runtime.block_on(async {
        SecretsCore::builder()
            .tenant("example-tenant")
            .default_ttl(Duration::from_secs(300))
            .build()
            .await
    })?;

    CORE.set(Arc::new(core))
        .map_err(|_| anyhow::anyhow!("core already initialised"))?;
    RUNTIME
        .set(runtime)
        .map_err(|_| anyhow::anyhow!("runtime already initialised"))?;

    println!("WASM host surface ready: call secrets.get(uri)");
    Ok(())
}
