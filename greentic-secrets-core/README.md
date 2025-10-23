# Greentic Secrets Core

`greentic-secrets-core` is the embedded runtime that powers the Greentic
secrets platform. It provides a pluggable `SecretsCore` builder, optional local
cache, and a common trait surface so credential providers can be swapped without
changing application logic.

The library compiles down to a single dependency-free crate by default while
allowing cloud backends to be pulled in behind feature flags. When published to
crates.io the crate name is `greentic-secrets-core`, but the compiled library
exports as `secrets_core` for continuity with earlier versions.

## Installation

```shell
cargo add greentic-secrets-core
```

By default the crate enables the lightweight `env` and `file` backends. You can
opt into additional integrations through feature flags:

| Feature | Purpose | Notes |
| --- | --- | --- |
| `env` (default) | Pull secrets from process environment variables | No async runtime required |
| `file` (default) | Read secrets from disk snapshots | Useful for local development |
| `aws` | AWS Secrets Manager client stubs | Enable together with a concrete provider implementation |
| `gcp` | Google Secret Manager client stubs | Requires async runtime |
| `azure` | Azure Key Vault secrets client stubs | Requires async runtime |
| `k8s` | Kubernetes secrets client stubs | Depends on the bundled kube/k8s-openapi stubs |
| `nats` | Emit invalidation events over NATS | Pulls in `tokio` and `async-nats` |
| `imds` | Access cloud metadata services | Activates `reqwest` (Rustls TLS only) |
| `schema` | Generate JSON schema for `SecretSpec` | Enables `schemars` |
| `xchacha` | Use XChaCha20-Poly1305 envelopes | Optional stronger envelope encryption |

## Quick Start

```rust
use secrets_core::SecretsCore;
use std::time::Duration;

# tokio::runtime::Runtime::new().unwrap().block_on(async {
let core = SecretsCore::builder()
    .tenant("example-tenant")
    .default_ttl(Duration::from_secs(600))
    .build()
    .await?;

let password = core
    .get_text("secrets://dev/example-tenant/_/configs/db_password")
    .await?;
println!("db_password: {password:?}");
# Ok::<(), secrets_core::Error>(())
# });
```

See the repository root [`docs/embedded.md`](../docs/embedded.md) for
configuration knobs (TTL, cache backends, invalidation semantics) and
[`docs/backends.md`](../docs/backends.md) for backend mapping rules.

## Working with Providers

Cloud-specific providers live in sibling crates (for example
`greentic-secrets-provider-aws-sm`). Each provider implements
`SecretsBackend` and `KeyProvider`, so you can compose the pieces that match
your deployment while still depending on `greentic-secrets-core` from your
application crate.

```toml
[dependencies]
greentic-secrets-core = { version = "0.1", features = ["aws"] }
greentic-secrets-provider-aws-sm = "0.1"
```

```rust
use secrets_core::{SecretsBroker, SecretsCore};
use secrets_provider_aws_sm::build_backend;

let SecretsBroker { backend, key_provider } = build_backend()?;
let core = SecretsCore::builder()
    .with_backend(backend)
    .with_key_provider(key_provider)
    .build()
    .await?;
```

For additional samples, browse the `examples/` directory or run
`cargo run --example put_get_json` inside the workspace.

## License

Licensed under the terms of the MIT license.
