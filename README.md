# Greentic Secrets

The workspace provides two related entry points:

* **Embedded runtime (`secrets-core`)** – preferred path for applications to
  fetch secrets directly from Rust using the `SecretsCore` builder, optional
  cache, and pluggable backends.
* **HTTP/NATS broker (`secrets-broker`)** – optional control-plane surface for
  operators or cross-language clients.

## Quick start

| Goal | Crate | Example | Run it |
|---|---|---|---|
| Fetch a secret via embedded core (env/file) | `greentic-secrets-core` | `examples/embedded_fetch.rs` | `cargo run -p greentic-secrets-core --example embedded_fetch` |
| Self-describe & validate a secret spec | `greentic-secrets-core` | `examples/describe_and_validate.rs` | `cargo run -p greentic-secrets-core --example describe_and_validate` |
| Start the broker (HTTP/NATS) with one backend | `greentic-secrets-broker` | `examples/broker_startup.rs` | `cargo run -p greentic-secrets-broker --example broker_startup` |

### Minimal embedded usage (copy-paste)
```rust
use greentic_secrets_core::{SecretsCore, backends::EnvBackend};

fn main() {
    let core = SecretsCore::builder()
        .with_backend("env", EnvBackend::default())
        .build();
    let db_url = core.get("env:DB_URL").expect("DB_URL missing");
    println!("DB_URL = {}", db_url.redact_preview());
}
```

### Broker quick start (copy-paste)
```bash
# Minimal example — tweak ports/keys as needed
export SECRETS_BACKEND="env"
export RUST_LOG=info
cargo run -p greentic-secrets-broker --example broker_startup
```

### Providers (opt-in features)
Enable only what you deploy to:

```toml
# Direct dependency on the core crate
greentic-secrets-core = { version = "0.1", features = ["providers-aws"] }

# Or via the umbrella crate re-exports
greentic-secrets = { version = "0.1", features = ["providers-aws"] }
```

```rust
// Direct core import
use greentic_secrets_core::SecretsCore;
use greentic_secrets_core::aws::ProviderAwsBackend;

let core = SecretsCore::builder()
    .with_backend("aws", ProviderAwsBackend::default())
    .build();

// Umbrella crate re-export
use greentic_secrets::core::SecretsCore as UmbrellaCore;
use greentic_secrets::aws::ProviderAwsBackend as UmbrellaAwsBackend;

let umbrella_core = UmbrellaCore::builder()
    .with_backend("aws", UmbrellaAwsBackend::default())
    .build();
```

## Embedded usage

```rust
use secrets_core::SecretsCore;
use std::time::Duration;

# tokio::runtime::Runtime::new().unwrap().block_on(async {
let core = SecretsCore::builder()
    .tenant("example-tenant")
    .default_ttl(Duration::from_secs(600))
    .build()
    .await
    .unwrap();

let pwd = core
    .get_text("secrets://dev/example-tenant/_/configs/db_password")
    .await;
println!("db_password: {:?}", pwd);
# });
```

See [`docs/embedded.md`](docs/embedded.md) for builder options, environment
variables, invalidation semantics, and end-to-end examples (including WASM host
export).

For backend mapping rules see [`docs/backends.md`](docs/backends.md); policy
notes live under [`docs/policy.md`](docs/policy.md). Operator-focused guidance
is captured in [`docs/security.md`](docs/security.md) and
[`docs/rotation.md`](docs/rotation.md).

## Self-described secrets

Libraries can publish their required secrets by implementing
`SecretDescribable` and returning a static slice of `SecretSpec`. This allows
tooling to enumerate dependencies without instantiating the runtime core.

```rust
use secrets_core::{SecretDescribable, SecretSpec};

struct PaymentsSecrets;

impl SecretDescribable for PaymentsSecrets {
    fn secret_specs() -> &'static [SecretSpec] {
        &[SecretSpec {
            name: "PAYMENTS_API_TOKEN",
            description: Some("Token used to authenticate outbound payment calls"),
        }]
    }
}

let mut registry = secrets_core::SecretSpecRegistry::new();
registry.extend_with(PaymentsSecrets::secret_specs());
println!("{}", registry.to_markdown_table());

let validation = core
    .validate_specs_at_prefix("secrets://dev/example-tenant/_/", PaymentsSecrets::secret_specs())
    .await?;
if !validation.missing.is_empty() {
    eprintln!("missing secrets: {:?}", validation.missing);
}
```

## Broker

The broker remains available for HTTP and NATS workflows. Build it with the
backend features you need and run it alongside your existing infrastructure.

## Releasing

We publish workspace crates to crates.io via GitHub Actions:

- **Bump versions** in each `Cargo.toml` you want to release (or use your preferred versioning tool).
- **Tag the repo**: `git tag v0.1.3 && git push --tags`.
- CI publishes only crates whose new version isn’t yet on crates.io (in dependency order) and creates a GitHub Release.
- To validate before tagging, open a PR and check **“Check crates (package dry-run)”**.
- To publish one crate manually (e.g., a provider), use the **“Publish one crate”** workflow from the Actions tab.
- You can automate the bump/tag/push flow with `scripts/release.sh X.Y.Z`, which runs `cargo workspaces version`, dry-run packaging, regenerates `CHANGELOG.md`, and pushes the release tag.

Make sure the repository has the `CARGO_REGISTRY_TOKEN` secret set (crates.io → Account → New token).
