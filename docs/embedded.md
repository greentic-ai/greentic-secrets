# Embedded SecretsCore

The `SecretsCore` builder allows Rust runtimes to fetch and manage secrets
directly without standing up the HTTP broker.

```rust
use secrets_core::{CoreBuilder, SecretsCore};
use serde_json::json;

# tokio::runtime::Runtime::new().unwrap().block_on(async {
// Build the core using environment defaults.  By default this enables the
// in-memory backend which is suitable for local development and tests.
let core: SecretsCore = CoreBuilder::from_env()
    .build()
    .await
    .expect("core");

// Write JSON data to a secret URI.
let uri = "secrets://dev/example/_/configs/runtime";
core.put_json(uri, &json!({ "token": "secret-value" }))
    .await
    .expect("put");

// Retrieve the secret as strongly typed JSON.
let value: serde_json::Value = core.get_json(uri).await.expect("get");
assert_eq!(value["token"], "secret-value");
# });
```

The builder also supports custom configuration:

```rust
use secrets_core::{MemoryBackend, MemoryKeyProvider, SecretsCore};
use std::time::Duration;

# tokio::runtime::Runtime::new().unwrap().block_on(async {
let core = SecretsCore::builder()
    .tenant("my-tenant")
    .team("payments")
    .default_ttl(Duration::from_secs(120))
    .backend(MemoryBackend::new(), MemoryKeyProvider::default())
    .build()
    .await
    .unwrap();
# let _ = core;
# });
```

Additional backends can be registered by supplying a type that implements
`SecretsBackend` together with a compatible `KeyProvider`.

When the `nats` feature is enabled and `nats_url` is configured, the core will
subscribe to `secrets.changed.<tenant>.<prefix>` subjects and evict cached
entries whenever an invalidation message is published:

```json
{"uris":["secrets://dev/tenant/_/configs/demo","secrets://dev/tenant/_/configs/db/*"]}
```

Exact URIs invalidate a single cache entry while values ending with `*`
invalidate all cached entries sharing the prefix.

## Environment configuration

The builder reads configuration from the following environment variables:

| Variable | Description |
| --- | --- |
| `GREENTIC_SECRETS_TENANT` | Default tenant scope (`"default"` if unset). |
| `GREENTIC_SECRETS_TEAM` | Optional team scope (`_` implies no team). |
| `GREENTIC_SECRETS_DEFAULT_TTL` | Cache TTL (e.g. `600s`). |
| `GREENTIC_SECRETS_NATS_URL` | NATS endpoint for cache invalidations. |
| `GREENTIC_SECRETS_DEV` | `1` enables the in-memory backend (default). |
| `GREENTIC_SECRETS_FILE_ROOT` | Root directory for the file backend. |

Feature backends rely on their platform defaults:

* **AWS (`--features aws`)** – honour `AWS_REGION`, IMDS, and credential env vars.
* **Kubernetes (`--features k8s`)** – use in-cluster configuration or `KUBECONFIG`.

## Autodiscovery (scaffold)

`CoreBuilder::auto_detect_backends()` prepares the builder with sensible
defaults when no backends have been registered:

```rust,no_run
# tokio::runtime::Runtime::new().unwrap().block_on(async {
use secrets_core::SecretsCore;

let core = SecretsCore::builder()
    .auto_detect_backends()
    .await
    .build()
    .await?;
# let _: SecretsCore = core;
# anyhow::Ok(())
# }).unwrap();
```

When the `k8s` feature is enabled, the builder first checks for
`KUBERNETES_SERVICE_HOST` together with the standard service account directory
(`/var/run/secrets/kubernetes.io/serviceaccount`). If both signals are present,
the Kubernetes backend is registered ahead of the local fallbacks.

With the `aws` feature, the probe issues a single HTTP `HEAD` request to the
instance metadata endpoint (`169.254.169.254/latest/meta-data/instance-id`)
using the shared IMDS helper and a 50 ms timeout. A successful response enables
the AWS Secrets Manager backend.

Additional probes follow the same pattern:

| Environment | Endpoint | Required Headers | Timeout |
| --- | --- | --- | --- |
| Kubernetes | Service account dir + `KUBERNETES_SERVICE_HOST` | n/a | filesystem check |
| AWS | `http://169.254.169.254/latest/meta-data/instance-id` | _none_ | configurable (default 50 ms) |
| GCP | `http://169.254.169.254` | `Metadata-Flavor: Google` | configurable (default 50 ms) |
| Azure | `http://169.254.169.254/metadata/instance` | `Metadata: true` | configurable (default 50 ms) |

Outside of Kubernetes/AWS, autodetection continues with GCP → Azure → environment and,
when `GREENTIC_SECRETS_FILE_ROOT` is set, the filesystem backend. Set
`GREENTIC_SECRETS_BACKENDS` to any value to disable autodetection entirely and
configure backends manually. The IMDS probe timeout can be overridden via
`GREENTIC_SECRETS_PROBE_TIMEOUT_MS` (default 50 ms).

The overall evaluation order is: Kubernetes → AWS → GCP → Azure → environment → file.

Future releases will extend the probes to cover additional cloud environments
while keeping the same API surface. These probes will rely on shared instance
metadata (IMDS) requests capped at 50–100 ms timeouts to stay responsive.
