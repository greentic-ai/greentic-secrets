# Repository Overview

## 1. High-Level Purpose
- Rust workspace for the Greentic secrets platform, providing an embedded secrets runtime plus optional HTTP/NATS broker so applications and operators can fetch, validate, and rotate secrets.
- Ships provider integrations for major backends (AWS Secrets Manager + KMS, Azure Key Vault, GCP Secret Manager + KMS, Kubernetes Secrets, Vault KV/Transit) and a dev/test backend, along with an umbrella crate, conformance suite, examples, and minimal runner bindings.

## 2. Main Components and Functionality
- **Path:** `greentic-secrets-api`  
  **Role:** Shared async trait + errors for secrets managers.  
  **Key functionality:** Defines `SecretsManager` read/write/delete API and `SecretError` variants for downstream hosts/providers.  
  **Key dependencies / integration points:** `async-trait`, `thiserror`; used by core and providers.
- **Path:** `greentic-secrets-spec`  
  **Role:** Common spec/types for secrets providers.  
  **Key functionality:** Secret URIs, records, envelopes, schema helpers, `SecretsBackend` and `KeyProvider` traits, versioning, and a registry for describable specs.  
  **Key dependencies / integration points:** No-std capable; reused by core, providers, and tooling.
- **Path:** `greentic-secrets-core`  
  **Role:** Embedded runtime for fetching/sealing secrets.  
  **Key functionality:** `SecretsCore` builder with TTL/cache, policy/resolver logic, optional HTTP/NATS/dek cache features, helper APIs for provider secrets, signing keys, and API keys; seed/apply pipeline (`DevContext` resolver, seed normalization, apply to pluggable `SecretsStore`, optional JSON-schema validation), dev-store adapter using the dev provider; example programs for embedded fetch, validation, and broker wiring.  
  **Key dependencies / integration points:** Uses `reqwest`/`tokio` when features enabled; integrates with providers via `SecretsBackend`/`KeyProvider`; dev-store feature uses `greentic-secrets-provider-dev`.
- **Path:** `greentic-secrets-broker`  
  **Role:** HTTP/NATS broker exposing the secrets engine and a CLI for spec tooling.  
  **Key functionality:** Binaries for the broker service and `secrets` CLI (print/check/schema subcommands) that load component secret specs (examples/plugins) and validate against a configured backend.  
  **Key dependencies / integration points:** Axum + NATS for transport; telemetry via `greentic-types`; composes provider backends.
- **Path:** `crates/greentic-secrets-cli`  
  **Role:** Dedicated CLI binary (`greentic-secrets`) for dev flows and seed handling.  
  **Key functionality:** Commands for `dev up/down` (prepare/remove local dev store), `ctx set/show` (store dev-only context), `scaffold` (generate seed template from pack `secret_requirements`), `wizard` (fill seeds interactively or from dotenv), `apply` (apply seeds to dev store or broker HTTP with optional requirement validation), and `init` (orchestrates dev up + ctx + scaffold + wizard + apply). Uses seed/apply helpers from core and reads pack metadata as JSON/YAML or `.gtpack` zip containing `secret_requirements`.  
  **Key dependencies / integration points:** Depends on core/spec (dev-store feature), serde, clap, zip; uses file-based dev provider path `.greentic/dev/.dev.secrets.env` by default; can target broker HTTP endpoints.
- **Path:** `greentic-secrets`  
  **Role:** Umbrella crate re-exporting core/spec/api and optional providers.  
  **Key functionality:** Simplifies downstream dependency management; re-exports spec requirement/seed types and core seed/apply helpers; enables provider features through a single crate.
- **Path:** `crates/greentic-secrets-runner`  
  **Role:** Host bridge for environment-backed secrets with tenant policy enforcement.  
  **Key functionality:** Bindings and tenant context types, allowlist-based policy, environment provider, and `secrets_get` helper to gate access per tenant/team.  
  **Key dependencies / integration points:** `serde`, `serde_json`, `thiserror`.
- **Path:** `providers/greentic-dev`  
  **Role:** Development/test backend with deterministic key provider.  
  **Key functionality:** File/env-backed secret storage with versioning, simple XOR-based key wrapping derived from a master key, persistence to `.dev.secrets.env`, and env overrides.  
  **Key dependencies / integration points:** Uses `greentic-secrets-spec` traits; integrates with broker/core during local dev.
- **Path:** `providers/greentic-aws-sm`  
  **Role:** AWS Secrets Manager backend plus KMS key provider.  
  **Key functionality:** Builds clients from env, supports custom endpoints/prefixes/version stages, reads/writes/list/deletes secrets, wraps DEKs via KMS.  
  **Key dependencies / integration points:** AWS SDK v1, `greentic-secrets-spec` traits; intended for broker/core wiring.
- **Path:** `providers/greentic-gcp-sm`  
  **Role:** Google Secret Manager backend with Cloud KMS key wrapping.  
  **Key functionality:** HTTPS-based CRUD/list operations against Secret Manager storing JSON `SecretRecord`s, KMS encrypt/decrypt via REST, env-configured project/key/token/prefix/timeouts.  
  **Key dependencies / integration points:** Uses core HTTP facade; bearer token supplied via env; integrates with broker/core.
- **Path:** `providers/greentic-azure-kv`  
  **Role:** Azure Key Vault backend and key provider.  
  **Key functionality:** Stores `SecretRecord` JSON in KV secrets, wraps/unwraps via KV keys, OAuth2 client-credentials or static bearer auth, supports proxy/tls overrides and caching of access tokens.  
  **Key dependencies / integration points:** `reqwest`, `sha2`, `tokio`; used by broker/core.
- **Path:** `providers/greentic-k8s`  
  **Role:** Kubernetes Secrets backend with versioned resources.  
  **Key functionality:** Maps Greentic scopes to namespaced Kubernetes Secrets with encoded versions/status labels, reads/writes/list/deletes via Kubernetes REST using bearer token/CAs, enforces size limits and namespace naming rules.  
  **Key dependencies / integration points:** Uses core HTTP client; integrates with broker/core.
- **Path:** `providers/greentic-vault-kv`  
  **Role:** Vault KV v2 backend and Transit key provider.  
  **Key functionality:** Persists secrets under KV path structure, serializes records to base64 JSON, wraps/unwraps DEKs via Transit, supports env-configured mounts/prefixes/HTTP client.  
  **Key dependencies / integration points:** `reqwest`; used by broker/core.
- **Path:** `conformance`  
  **Role:** Provider conformance test harness.  
  **Key functionality:** Runs suites per provider feature (dev/aws/azure/gcp/k8s/vault), performs CRUD/encryption checks, Azure preflight helper to validate creds before running.  
  **Key dependencies / integration points:** Uses provider crates behind feature flags; driven by `make e2e-*` scripts.
- **Path:** `examples/`  
  **Role:** Runnable demos for embedded core usage, broker startup, and spec helpers.  
  **Key functionality:** Fetch/put/get JSON samples, rotation, provider secret helpers, broker wiring.
- **Path:** `docs/` and `scripts/`  
  **Role:** Developer/operator docs (embedded usage, backends, policy, rotation, events/messaging, signing/API key refs) and tooling scripts (e2e compose/seed, release automation).  
  **Key functionality:** Guidance for local emulators, release flow, and telemetry setup.

## 3. Work In Progress, TODOs, and Stubs
- No explicit TODO/FIXME/XXX markers or `todo!/unimplemented!` stubs found in the repository as of this scan.

## 4. Broken, Failing, or Conflicting Areas
- `ci/local_check.sh` now passes locally (fmt, clippy, build, tests). Coverage/package and online conformance suites are skipped unless `LOCAL_CHECK_*` flags are set.
- AWS provider test auto-skips when native root certs are unavailable (prints a warning but does not fail).

## 5. Notes for Future Work
- Consider running `cargo test --workspace` (and provider-specific suites with required env/backends) to verify integrations beyond `greentic-secrets-core`.
- Keep `.env`/emulator configuration aligned with `make e2e` targets for AWS/Azure/Vault to ensure conformance coverage.
