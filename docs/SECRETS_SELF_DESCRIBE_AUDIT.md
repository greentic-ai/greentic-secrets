# Greentic Secrets: Self-Describe Audit

## A) Executive summary
- greentic-secrets exposes a first-class “self-describing secrets” surface via `SecretSpec`/`SecretDescribable` and `SecretSpecRegistry` in `greentic-secrets-core/src/spec.rs` and `greentic-secrets-core/src/spec_registry.rs`.
- Consumers can render requirements to JSON Schema via `specs_to_json_schema` in `greentic-secrets-core/src/spec_schema.rs` and via the `secrets` CLI in `greentic-secrets-broker/src/bin/secrets.rs`.
- A parallel, richer requirements model exists as `SecretRequirement` (required flag, scope, format, schema, examples) in `crates/greentic-types/src/secrets.rs`, used by the `greentic-secrets` CLI to scaffold seeds.
- Seeded values are structured with `SeedDoc`/`SeedEntry` and apply/validation logic in `greentic-secrets-core/src/seed.rs` and schema docs in `docs/seed-format.md`.
- Provider packs ship explicit JSON schemas (`schema/config.schema.json`, `schema/secrets-required.schema.json`) referenced from `packs/*/gtpack.yaml` and flows, enabling UI/automation around requirements and config.
- Secrets are normalized into a canonical URI scheme (`secrets://<env>/<tenant>/<team|_>/<category>/<name>`) in `greentic-secrets-spec/src/uri.rs` and reused across helper APIs (`greentic-secrets-core/src/provider_secrets.rs`).
- Embedded access enforces tenant/team scoping in `greentic-secrets-core/src/embedded.rs`; the broker enforces tenant/team/role constraints in `greentic-secrets-broker/src/auth.rs` and routes in `greentic-secrets-broker/src/http.rs`.
- Backend selection can be automated via probes (IMDS) or explicit config in `greentic-secrets-core/src/embedded.rs` and `greentic-secrets-core/src/resolver.rs`.
- Setup tooling exists (CLI scaffold/wizard/apply/init and broker specs CLI), but is mostly file/CLI driven and not a central service.
- JSON Schema validation in seed apply is optional and feature-gated (`schema-validate`) in `greentic-secrets-core/src/seed.rs`.
- Providers still depend heavily on environment variables for runtime config; there is limited provider-side auto-discovery beyond IMDS detection (inferred from `greentic-secrets-core/src/probe.rs`).
- There is no dynamic registry of secret requirements across tenants/environments; discovery is based on static specs, pack metadata, and local tooling.
- User-level scoping exists in `crates/greentic-secrets-runner/src/tenant.rs` but is not enforced in the core/broker policy paths shown.

## B) “Self-describing” mechanisms

**Artifacts and structures**
- `SecretSpec`/`SecretDescribable` define a minimal, code-first declaration of required secrets (`greentic-secrets-core/src/spec.rs`).
- `SecretSpecRegistry` merges spec lists and can emit Markdown or JSON (`greentic-secrets-core/src/spec_registry.rs`).
- `specs_to_json_schema` converts `SecretSpec` lists into a JSON Schema object (`greentic-secrets-core/src/spec_schema.rs`).
- `SecretRequirement` (required flag, scope, format, schema, examples) is the canonical structured requirement model (`crates/greentic-types/src/secrets.rs`).
- Seed documents for initialization use `SeedDoc`/`SeedEntry` and `SeedValue` (`greentic-secrets-spec/src/requirements.rs`, `greentic-secrets-core/src/seed.rs`, `docs/seed-format.md`).
- Provider pack metadata and schemas live under `packs/*/gtpack.yaml` and `packs/*/schema/*.schema.json` (for config and secrets-required), with flow schemas referenced from `packs/*/flows/*.ygtc`.
- The provider schema WIT interface includes `describe()` and `validate_config()` for self-description/validation (`components/common/schema_core_api.rs`).

**Source of truth**
- For simple runtime checks, the source of truth is in Rust code implementing `SecretDescribable` (`greentic-secrets-core/src/spec.rs`, examples in `docs/self_described_secrets.md`).
- For pack-driven configuration, `SecretRequirement` in pack metadata (JSON/YAML or `.gtpack`) is the source of truth for the `greentic-secrets` CLI.
- For provider operational schemas, the JSON Schema files in `packs/*/schema/` are the source of truth for config/secrets requirements.

**Discovery of required/optional secrets, types, constraints**
- CLI discovery for code-based specs: `secrets` CLI prints/validates specs and schema (`greentic-secrets-broker/src/bin/secrets.rs`).
- Pack-based discovery: `greentic-secrets` CLI reads secret requirements from pack metadata (`read_pack_requirements`).
- Constraints such as required/optional, format, and JSON Schema are represented in `SecretRequirement` (`crates/greentic-types/src/secrets.rs`).
- JSON Schema validation of seeded secrets is performed when `schema-validate` is enabled (`greentic-secrets-core/src/seed.rs`).

**Naming/normalization conventions**
- Canonical URI scheme: `secrets://<env>/<tenant>/<team|_>/<category>/<name>` (`greentic-secrets-spec/src/uri.rs`, `docs/seed-format.md`).
- Team omission uses `_` as a placeholder in URIs (`greentic-secrets-spec/src/uri.rs`).
- Environment backend normalization uses `GTSEC_<ENV>_<TENANT>_<TEAM>_<CATEGORY>_<NAME>` with non-alphanumerics mapped to `_` (`greentic-secrets-core/src/backend/env.rs`).
- File backend uses `<root>/<env>/<tenant>/<team|_>/<category>/<name>` (`greentic-secrets-core/src/backend/file.rs`).
- Provider helpers embed naming patterns for events/messaging adapters (`greentic-secrets-core/src/provider_secrets.rs`).
- Provider-specific secret IDs/paths follow the same scope+category+name shape (e.g., AWS path in `providers/greentic-aws-sm/src/lib.rs`; Azure naming in `providers/greentic-azure-kv/src/lib.rs`).

## C) Setup & automation

**CLI entrypoints**
- `greentic-secrets` CLI:
  - `dev up/down`: create/remove dev store file (`DevStore`) with optional `--destroy`.
  - `ctx set/show`: persist context (env/tenant/team) to `secrets.toml` in state dir.
  - `scaffold`: generate a seed file from pack `SecretRequirement`s.
  - `wizard`: interactively fill seed values (or `--from-dotenv`), writes updated seed.
  - `apply`: apply a seed to dev store or broker HTTP endpoint (requires `--broker-url` unless `secrets.kind=dev`).
  - `init`: orchestrates `dev up` → `ctx` → `scaffold` → `wizard` → `apply`.
  - `config show/explain`: introspect resolved config.
- `secrets` broker CLI (`greentic-secrets-broker/src/bin/secrets.rs`):
  - `specs print`: render code-based specs (Markdown/JSON).
  - `specs check`: validate presence of secrets in dev backend and exit `2` if missing.
  - `specs schema`: output JSON Schema for specs.

**Automation/initialization flows**
- Seed application and validation pipeline (`greentic-secrets-core/src/seed.rs`) consumes `SeedDoc` and writes via a `SecretsStore` (dev or broker-backed).
- Seed scaffolding uses `SecretRequirement` to compute URIs and placeholders.
- Embedded runtime can auto-detect backends and defaults (`greentic-secrets-core/src/embedded.rs`, `docs/embedded.md`).

**Validation and diagnostics**
- Secret presence validation: `validate_specs_at_prefix` returns missing/present lists (`greentic-secrets-core/src/spec_validate.rs`).
- Seed apply reports `ApplyReport` with per-entry failures (`greentic-secrets-core/src/seed.rs`).
- CLI spec check exits `2` on missing secrets (`greentic-secrets-broker/src/bin/secrets.rs`).
- Missing configuration errors are surfaced via `SecretsError::Builder` for scope mismatch (`greentic-secrets-core/src/embedded.rs`) and detailed provider errors for auth/config failures (e.g., `providers/greentic-azure-kv/src/lib.rs`).

## D) Provider model

**Providers/backends**
- Local backends: in-memory (embedded), env backend, file backend (`greentic-secrets-core/src/embedded.rs`, `greentic-secrets-core/src/backend/env.rs`, `greentic-secrets-core/src/backend/file.rs`).
- Cloud providers: AWS Secrets Manager (`providers/greentic-aws-sm/src/lib.rs`), Azure Key Vault (`providers/greentic-azure-kv/src/lib.rs`), GCP Secret Manager (`providers/greentic-gcp-sm/src/lib.rs`), Kubernetes secrets (`providers/greentic-k8s/src/lib.rs`), Vault KV + Transit (`providers/greentic-vault-kv/src/lib.rs`).
- Dev provider: `.env`-style dev store with optional persistence (`providers/greentic-dev/src/lib.rs`).

**Plug-in/selection mechanics**
- Embedded core can register any `SecretsBackend` + `KeyProvider` pair manually or via `auto_detect_backends` (`greentic-secrets-core/src/embedded.rs`).
- Default resolver auto-detects environment and picks provider in order K8s → AWS → GCP → Azure → Local (`greentic-secrets-core/src/resolver.rs`, `greentic-secrets-core/src/probe.rs`).
- Broker selects backend based on config/env (`SECRETS_BACKEND`) and feature flags (`greentic-secrets-broker/src/config.rs`, `greentic-secrets-broker/src/main.rs`).

## E) Multi-tenancy boundaries

**Scope propagation and naming**
- `Scope` (env/tenant/team) is enforced at URI parse/creation time (`greentic-secrets-spec/src/types.rs`, `greentic-secrets-spec/src/uri.rs`).
- Broker routes embed env/tenant/team in URL paths and translate into `Scope` (`greentic-secrets-broker/src/http.rs`, `greentic-secrets-broker/src/path.rs`).
- Canonical URI helper APIs in `greentic-secrets-core/src/provider_secrets.rs` map `TenantCtx` to URIs.

**Enforcement (cross-tenant prevention)**
- Embedded core rejects any secret access outside the configured tenant/team (`ensure_scope_allowed` in `greentic-secrets-core/src/embedded.rs`).
- Broker authorizer rejects tokens that mismatch tenant/team or exceed cross-team roles (`greentic-secrets-broker/src/auth.rs`).
- PolicyGuard provides scope/visibility checks at the core level (`greentic-secrets-core/src/policy.rs`), but embedded runtime policy defaults to allow-all beyond tenant/team gate (`greentic-secrets-core/src/embedded.rs`).

**User/team boundaries**
- `TenantCtx` supports optional team and user identifiers (`crates/greentic-secrets-runner/src/tenant.rs`), but user-level authorization is not enforced in core/broker paths shown (inference from lack of user checks in `greentic-secrets-core/src/embedded.rs` and `greentic-secrets-broker/src/auth.rs`).

## F) Inventory of env vars

**Core/embedded/resolver/probes**
- `GREENTIC_SECRETS_TENANT` (optional; default `"default"`) read in `greentic-secrets-core/src/embedded.rs`.
- `GREENTIC_SECRETS_TEAM` (optional) read in `greentic-secrets-core/src/embedded.rs`.
- `GREENTIC_SECRETS_CACHE_TTL_SECS` (optional) read in `greentic-secrets-core/src/embedded.rs`.
- `GREENTIC_SECRETS_NATS_URL` (optional) read in `greentic-secrets-core/src/embedded.rs`.
- `GREENTIC_SECRETS_DEV` (optional; default true) read in `greentic-secrets-core/src/embedded.rs` and `greentic-secrets-core/src/resolver.rs`.
- `GREENTIC_SECRETS_BACKENDS` (optional; disables auto-detect) read in `greentic-secrets-core/src/embedded.rs`.
- `GREENTIC_SECRETS_FILE_ROOT` (optional) read in `greentic-secrets-core/src/embedded.rs` and `greentic-secrets-core/src/resolver.rs`.
- `GREENTIC_SECRETS_PROVIDER` (optional; selects provider) read in `greentic-secrets-core/src/resolver.rs`.
- `GREENTIC_SECRETS_PROBE_TIMEOUT_MS` (optional) read in `greentic-secrets-core/src/probe.rs`.
- `SECRETS_DEK_CACHE_TTL_SECS` (optional) read in `greentic-secrets-core/src/crypto/dek_cache.rs`.
- `SECRETS_ENC_ALGO` (optional) read in `greentic-secrets-core/src/crypto/envelope.rs`.
- Note (docs mismatch): `docs/embedded.md` documents `GREENTIC_SECRETS_DEFAULT_TTL`, but code reads `GREENTIC_SECRETS_CACHE_TTL_SECS` (inference based on `docs/embedded.md` and `greentic-secrets-core/src/embedded.rs`).

**Broker/runtime**
- `SECRETS_BACKEND` (optional; overrides config) read in `greentic-secrets-broker/src/config.rs` and `greentic-secrets-broker/src/main.rs`.
- `BROKER__BIND_ADDRESS` (optional) read in `greentic-secrets-broker/src/main.rs`.
- `BROKER__NATS_URL` (optional) read in `greentic-secrets-broker/src/main.rs`.
- `GREENTIC_DEV_SECRETS_PATH` (optional; enables dev backend fallback) read in `greentic-secrets-broker/src/lib.rs`.
- `AUTH_JWT_ISS` (required) read in `greentic-secrets-broker/src/auth.rs`.
- `AUTH_JWT_AUD` (required) read in `greentic-secrets-broker/src/auth.rs`.
- `AUTH_JWT_JWKS_URL` or `AUTH_JWT_ED25519_PUB` (exactly one required) read in `greentic-secrets-broker/src/auth.rs`.
- `AUTH_JWT_INTERNAL_SUBJECTS` (optional) read in `greentic-secrets-broker/src/auth.rs`.
- `AUTH_JWT_INTERNAL_TOKEN` (optional, only used when internal subjects set) read in `greentic-secrets-broker/src/auth.rs`.

**Providers (runtime)**
- AWS provider: `GREENTIC_AWS_KMS_KEY_ID` (required), `GREENTIC_AWS_SECRET_PREFIX` (optional), `GREENTIC_AWS_VERSION_STAGE` (optional), `GREENTIC_AWS_REGION` (optional), `GREENTIC_AWS_SM_ENDPOINT` (optional), `GREENTIC_AWS_KMS_ENDPOINT` (optional), `GITHUB_REPOSITORY`/`GITHUB_RUN_ID`/`GITHUB_RUN_ATTEMPT` (optional tags) in `providers/greentic-aws-sm/src/lib.rs`.
- Azure provider: `AZURE_KEYVAULT_URL`/`AZURE_KEYVAULT_URI`/`GREENTIC_AZURE_VAULT_URI` (required), `GREENTIC_AZURE_BEARER_TOKEN` or `AZURE_KEYVAULT_BEARER_TOKEN` (optional; if missing uses client credentials), `AZURE_TENANT_ID`/`AZURE_CLIENT_ID`/`AZURE_CLIENT_SECRET` (required when no static token), `GREENTIC_AZURE_KEY_NAME` (required), `GREENTIC_AZURE_KEY_ALGORITHM` (optional), `GREENTIC_AZURE_SECRET_PREFIX` (optional), `GREENTIC_AZURE_HTTP_TIMEOUT_SECS` (optional), `GREENTIC_AZURE_PROXY_URL`/`AZURE_KEYVAULT_PROXY_URL` (optional), `AZURE_KEYVAULT_INSECURE_SKIP_VERIFY` (optional; disallowed) in `providers/greentic-azure-kv/src/lib.rs` and `providers/greentic-azure-kv/src/auth.rs`.
- GCP provider: `GREENTIC_GCP_PROJECT` or `GCP_PROJECT` (required), `GREENTIC_GCP_KMS_KEY` (required), `GREENTIC_GCP_ACCESS_TOKEN` or `GOOGLE_OAUTH_ACCESS_TOKEN` (required), `GREENTIC_GCP_SECRET_PREFIX` (optional), `GREENTIC_GCP_SM_ENDPOINT` (optional), `GREENTIC_GCP_KMS_ENDPOINT` (optional), `GREENTIC_GCP_HTTP_TIMEOUT_SECS` (optional) in `providers/greentic-gcp-sm/src/lib.rs`.
- K8s provider: `K8S_API_SERVER` (required), `K8S_BEARER_TOKEN` or `K8S_BEARER_TOKEN_FILE` (required), `K8S_CA_BUNDLE` (optional), `K8S_INSECURE_SKIP_TLS` (optional; disallowed), `K8S_HTTP_TIMEOUT_SECS` (optional), `K8S_NAMESPACE_PREFIX` (optional), `K8S_SECRET_MAX_BYTES` (optional), `K8S_KEK_ALIAS*` (optional alias map) in `providers/greentic-k8s/src/lib.rs`.
- Vault provider: `VAULT_ADDR` (required), `VAULT_TOKEN` (required), `VAULT_NAMESPACE` (optional), `VAULT_KV_MOUNT` (optional), `VAULT_KV_PREFIX` (optional), `VAULT_TRANSIT_MOUNT` (optional), `VAULT_TRANSIT_KEY` (optional), `VAULT_HTTP_TIMEOUT_SECS` (optional), `VAULT_CA_BUNDLE` (optional), `VAULT_INSECURE_SKIP_TLS` (optional) in `providers/greentic-vault-kv/src/lib.rs`.
- Dev provider: `GREENTIC_DEV_SECRETS_PATH` (optional), `GREENTIC_DEV_MASTER_KEY` (optional) in `providers/greentic-dev/src/lib.rs`.

**Tests/conformance/CI (bootstrap-only)**
- `GREENTIC_INTEGRATION` (optional gate) in provider conformance tests (`providers/greentic-*-*/tests/conformance.rs`).
- `GTS_PREFIX` (optional) and `GREENTIC_REQUIRE_<PROVIDER>` (optional) in conformance runner (`conformance/src/lib.rs`).
- `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_KEYVAULT_URL`, `AZURE_KV_SCOPE`, `GREENTIC_AZURE_KEY_NAME` (required for Azure conformance) in `conformance/src/lib.rs`.
- `GCP_PROJECT_ID` or `GCP_PROJECT` (required for GCP conformance tests) in `providers/greentic-gcp-sm/tests/conformance.rs`.
- `GREENTIC_TEST_PREFIX`, `GREENTIC_TEST_CLEANUP`, `GREENTIC_TEST_KEEP` (optional) in `crates/secrets-provider-tests/src/env.rs`.
- `GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT`, `GITHUB_REPOSITORY` (optional) in `crates/secrets-provider-tests/src/env.rs`.

## G) Portability hooks

- **Secret declaration + registry**: `SecretSpec`, `SecretDescribable`, `SecretSpecRegistry` are reusable for any config/secret catalog (`greentic-secrets-core/src/spec.rs`, `greentic-secrets-core/src/spec_registry.rs`).
- **Schema rendering**: `specs_to_json_schema` is a simple, deterministic schema generator for UI/validation (`greentic-secrets-core/src/spec_schema.rs`).
- **Seed pipeline**: `SeedDoc`/`SeedEntry` and `apply_seed` encode a generic initialization flow (`greentic-secrets-spec/src/requirements.rs`, `greentic-secrets-core/src/seed.rs`).
- **Pack metadata reader**: `read_pack_requirements` + `PackMetadata` parsing provides a reusable discovery bridge between packs and config tooling.
- **Tenant-bound allowlist policy**: `Bindings` + `Policy` enforce a per-tenant env-secret allowlist (`crates/greentic-secrets-runner/src/bindings.rs`, `crates/greentic-secrets-runner/src/policy.rs`).
