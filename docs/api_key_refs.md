# API Key References for Store/Distributor/Billing

These helpers manage **references** to API keys; the actual key material is never exposed here.

## URI conventions
- Scheme: `secrets://<env>/<tenant>/<team|_>/<category>/<name>`
- Store → Repo API keys:
  - Category: `store`
  - Name: `repo__{repo_ref}__api-key`
- Distributor API keys:
  - Category: `distributor`
  - Name: `{distributor_ref}__api-key`
- Billing provider API keys:
  - Category: `billing`
  - Name: `{billing_provider_id}__api-key`

Examples:
- `secrets://prod/acme/_/store/repo__core-repo__api-key`
- `secrets://prod/acme/_/distributor/main-distributor__api-key`
- `secrets://prod/acme/_/billing/stripe__api-key`

## Helpers
```rust
use greentic_types::{EnvId, RepoRef, TenantCtx, TenantId};
use secrets_core::{
    ApiKeyRef, get_repo_api_key_ref, repo_api_key_uri, SecretsCore,
};

let ctx = TenantCtx::new(EnvId::try_from("dev")?, TenantId::try_from("acme")?);
let repo = RepoRef::try_from("core-repo")?;
let uri = repo_api_key_uri(&ctx, &repo)?;

// Store a reference (opaque ApiKeyRef newtype)
let key_ref = ApiKeyRef::from("api-key-ref-core");
core.put_json(&uri.to_string(), &key_ref).await?;

// Retrieve it later
let fetched = get_repo_api_key_ref(&core, &ctx, &repo).await?;
```

- `ApiKeyRef` is an opaque newtype; do not store raw keys.
- TTL/tags: reuse `ttl_seconds` in `SecretMeta.tags` if you need expiry metadata.
- Team segment uses `TenantCtx.team` when present, `_` otherwise.

## Audit/logging
Helper retrieval logs include tenant, optional team, category/subject, and the opaque ref id. No key material or provider internals are logged.
