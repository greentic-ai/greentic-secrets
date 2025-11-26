# Signing Key References (no signing logic)

Greentic-secrets stores opaque signing key references only; signing happens elsewhere (signing packs, runners).

## URI convention
- Scheme: `secrets://<env>/<tenant>/<team|_>/<category>/<name>`
- Category: `signing`
- Name pattern: `{purpose}__key-ref`
  - `build__key-ref`
  - `attestation__key-ref`
  - `sbom__key-ref`
  - `generic__key-ref`

Examples:
- `secrets://prod/acme/_/signing/build__key-ref`
- `secrets://prod/acme/team-alpha/signing/attestation__key-ref`

## Helpers
```rust
use greentic_types::{EnvId, SigningKeyRef, TenantCtx, TenantId};
use secrets_core::{get_signing_key_ref, signing_key_ref_uri, SigningPurpose, SecretsCore};

let ctx = TenantCtx::new(EnvId::try_from("dev")?, TenantId::try_from("acme")?);
let uri = signing_key_ref_uri(&ctx, SigningPurpose::Build)?;

// Store a reference (opaque ID from greentic-types)
let key_ref = SigningKeyRef::try_from("signing-key-ref-1")?;
core.put_json(&uri.to_string(), &key_ref).await?;

// Retrieve it later
let fetched = get_signing_key_ref(&core, &ctx, SigningPurpose::Build).await?;
```

- `SigningKeyRef` is re-used from `greentic-types` and treated as opaque.
- TTL/tags use the existing `ttl_seconds` tag convention on `SecretMeta.tags` if you choose to set it.

## Logging/audit
Retrieval logs may include tenant, optional team, purpose, and the opaque key ref ID. Never log provider specifics or key material.
