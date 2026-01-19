# Provider Extension ID Audit

- Repo state: `master` @ `f7f6dd69a0c8d9f30672eb36bbd1666a009ea871`.
- Scope: confirm canonical provider extension ID usage and guardrails.

## Findings
- Pack manifests (`packs/*/pack.yaml`) declare extensions under `greentic.provider-extension.v1` with matching `kind`, version, and provider runtime pinned to `greentic:provider/schema-core@1.0.0`.
- Validation: `scripts/validate-packs.sh` enforces the canonical extension ID/kind/version and required runtime fields; `scripts/build-provider-packs.sh` invokes `scripts/validate-gtpack-extension.sh` to assert built `.gtpack` manifests carry the canonical key.
- Tests: `crates/greentic-secrets-runner/tests/pack_validation.rs` checks YAML manifests for the canonical extension and builds provider `.gtpack` bundles, decoding `manifest.cbor` via `greentic_types::decode_pack_manifest` to confirm the extension entry has the correct key/kind.
- Dependency: `greentic-types v0.4.28` is present and its `PROVIDER_EXTENSION_ID` is used in tests to avoid hardcoding the identifier.

## Conclusion
- Canonical provider extension ID `greentic.provider-extension.v1` is enforced across pack sources, build validation, and tests; legacy identifiers are no longer accepted.
