# Secret Rotation Guide

Greentic supports continuous rotation by combining TTL metadata, cache
invalidation, and version-aware retrieval.

1. **Plan rotation frequency** – set TTL tags (for example with
   `with_ttl(record, seconds)` from `greentic-secrets-support`) to describe when
   a secret should be refreshed. The embedded runtime and broker can honour
   these tags when issuing rotation jobs.
2. **Publish the new value** – write an updated `SecretRecord` using the core
   or broker APIs. A new version number is issued automatically by each
   provider backend.
3. **Invalidate caches** – send cache invalidation messages (L2 or NATS) so
   cached plaintext is evicted quickly. The embedded cache responds to subject
   patterns like `secrets.changed.<tenant>.<team>`.
4. **Roll consumers** – applications should request the latest version after
   receiving invalidation notices. If a specific revision is required, use
   `version_of`/`versions` APIs to fetch that number explicitly.
5. **Retire old versions** – once all consumers have moved to the new
   credential, call `delete` or tombstone the previous version. Provider
   backends retain history to aid debugging while marking deleted entries.

Automate these steps via CI workflows or rotation controllers to keep secrets
fresh without manual coordination.
