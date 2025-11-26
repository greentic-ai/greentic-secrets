# Events & Messaging Provider Secrets

Shared helpers expose a canonical naming scheme for event providers and messaging adapters. Secrets stay provider-agnostic and sit in the existing `secrets://<env>/<tenant>/<team|_>/<category>/<name>` shape.

## Naming convention
- **Events providers**: `category = "events"`, `name = "{provider_name}__credentials"`.
- **Messaging adapters**: `category = "messaging"`, `name = "{adapter_name}__api-key"`.
- Future suffixes follow the same pattern: `{provider_name}__endpoint`, `{adapter_name}__webhook-secret`, etc.
- Scope comes from `greentic_types::TenantCtx`:
  - `env` ← `tenant_ctx.env`
  - `tenant` ← `tenant_ctx.tenant_id`
  - `team` ← `tenant_ctx.team`/`team_id` or `_` when absent.

Examples:
- `secrets://prod/acme/_/events/nats-core__credentials`
- `secrets://dev/acme/team-a/messaging/teams-main__api-key`

## Helpers
```rust
use greentic_types::{EnvId, TenantCtx, TenantId};
use secrets_core::{
    get_events_provider_secret, get_messaging_adapter_secret, messaging_adapter_secret_uri,
    ttl_duration, ProviderSecret,
};

let ctx = TenantCtx::new(EnvId::try_from("dev")?, TenantId::try_from("acme")?);
let secret: ProviderSecret =
    get_events_provider_secret(&core, &ctx, "nats-core").await?;
let ttl = ttl_duration(&secret.meta); // Option<Duration> from ttl_seconds tag
let uri = messaging_adapter_secret_uri(&ctx, "teams-main")?;
```

- Helpers return `ProviderSecret` (alias of `BrokerSecret`), giving you payload + `SecretMeta` tags.
- `ttl_seconds` is parsed from `SecretMeta.tags` when present; no schema change is needed.
- Errors propagate `SecretsError::NotFound` unchanged for missing secrets.

## Writing secrets
Use existing storage helpers (e.g., `SecretsCore::put_json`) with the URIs produced by:
- `events_provider_secret_uri(&tenant_ctx, provider)`
- `messaging_adapter_secret_uri(&tenant_ctx, adapter)`

This keeps events/messaging credentials consistent across providers/adapters without embedding provider-specific logic here.
