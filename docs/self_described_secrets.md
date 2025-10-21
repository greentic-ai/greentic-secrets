# Self-Described Secrets

`SecretSpec` and `SecretDescribable` allow crates to publish the secrets they
need without coupling to a specific runtime. This makes it easy to aggregate
requirements, drive tooling/UX, and validate configuration at startup.

## Declaring specs

```rust
use greentic_secrets_core::{SecretDescribable, SecretSpec};

pub struct TelegramSecrets;

impl SecretDescribable for TelegramSecrets {
    fn secret_specs() -> &'static [SecretSpec] {
        &[SecretSpec {
            name: "TELEGRAM_TOKEN",
            description: Some("Bot token from @BotFather (format: 1234567890:AA...)")
        }]
    }
}
```

The stable `name` maps to `configs/<NAME>` under the tenant prefix (e.g.
`secrets://dev/example/_/configs/TELEGRAM_TOKEN`).

## Aggregating specs

```rust
use greentic_secrets_core::{SecretSpecRegistry, SecretDescribable};

let mut registry = SecretSpecRegistry::new();
registry.extend_with(TelegramSecrets::secret_specs());
println!("{}", registry.to_markdown_table());
```

`SecretSpecRegistry` deduplicates by secret name and prefers longer human hints
when merging.

## Validating at runtime

```rust
use greentic_secrets_core::SecretsCore;

let core = SecretsCore::builder().tenant("example").build().await?;
let result = core
    .validate_specs_at_prefix("secrets://dev/example/_/", TelegramSecrets::secret_specs())
    .await?;
if !result.missing.is_empty() {
    eprintln!("Missing secrets: {:?}", result.missing);
}
```

This calls `get_bytes` for each secret and categorises the keys that exist.

## Mapping convention

Runtime lookups use `configs/<NAME>` under the tenant/team prefix. Plugins
should keep their spec names stable so that operators can provision secrets
consistently across environments.

## CLI walkthrough

The repository ships a small operational CLI in `secrets-broker` that consumes
these specs:

```bash
cargo run -p secrets-broker --bin secrets -- specs print --format md
cargo run -p secrets-broker --bin secrets -- specs print --format json
```

Add `--components telegram,weather` to limit the output to specific plugins.
The checker subcommand validates secrets against the development backend:

```bash
cargo run -p secrets-broker --bin secrets -- specs check \
  --tenant example-tenant \
  --team _ \
  --components telegram,weather
```

The command exits with code `0` when every secret is present, or `2` if anything
is missing. Point it at a different backing file by exporting
`GREENTIC_DEV_SECRETS_PATH=/path/to/.dev.secrets.env`.

Running the schema export produces JSON suitable for UI form generation:

```bash
cargo run -p secrets-broker --bin secrets -- specs schema --pretty
```

Example output:

```json
{
  "type": "object",
  "properties": {
    "TELEGRAM_TOKEN": {
      "type": "string",
      "description": "Bot token from @BotFather (format: 1234567890:AA...)"
    },
    "WEATHERAPI_KEY": {
      "type": "string",
      "description": "API key from weatherapi.com dashboard."
    }
  }
}
```

## Plugin quick reference

```rust
use greentic_secrets_core::{SecretDescribable, SecretSpec};

pub struct TelegramSecrets;

impl SecretDescribable for TelegramSecrets {
    fn secret_specs() -> &'static [SecretSpec] {
        &[
            SecretSpec {
                name: "TELEGRAM_TOKEN",
                description: Some("Bot token from @BotFather (format: 1234567890:AA...)"),
            },
        ]
    }
}
```

## Runtime validation snippet

```rust,no_run
use greentic_secrets_core::{SecretDescribable, SecretSpecRegistry, SecretsCore};

let core = SecretsCore::builder().build().await?;
let mut registry = SecretSpecRegistry::new();
registry.extend_with(TelegramSecrets::secret_specs());

let base = format!(
    "secrets://{}/{}/{}/",
    std::env::var("ENV").unwrap_or_else(|_| "dev".into()),
    std::env::var("TENANT").unwrap_or_else(|_| "example-tenant".into()),
    std::env::var("TEAM").unwrap_or_else(|_| "_".into()),
);
let result = core
    .validate_specs_at_prefix(&base, TelegramSecrets::secret_specs())
    .await?;
if !result.missing.is_empty() {
    anyhow::bail!("Missing required secrets: {:?}", result.missing);
}
```
