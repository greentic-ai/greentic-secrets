# greentic-secrets

Umbrella crate that re-exports the Greentic secrets specification, core runtime,
support helpers, and optional provider integrations for ergonomic downstream use.

## Env provider (dev/test only)

The `env` feature brings along `EnvSecretsManager`, a read-only secrets manager
that reads values directly from `std::env` and re-exports the shared
`greentic-secrets-api` traits such as `SecretsManager`, `SecretError`, and
`Result`. Write/delete operations always emit a `SecretError::Permission`
because the environment cannot be mutated from within the runner. Use this
feature for rapid local development or unit tests where the runner needs
something to delegate to, but add full-featured production backends in this
workspace's `providers/` directory (or via additional crates) before deploying.
