# greentic-config-types

Pure configuration schema for Greentic hosts. This crate only defines
serde-friendly types (no IO, no environment parsing) so services, CLIs,
and tools can share a single config contract without duplicating
structures or handling secrets inline.

- Canonical `GreenticConfig` root with environment, paths, runtime,
  telemetry, network, secrets backend reference, and optional dev
  defaults.
- Uses `greentic-types` identifiers (`EnvId`, `DeploymentCtx`,
  `ConnectionKind`) for environment context.
- No secret material: backend fields describe the selected backend and
  reference metadata only.
- Includes provenance helpers (`ConfigSource`, `ProvenancePath`) for
  higher-level loaders to track where values came from.
