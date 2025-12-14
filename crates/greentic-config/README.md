# greentic-config

Enterprise configuration resolver for Greentic hosts. Combines defaults,
user config (`~/.config/greentic/config.toml`), project config
(`.greentic/config.toml` or `--config` override), environment variables
(`GREENTIC_*`), and CLI overrides into a single `GreenticConfig` with
per-field provenance and validation warnings.

Features:
- Precedence: CLI > env > project > user > defaults.
- Provenance tracking for every resolved field.
- Optional explanations (`ExplainReport`) for human or JSON output.
- Deterministic path handling (absolute paths under project root by
  default).
- Lightweight validation (offline vs remote endpoints, insecure TLS
  outside dev, pathological timeouts).

This crate performs no secrets handling and leaves service-specific IO
to consumers.
