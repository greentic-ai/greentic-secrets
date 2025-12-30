# secrets-provider-tests

Shared conformance test harness for Greentic secrets providers. Intended for integration tests run by individual provider crates.

## Environment contract

- `GREENTIC_TEST_PREFIX` (optional): override the base prefix for all secrets. Defaults to:
  - `ci/<provider>/<repo>/<run_id>/<attempt>/...` when GitHub Actions env vars are present.
  - `local/<provider>/<timestamp>/<pid>/...` otherwise.
- `GREENTIC_TEST_CLEANUP`: whether to delete secrets after the suite (default: true; set `0`/`false` to skip).
- `GREENTIC_TEST_KEEP`: hard override to disable cleanup when set to a truthy value.

Provider-specific environment variables should be documented alongside each provider’s conformance test.

## Usage

Add a dev-dependency on `secrets-provider-tests`, gate your conformance test with `#[cfg(feature = "integration")]` and `#[ignore]`, and call `ConformanceSuite::new("provider-name", &client, Capabilities::default()).run().await`.

## Notes

- No secrets values are logged; failures include the provider name and key path only.
- Prefixes are unique per test run to keep parallel runs isolated.
- `retry_async` is provided for eventual-consistency reads.

