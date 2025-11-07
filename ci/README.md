# Local Checks

Run `ci/local_check.sh` to mirror the main CI workflows (fmt, clippy, build, test, package dry-run, coverage, provider conformance).

```bash
# offline defaults
ci/local_check.sh

# enable network-heavy checks (docker pulls, cloud providers) and fail-fast on missing tools
LOCAL_CHECK_ONLINE=1 LOCAL_CHECK_STRICT=1 ci/local_check.sh

# run coverage-heavy tarpaulin step as well
LOCAL_CHECK_COVERAGE=1 ci/local_check.sh

# include cargo package dry-runs (mirrors release workflow)
LOCAL_CHECK_PACKAGE=1 ci/local_check.sh

# show each command before it runs
LOCAL_CHECK_VERBOSE=1 ci/local_check.sh
```

Key toggles:
- `LOCAL_CHECK_ONLINE=1` enables KinD/Vault provisioning plus AWS/Azure/GCP live conformance.
- `LOCAL_CHECK_COVERAGE=1` runs the tarpaulin coverage workflow (otherwise skipped because it’s slow/heavy).
- `LOCAL_CHECK_PACKAGE=1` (or legacy `LOCAL_CHECKPACKAGE=1`) runs `cargo package --offline` dry-runs for every publishable crate (otherwise skipped to avoid false positives when local versions aren’t on crates.io yet).
- `LOCAL_CHECK_STRICT=1` treats missing tooling/env vars as fatal and runs every optional check.
- `LOCAL_CHECK_VERBOSE=1` turns on shell tracing (`set -x`).

A pre-push hook is installed automatically (if absent) and simply executes `ci/local_check.sh` so every push matches CI expectations.
