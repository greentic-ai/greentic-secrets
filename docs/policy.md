# Policy

The embedded `SecretsCore` now enforces tenant scoping: every runtime is bound
to the tenant configured on the builder (and, when provided, a specific team).
Requests that target a different tenant or team are rejected with a builder
error before any backend calls are issued. This deny-by-default stance mirrors
the broker’s behaviour for cross-tenant access. Additional policy surfaces
remain allow-all today; future iterations will extend the embedded policy to
cover category- and attribute-based rules without requiring the HTTP broker.
