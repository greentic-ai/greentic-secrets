# Security Considerations

The Greentic secrets workspace relies on envelope encryption: providers keep
only wrapped data-encryption keys (DEKs), while customer-managed key providers
issue and rotate the root keys used to wrap DEKs. When a secret is stored, the
runtime generates a fresh DEK, encrypts it with the configured key provider,
and stores the encrypted payload alongside minimal metadata. Reading a secret
unwraps the DEK, decrypts the payload, and validates integrity before returning
the value.

Threat model highlights:

- **Data at rest** – secrets are stored as encrypted envelopes. Without access
  to both the wrapped DEK and key provider, plaintext cannot be recovered.
- **Transport** – provider integrations should use TLS-secured SDKs or APIs.
  The core and SDK crates avoid transmitting plaintext secrets over insecure
  channels.
- **Key isolation** – backends never persist unwrapped DEKs. Provider-specific
  key sources (KMS, HSM, etc.) should enforce IAM policies to scope access.
- **Cache invalidation** – when using the embedded cache, prefer short TTLs and
  trigger invalidations when rotating secrets to limit exposure.

Audit and rotate provider credentials regularly, and set the
`CARGO_REGISTRY_TOKEN` secret in CI to ensure automated releases pull vetted
artifacts only after the pipeline succeeds.
