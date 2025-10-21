# Policy

The embedded `SecretsCore` currently enforces an **allow-all** policy.
All requests made through the runtime API are permitted once the caller has
instantiated a `SecretsCore` instance. Future iterations will introduce
prefix- and attribute-based controls so that runtimes can restrict access to a
subset of secrets without standing up the HTTP broker.
