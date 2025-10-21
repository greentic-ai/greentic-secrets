# Backend Mapping Reference

## Environment backend (`env` feature)

* URI `secrets://<env>/<tenant>/<team|_>/<category>/<name>`
* Environment variable: `GTSEC_<ENV>_<TENANT>_<TEAM>_<CATEGORY>_<NAME>`
  * Components are uppercased and non-alphanumeric characters mapped to `_`.
  * Team placeholder `_` is used when the URI omits a team.
* Value: JSON-encoded `SecretRecord` (as produced by `serde_json::to_string`).

## File backend (`file` feature)

* Root directory: `GREENTIC_SECRETS_FILE_ROOT` (default: current directory).
* Path: `<root>/<env>/<tenant>/<team|_>/<category>/<name>`.
* File contents: JSON-encoded `SecretRecord`.

## Kubernetes backend (`k8s` feature)

* Namespace: `gtsec-<env>-<tenant>[-<team>]` (DNS-1123 sanitised).
* Secret name: `<category>-<name>` (DNS-1123 sanitised).
* Data key: `payload` (base64 JSON-encoded `SecretRecord`).
* In-cluster configuration is used; respect standard `KUBECONFIG` overrides.

## AWS Secrets Manager backend (`aws` feature)

* Secret ID: `gtsec/<env>/<tenant>/<team|_>/<category>/<name>`.
* Version stage: `AWSCURRENT` by default (override via configuration later).
* Payload: stored as JSON-encoded `SecretRecord` under `SecretString`.
* Credentials and region are sourced via `aws-config`.
