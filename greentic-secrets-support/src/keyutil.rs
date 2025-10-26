use greentic_secrets_spec::{SecretUri, SecretsResult};

pub fn parse(key: &str) -> SecretsResult<SecretUri> {
    SecretUri::parse(key)
}
