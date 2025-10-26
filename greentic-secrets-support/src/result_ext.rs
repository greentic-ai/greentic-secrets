use greentic_secrets_spec::{SecretsError, SecretsResult};

pub trait ResultExt<T> {
    fn not_found_if(self, cond: bool, key: &str) -> SecretsResult<T>;
}
impl<T, E: std::fmt::Display> ResultExt<T> for Result<T, E> {
    fn not_found_if(self, cond: bool, key: &str) -> SecretsResult<T> {
        match self {
            Ok(v) => Ok(v),
            Err(e) => {
                if cond {
                    Err(SecretsError::NotFound { entity: key.into() })
                } else {
                    Err(SecretsError::Backend(e.to_string()))
                }
            }
        }
    }
}
