use crate::{SecretsError, SecretsResult};

pub trait ResultExt<T> {
    fn not_found_if(self, cond: bool, key: &str) -> SecretsResult<T>;
}

impl<T, E: std::fmt::Display> ResultExt<T> for Result<T, E> {
    fn not_found_if(self, cond: bool, key: &str) -> SecretsResult<T> {
        match self {
            Ok(value) => Ok(value),
            Err(err) => {
                if cond {
                    Err(SecretsError::NotFound { entity: key.into() })
                } else {
                    Err(SecretsError::Backend(err.to_string()))
                }
            }
        }
    }
}
