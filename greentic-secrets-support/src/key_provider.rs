use greentic_secrets_spec::{Scope, SecretsResult};
use std::sync::Arc;

/// Trait implemented by key providers responsible for wrapping and unwrapping DEKs.
pub trait KeyProvider: Send + Sync {
    fn wrap_dek(&self, scope: &Scope, dek: &[u8]) -> SecretsResult<Vec<u8>>;
    fn unwrap_dek(&self, scope: &Scope, wrapped: &[u8]) -> SecretsResult<Vec<u8>>;
}

impl<T> KeyProvider for Arc<T>
where
    T: KeyProvider + ?Sized,
{
    fn wrap_dek(&self, scope: &Scope, dek: &[u8]) -> SecretsResult<Vec<u8>> {
        (**self).wrap_dek(scope, dek)
    }

    fn unwrap_dek(&self, scope: &Scope, wrapped: &[u8]) -> SecretsResult<Vec<u8>> {
        (**self).unwrap_dek(scope, wrapped)
    }
}

impl<T> KeyProvider for Box<T>
where
    T: KeyProvider + ?Sized,
{
    fn wrap_dek(&self, scope: &Scope, dek: &[u8]) -> SecretsResult<Vec<u8>> {
        (**self).wrap_dek(scope, dek)
    }

    fn unwrap_dek(&self, scope: &Scope, wrapped: &[u8]) -> SecretsResult<Vec<u8>> {
        (**self).unwrap_dek(scope, wrapped)
    }
}
