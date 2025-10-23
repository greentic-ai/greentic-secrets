use crate::errors::Result;
use crate::types::Scope;
use std::sync::Arc;

/// Provides wrapping and unwrapping of data-encryption keys (DEKs).
pub trait KeyProvider: Send + Sync {
    /// Wrap the provided plaintext DEK for the given scope.
    fn wrap_dek(&self, scope: &Scope, dek: &[u8]) -> Result<Vec<u8>>;

    /// Unwrap a previously wrapped DEK for the given scope.
    fn unwrap_dek(&self, scope: &Scope, wrapped: &[u8]) -> Result<Vec<u8>>;
}

impl<T> KeyProvider for Arc<T>
where
    T: KeyProvider + ?Sized,
{
    fn wrap_dek(&self, scope: &Scope, dek: &[u8]) -> Result<Vec<u8>> {
        (**self).wrap_dek(scope, dek)
    }

    fn unwrap_dek(&self, scope: &Scope, wrapped: &[u8]) -> Result<Vec<u8>> {
        (**self).unwrap_dek(scope, wrapped)
    }
}

impl<T> KeyProvider for Box<T>
where
    T: KeyProvider + ?Sized,
{
    fn wrap_dek(&self, scope: &Scope, dek: &[u8]) -> Result<Vec<u8>> {
        (**self).wrap_dek(scope, dek)
    }

    fn unwrap_dek(&self, scope: &Scope, wrapped: &[u8]) -> Result<Vec<u8>> {
        (**self).unwrap_dek(scope, wrapped)
    }
}
