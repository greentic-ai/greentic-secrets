use greentic_secrets_runner::{Bindings, SecretError, TenantBinding, secrets_get};

#[test]
fn global_secret_allowed_without_tenant() {
    let key = "SHARED_SENTRY_DSN";
    // SAFETY: tests own this key and clear it before finishing.
    unsafe {
        std::env::set_var(key, "dsn-value");
    }

    let bindings = Bindings::default().with_global(TenantBinding::new([key]));

    let value = secrets_get(&bindings, key, None).expect("global secret should resolve");
    assert_eq!(value, "dsn-value");

    // SAFETY: see note above; we restore the environment after the assertion.
    unsafe {
        std::env::remove_var(key);
    }
}

#[test]
fn allowed_secret_missing_from_env_returns_not_found() {
    let key = "MISSING_ENV_SECRET";
    // SAFETY: fixture guarantees exclusive access to the test environment key.
    unsafe {
        std::env::remove_var(key);
    }

    let bindings = Bindings::default().with_global(TenantBinding::new([key]));

    let err = secrets_get(&bindings, key, None).expect_err("secret should not exist");
    assert_eq!(err, SecretError::NotFound { key: key.into() });
    assert_eq!(err.code(), "not_found");
}
