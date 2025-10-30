use greentic_secrets_runner::{secrets_get, Bindings, SecretError, TenantBinding};

#[test]
fn global_secret_allowed_without_tenant() {
    let key = "SHARED_SENTRY_DSN";
    std::env::set_var(key, "dsn-value");

    let bindings = Bindings::default().with_global(TenantBinding::new([key]));

    let value = secrets_get(&bindings, key, None).expect("global secret should resolve");
    assert_eq!(value, "dsn-value");

    std::env::remove_var(key);
}

#[test]
fn allowed_secret_missing_from_env_returns_not_found() {
    let key = "MISSING_ENV_SECRET";
    std::env::remove_var(key);

    let bindings = Bindings::default().with_global(TenantBinding::new([key]));

    let err = secrets_get(&bindings, key, None).expect_err("secret should not exist");
    assert_eq!(err, SecretError::NotFound { key: key.into() });
    assert_eq!(err.code(), "not_found");
}
