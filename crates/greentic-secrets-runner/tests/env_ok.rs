use greentic_secrets_runner::{Bindings, TenantBinding, TenantCtx, secrets_get};

#[test]
fn env_secret_allowed() {
    let key = "TELEGRAM_BOT_TOKEN";
    // SAFETY: tests set known UTF-8 values before reading and clear them afterwards.
    unsafe {
        std::env::set_var(key, "allowed-value");
    }

    let bindings = Bindings::default().with_tenant("tenant-a", TenantBinding::new([key]));
    let tenant = TenantCtx::new("prod", "tenant-a");

    let value = secrets_get(&bindings, key, Some(&tenant)).expect("secret should resolve");
    assert_eq!(value, "allowed-value");

    // SAFETY: we control the env key and ensure no other thread relies on it.
    unsafe {
        std::env::remove_var(key);
    }
}
