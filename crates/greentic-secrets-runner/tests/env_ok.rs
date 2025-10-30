use greentic_secrets_runner::{secrets_get, Bindings, TenantBinding, TenantCtx};

#[test]
fn env_secret_allowed() {
    let key = "TELEGRAM_BOT_TOKEN";
    std::env::set_var(key, "allowed-value");

    let bindings = Bindings::default().with_tenant("tenant-a", TenantBinding::new([key]));
    let tenant = TenantCtx::new("prod", "tenant-a");

    let value = secrets_get(&bindings, key, Some(&tenant)).expect("secret should resolve");
    assert_eq!(value, "allowed-value");

    std::env::remove_var(key);
}
