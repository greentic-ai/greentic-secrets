use greentic_secrets_runner::{Bindings, TenantBinding, TenantCtx, secrets_get};

#[test]
fn env_secret_denied_when_missing_from_allowlist() {
    let bindings = Bindings::default().with_tenant("tenant-b", TenantBinding::new(["OTHER_KEY"]));
    let tenant = TenantCtx::new("prod", "tenant-b");

    let err = secrets_get(&bindings, "UNKNOWN_SECRET", Some(&tenant))
        .expect_err("secret should be denied");

    assert_eq!(err.code(), "denied");
}
