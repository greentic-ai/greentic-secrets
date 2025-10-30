use greentic_secrets_runner::{Bindings, Policy, TenantBinding, TenantCtx};

#[test]
fn tenant_policy_allows_team_scope() {
    let bindings = Bindings::default().with_tenant("acme", TenantBinding::new(["ALLOWED_KEY"]));

    let ctx = TenantCtx::new("prod", "acme").with_team(Some("payments"));
    let policy = Policy::from_bindings(&bindings);

    assert!(policy.is_allowed("ALLOWED_KEY", Some(&ctx)));
    assert!(!policy.is_allowed("MISSING", Some(&ctx)));
}

#[test]
fn tenant_policy_allows_user_scope() {
    let bindings = Bindings::default().with_tenant("acme", TenantBinding::new(["TOKEN"]));

    let ctx = TenantCtx::new("prod", "acme")
        .with_team(Some("support"))
        .with_user(Some("alice"));
    let policy = Policy::from_bindings(&bindings);

    assert!(policy.is_allowed("TOKEN", Some(&ctx)));

    let other = TenantCtx::new("prod", "other")
        .with_team(Some("support"))
        .with_user(Some("alice"));
    assert!(!policy.is_allowed("TOKEN", Some(&other)));
}
