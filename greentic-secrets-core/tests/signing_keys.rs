use greentic_types::{EnvId, SigningKeyRef, TeamId, TenantCtx, TenantId};
use secrets_core::{SecretsCore, SigningPurpose, get_signing_key_ref, signing_key_ref_uri};

fn tenant_ctx_with_team() -> TenantCtx {
    let env = EnvId::try_from("dev").expect("env id");
    let tenant = TenantId::try_from("acme").expect("tenant id");
    let team = TeamId::try_from("team-a").expect("team id");
    TenantCtx::new(env, tenant).with_team(Some(team))
}

async fn core_for(tenant: &TenantCtx) -> SecretsCore {
    let mut builder = SecretsCore::builder().tenant(tenant.tenant_id.as_ref());
    if let Some(team) = tenant.team.as_ref() {
        builder = builder.team(team.as_ref());
    }
    builder.build().await.expect("core")
}

#[tokio::test]
async fn signing_key_ref_round_trip() {
    let tenant = tenant_ctx_with_team();
    let core = core_for(&tenant).await;
    let uri = signing_key_ref_uri(&tenant, SigningPurpose::Build).expect("uri");
    let value = SigningKeyRef::try_from("signing-key-ref-1").unwrap();
    core.put_json(&uri.to_string(), &value).await.expect("put");

    let key_ref = get_signing_key_ref(&core, &tenant, SigningPurpose::Build)
        .await
        .expect("get");
    assert_eq!(key_ref, value);
}

#[tokio::test]
async fn signing_key_ref_missing_returns_error() {
    let tenant = tenant_ctx_with_team();
    let core = core_for(&tenant).await;

    let err = get_signing_key_ref(&core, &tenant, SigningPurpose::Generic)
        .await
        .expect_err("should be missing");
    assert!(
        err.to_string().contains("not found"),
        "unexpected error: {err:?}"
    );
}

#[tokio::test]
async fn signing_uri_uses_team_placeholder() {
    let env = EnvId::try_from("dev").expect("env id");
    let tenant = TenantId::try_from("acme").expect("tenant id");
    let ctx = TenantCtx::new(env, tenant);
    let uri = signing_key_ref_uri(&ctx, SigningPurpose::Attestation).expect("uri");
    assert_eq!(
        uri.to_string(),
        "secrets://dev/acme/_/signing/attestation__key-ref"
    );
}

#[tokio::test]
async fn tenant_isolation_for_signing_refs() {
    let env = EnvId::try_from("dev").expect("env id");
    let tenant_a = TenantCtx::new(env.clone(), TenantId::try_from("alpha").unwrap());
    let tenant_b = TenantCtx::new(env, TenantId::try_from("beta").unwrap());

    // Separate cores scoped to each tenant.
    let core_a = SecretsCore::builder()
        .tenant(tenant_a.tenant_id.as_ref())
        .build()
        .await
        .expect("core a");
    let core_b = SecretsCore::builder()
        .tenant(tenant_b.tenant_id.as_ref())
        .build()
        .await
        .expect("core b");

    let uri_a = signing_key_ref_uri(&tenant_a, SigningPurpose::Build).expect("uri a");
    let key_ref = SigningKeyRef::try_from("key-alpha").unwrap();
    core_a
        .put_json(&uri_a.to_string(), &key_ref)
        .await
        .expect("put a");

    // Tenant B should not see tenant A's secret.
    let err = get_signing_key_ref(&core_b, &tenant_b, SigningPurpose::Build)
        .await
        .expect_err("should be missing for tenant b");
    assert!(
        err.to_string().contains("not found"),
        "unexpected error: {err:?}"
    );
}
