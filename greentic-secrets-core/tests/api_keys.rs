use greentic_types::{ApiKeyRef, DistributorRef, EnvId, RepoRef, TenantCtx, TenantId};
use secrets_core::{
    SecretsCore, billing_api_key_uri, distributor_api_key_uri, get_billing_provider_api_key_ref,
    get_distributor_api_key_ref, get_repo_api_key_ref, repo_api_key_uri,
};

async fn core_for(tenant: &TenantCtx) -> SecretsCore {
    let mut builder = SecretsCore::builder().tenant(tenant.tenant_id.as_ref());
    if let Some(team) = tenant.team.as_ref() {
        builder = builder.team(team.as_ref());
    }
    builder.build().await.expect("core")
}

#[tokio::test]
async fn repo_api_key_round_trip() {
    let tenant = TenantCtx::new(
        EnvId::try_from("dev").unwrap(),
        TenantId::try_from("acme").unwrap(),
    );
    let core = core_for(&tenant).await;
    let repo = RepoRef::try_from("core-repo").unwrap();
    let uri = repo_api_key_uri(&tenant, &repo).expect("uri");
    let value = ApiKeyRef::new("api-key-ref-core").unwrap();
    core.put_json(&uri.to_string(), &value).await.expect("put");

    let fetched = get_repo_api_key_ref(&core, &tenant, &repo)
        .await
        .expect("get");
    assert_eq!(fetched, value);
    assert_eq!(
        uri.to_string(),
        "secrets://dev/acme/_/store/repo__core-repo__api-key"
    );
}

#[tokio::test]
async fn distributor_api_key_round_trip() {
    let tenant = TenantCtx::new(
        EnvId::try_from("dev").unwrap(),
        TenantId::try_from("acme").unwrap(),
    );
    let core = core_for(&tenant).await;
    let dist = DistributorRef::try_from("main-distributor").unwrap();
    let uri = distributor_api_key_uri(&tenant, &dist).expect("uri");
    let value = ApiKeyRef::new("dist-key-ref").unwrap();
    core.put_json(&uri.to_string(), &value).await.expect("put");

    let fetched = get_distributor_api_key_ref(&core, &tenant, &dist)
        .await
        .expect("get");
    assert_eq!(fetched, value);
    assert_eq!(
        uri.to_string(),
        "secrets://dev/acme/_/distributor/main-distributor__api-key"
    );
}

#[tokio::test]
async fn billing_api_key_round_trip() {
    let tenant = TenantCtx::new(
        EnvId::try_from("dev").unwrap(),
        TenantId::try_from("acme").unwrap(),
    );
    let core = core_for(&tenant).await;
    let uri = billing_api_key_uri(&tenant, "stripe").expect("uri");
    let value = ApiKeyRef::new("stripe-key-ref").unwrap();
    core.put_json(&uri.to_string(), &value).await.expect("put");

    let fetched = get_billing_provider_api_key_ref(&core, &tenant, "stripe")
        .await
        .expect("get");
    assert_eq!(fetched, value);
    assert_eq!(
        uri.to_string(),
        "secrets://dev/acme/_/billing/stripe__api-key"
    );
}

#[tokio::test]
async fn api_key_isolation_between_tenants() {
    let env = EnvId::try_from("dev").unwrap();
    let tenant_a = TenantCtx::new(env.clone(), TenantId::try_from("alpha").unwrap());
    let tenant_b = TenantCtx::new(env, TenantId::try_from("beta").unwrap());
    let repo = RepoRef::try_from("core-repo").unwrap();

    let core_a = core_for(&tenant_a).await;
    let core_b = core_for(&tenant_b).await;

    let uri_a = repo_api_key_uri(&tenant_a, &repo).expect("uri");
    let value = ApiKeyRef::new("key-a").unwrap();
    core_a
        .put_json(&uri_a.to_string(), &value)
        .await
        .expect("put");

    let err = get_repo_api_key_ref(&core_b, &tenant_b, &repo)
        .await
        .expect_err("tenant b should not see tenant a key");
    assert!(err.to_string().contains("not found"));
}
