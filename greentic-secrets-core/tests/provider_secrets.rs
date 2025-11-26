use greentic_types::{EnvId, TeamId, TenantCtx, TenantId};
use secrets_core::{
    BrokerSecret, SecretsCore, events_provider_secret_uri, get_events_provider_secret,
    get_messaging_adapter_secret, messaging_adapter_secret_uri, ttl_duration,
};
use serde_json::json;
use std::time::Duration;

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
async fn events_secret_round_trip() {
    let tenant = tenant_ctx_with_team();
    let core = core_for(&tenant).await;
    let uri = events_provider_secret_uri(&tenant, "nats-core").expect("uri");

    core.put_json(&uri.to_string(), &json!({ "token": "abc123" }))
        .await
        .expect("put");

    let secret = get_events_provider_secret(&core, &tenant, "nats-core")
        .await
        .expect("get");
    assert_uri_payload(&secret, &uri.to_string(), "abc123");
}

#[tokio::test]
async fn messaging_secret_round_trip() {
    let tenant = tenant_ctx_with_team();
    let core = core_for(&tenant).await;
    let uri = messaging_adapter_secret_uri(&tenant, "teams-main").expect("uri");

    core.put_json(&uri.to_string(), &json!({ "api_key": "xyz" }))
        .await
        .expect("put");

    let secret = get_messaging_adapter_secret(&core, &tenant, "teams-main")
        .await
        .expect("get");
    assert_uri_payload(&secret, &uri.to_string(), "xyz");
}

#[tokio::test]
async fn uri_uses_placeholder_when_no_team() {
    let env = EnvId::try_from("dev").expect("env id");
    let tenant = TenantId::try_from("acme").expect("tenant id");
    let ctx = TenantCtx::new(env, tenant);
    let uri = events_provider_secret_uri(&ctx, "nats-core").expect("uri");
    assert_eq!(
        uri.to_string(),
        "secrets://dev/acme/_/events/nats-core__credentials"
    );
}

#[tokio::test]
async fn missing_secret_surfaces_not_found() {
    let tenant = tenant_ctx_with_team();
    let core = core_for(&tenant).await;

    let err = get_events_provider_secret(&core, &tenant, "missing")
        .await
        .expect_err("missing secret should error");
    assert!(
        err.to_string().contains("not found"),
        "unexpected error: {err:?}"
    );
}

#[tokio::test]
async fn ttl_is_exposed_from_tags() {
    let tenant = tenant_ctx_with_team();
    let core = core_for(&tenant).await;
    let uri = events_provider_secret_uri(&tenant, "nats-core").expect("uri");

    core.put_json(&uri.to_string(), &json!({ "token": "abc123" }))
        .await
        .expect("put");
    // apply ttl tag
    let mut meta = core
        .get_secret_with_meta(&uri.to_string())
        .await
        .expect("get meta")
        .meta;
    meta.set_tag("ttl_seconds", "600");
    let secret = BrokerSecret {
        version: 1,
        meta,
        payload: br#"{"token":"abc123"}"#.to_vec(),
    };
    let ttl = ttl_duration(&secret.meta);
    assert_eq!(ttl, Some(Duration::from_secs(600)));
}

fn assert_uri_payload(secret: &BrokerSecret, expected_uri: &str, expected_value: &str) {
    assert_eq!(secret.meta.uri.to_string(), expected_uri);
    let payload: serde_json::Value = serde_json::from_slice(&secret.payload).expect("json payload");
    assert!(
        payload
            .as_object()
            .expect("object")
            .values()
            .any(|v| v == expected_value)
    );
}
