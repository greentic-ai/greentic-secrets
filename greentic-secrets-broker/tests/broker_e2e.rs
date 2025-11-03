use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header::AUTHORIZATION};
#[path = "support/mod.rs"]
mod support;

use secrets_broker::models::{ListSecretsResponse, SecretResponse};
use secrets_broker::telemetry::CORRELATION_ID_HEADER;
use secrets_broker::{CorrelationId, http, nats};
use serde_json::json;
use support::auth::TestAuth;
use tower::ServiceExt;
use uuid::Uuid;

fn setup_dev_backend_env() -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let state_file = dir.path().join("dev.env");
    // SAFETY: integration test has exclusive control of the process env while running.
    unsafe {
        std::env::set_var("GREENTIC_DEV_SECRETS_PATH", state_file);
    }
    dir
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_and_nats_end_to_end() -> anyhow::Result<()> {
    let _guard = setup_dev_backend_env();
    let auth = TestAuth::configured();
    let state = secrets_broker::build_state().await?;
    let app = http::router(state.clone());

    let env = "dev";
    let tenant = {
        let id = Uuid::new_v4().simple();
        format!("tenant-{id}")
    };
    let category = "configs";
    let name = "service";
    let http_path = format!("/v1/{env}/{tenant}/{category}/{name}");
    let correlation = Uuid::new_v4().to_string();
    let admin_token = auth.token(&["admin"], &tenant, None);
    let bearer = format!("Bearer {admin_token}");

    let payload_body = json!({
        "visibility": "tenant",
        "content_type": "json",
        "encoding": "utf8",
        "description": "created via http",
        "value": "{\"token\":\"secret\"}"
    });

    let put_request = Request::builder()
        .method("PUT")
        .uri(&http_path)
        .header("content-type", "application/json")
        .header(CORRELATION_ID_HEADER, &correlation)
        .header(AUTHORIZATION, bearer.as_str())
        .body(Body::from(payload_body.to_string()))?;
    let put_response = app.clone().oneshot(put_request).await.unwrap();
    let put_status = put_response.status();
    let header = put_response
        .headers()
        .get(CORRELATION_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .expect("correlation header");
    assert_eq!(header, correlation);
    let put_body = to_bytes(put_response.into_body(), usize::MAX).await?;
    if put_status != StatusCode::CREATED {
        panic!(
            "put failed: {} {}",
            put_status,
            String::from_utf8_lossy(&put_body)
        );
    }
    let created: SecretResponse = serde_json::from_slice(&put_body)?;
    assert!(
        created.uri.ends_with(&format!("/{category}/{name}")),
        "unexpected uri: {}",
        created.uri
    );
    assert!(
        created.uri.contains(&tenant) && created.uri.contains(env),
        "scope missing from uri: {}",
        created.uri
    );

    let get_request = Request::builder()
        .method("GET")
        .uri(&http_path)
        .header(AUTHORIZATION, bearer.as_str())
        .body(Body::empty())?;
    let get_response = app.clone().oneshot(get_request).await.unwrap();
    assert_eq!(StatusCode::OK, get_response.status());
    let get_body = to_bytes(get_response.into_body(), usize::MAX).await?;
    let fetched: SecretResponse = serde_json::from_slice(&get_body)?;
    assert_eq!(fetched.value, created.value);
    assert_eq!(fetched.version, created.version);

    let subject_base = format!("secrets.get.req.{tenant}.{env}._");
    let nats_payload = serde_json::to_vec(&json!({
        "category": category,
        "name": name,
        "version": null,
        "token": admin_token.clone()
    }))?;
    let nats_response = nats::execute_get(state.clone(), &subject_base, &nats_payload).await?;
    assert_eq!(nats_response.version, created.version);
    assert_eq!(nats_response.value, created.value);

    let correlation_id = CorrelationId(Uuid::new_v4().to_string());
    let encoded = nats::serialize_payload_with_correlation(&nats_response, &correlation_id)?;
    let encoded_json: serde_json::Value = serde_json::from_slice(&encoded)?;
    assert_eq!(encoded_json["correlation_id"], correlation_id.0);

    let list_subject = format!("secrets.list.req.{tenant}.{env}._");
    let list_payload = serde_json::to_vec(&json!({
        "prefix": category,
        "token": admin_token.clone()
    }))?;
    let list_response: ListSecretsResponse =
        nats::execute_list(state.clone(), &list_subject, &list_payload).await?;
    assert!(
        list_response
            .items
            .iter()
            .any(|item| item.uri == created.uri),
        "secret missing from list response"
    );

    let delete_subject = format!("secrets.del.req.{tenant}.{env}._");
    let delete_payload = serde_json::to_vec(&json!({
        "category": category,
        "name": name,
        "token": admin_token.clone()
    }))?;
    let delete_response =
        nats::execute_delete(state.clone(), &delete_subject, &delete_payload).await?;
    assert!(delete_response.deleted);

    let missing_request = Request::builder()
        .method("GET")
        .uri(&http_path)
        .header(AUTHORIZATION, bearer.as_str())
        .body(Body::empty())?;
    let missing_get = app.oneshot(missing_request).await.unwrap();
    assert_eq!(StatusCode::NOT_FOUND, missing_get.status());

    Ok(())
}
