use axum::body::Body;
use axum::http::{header::AUTHORIZATION, Request, StatusCode};
#[path = "support/mod.rs"]
mod support;

use serde_json::json;
use serial_test::serial;
use support::auth::TestAuth;
use tower::ServiceExt;
use uuid::Uuid;

fn setup_dev_backend_env() -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let state_file = dir.path().join("dev.env");
    std::env::set_var("GREENTIC_DEV_SECRETS_PATH", state_file);
    dir
}

async fn bootstrap_state() -> (
    axum::Router,
    TestAuth,
    tempfile::TempDir,
    secrets_broker::AppState,
) {
    let guard = setup_dev_backend_env();
    let auth = TestAuth::configured();
    let state = secrets_broker::build_state().await.expect("state");
    let router = secrets_broker::http::router(state.clone());
    (router, auth, guard, state)
}

#[tokio::test]
#[serial]
async fn http_put_allowed_for_writer() {
    let (app, auth, _guard, state) = bootstrap_state().await;

    let tenant = format!("tenant-{}", Uuid::new_v4().simple());
    let path = format!("/v1/dev/{tenant}/configs/alpha");
    let token = auth.token(&["writer"], &tenant, None);
    state
        .authorizer
        .authenticate(&token)
        .await
        .expect("token should be valid");
    let request = Request::builder()
        .method("PUT")
        .uri(&path)
        .header("content-type", "application/json")
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(
            json!({
                "visibility": "tenant",
                "content_type": "json",
                "encoding": "utf8",
                "value": "{}"
            })
            .to_string(),
        ))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    if status != StatusCode::CREATED {
        panic!(
            "unexpected status: {} {}",
            status,
            String::from_utf8_lossy(&body)
        );
    }
}

#[tokio::test]
#[serial]
async fn http_put_denied_for_reader() {
    let (app, auth, _guard, state) = bootstrap_state().await;

    let tenant = format!("tenant-{}", Uuid::new_v4().simple());
    let path = format!("/v1/dev/{tenant}/configs/alpha");
    let token = auth.token(&["reader"], &tenant, None);
    state
        .authorizer
        .authenticate(&token)
        .await
        .expect("token should be valid");
    let request = Request::builder()
        .method("PUT")
        .uri(&path)
        .header("content-type", "application/json")
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(
            json!({
                "visibility": "tenant",
                "content_type": "json",
                "encoding": "utf8",
                "value": "{}"
            })
            .to_string(),
        ))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    if status != StatusCode::FORBIDDEN {
        panic!(
            "unexpected status: {} {}",
            status,
            String::from_utf8_lossy(&body)
        );
    }
}

#[tokio::test]
#[serial]
async fn http_put_missing_token() {
    let (app, _auth, _guard, _state) = bootstrap_state().await;

    let tenant = format!("tenant-{}", Uuid::new_v4().simple());
    let path = format!("/v1/dev/{tenant}/configs/alpha");
    let request = Request::builder()
        .method("PUT")
        .uri(&path)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "visibility": "tenant",
                "content_type": "json",
                "encoding": "utf8",
                "value": "{}"
            })
            .to_string(),
        ))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial]
async fn http_put_expired_token() {
    let (app, auth, _guard, _state) = bootstrap_state().await;

    let tenant = format!("tenant-{}", Uuid::new_v4().simple());
    let path = format!("/v1/dev/{tenant}/configs/alpha");
    let token = auth.expired_token(&["writer"], &tenant, None);
    let request = Request::builder()
        .method("PUT")
        .uri(&path)
        .header("content-type", "application/json")
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(
            json!({
                "visibility": "tenant",
                "content_type": "json",
                "encoding": "utf8",
                "value": "{}"
            })
            .to_string(),
        ))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
