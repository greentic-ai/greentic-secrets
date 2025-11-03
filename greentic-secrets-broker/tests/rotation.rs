#[path = "support/mod.rs"]
mod support;

use secrets_broker::rotate;
use secrets_core::types::{ContentType, Scope, Visibility};
use secrets_core::{SecretMeta, SecretUri};
use support::auth::TestAuth;

fn setup_dev_backend_env() -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let state_file = dir.path().join("dev-rotate.env");
    // SAFETY: tests manage this process-wide env var and remove tempdir at drop.
    unsafe {
        std::env::set_var("GREENTIC_DEV_SECRETS_PATH", state_file);
    }
    dir
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotation_idempotent_via_tags() -> anyhow::Result<()> {
    let _guard = setup_dev_backend_env();
    let _auth = TestAuth::configured();
    let state = secrets_broker::build_state().await?;

    let scope = Scope::new("dev", "rotation-tenant", Some("core".into()))?;
    let uri = SecretUri::new(scope.clone(), "config", "service")?;
    let mut meta = SecretMeta::new(uri.clone(), Visibility::Team, ContentType::Json);
    meta.description = Some("rotation test".into());

    {
        let mut broker = state.broker.lock().await;
        broker.put_secret(meta.clone(), br#"{"token":"initial"}"#)?;
    }

    let first = rotate::execute_rotation(
        state.clone(),
        scope.clone(),
        "config",
        "job-1".to_string(),
        "tester",
    )
    .await?;
    assert_eq!(first.rotated, 1);
    assert_eq!(first.skipped, 0);

    {
        let mut broker = state.broker.lock().await;
        let secret = broker
            .get_secret(&uri)?
            .expect("secret must exist after rotation");
        assert_eq!(
            secret
                .meta
                .tags()
                .get("rotation.last_job")
                .map(String::as_str),
            Some("job-1")
        );
    }

    let second =
        rotate::execute_rotation(state, scope, "config", "job-1".to_string(), "tester").await?;
    assert_eq!(second.rotated, 0);
    assert!(second.skipped >= 1);

    Ok(())
}
