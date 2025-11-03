use secrets_core::embedded::SecretsCore;
use secrets_core::embedded::SecretsError;

#[tokio::test]
async fn denies_cross_tenant_access() {
    // SAFETY: tests toggle the dev flag globally before constructing the runtime.
    unsafe {
        std::env::set_var("GREENTIC_SECRETS_DEV", "1");
    }
    let core = SecretsCore::builder()
        .tenant("primary")
        .build()
        .await
        .unwrap();

    let err = core
        .get_bytes("secrets://dev/other/_/configs/token")
        .await
        .expect_err("cross-tenant access should be denied");
    assert!(matches!(err, SecretsError::Builder(_)));

    let list_err = core
        .list("secrets://dev/other/_/configs")
        .await
        .expect_err("cross-tenant listing should be denied");
    assert!(matches!(list_err, SecretsError::Builder(_)));
}

#[tokio::test]
async fn denies_cross_team_access_for_team_scoped_runtime() {
    unsafe {
        std::env::set_var("GREENTIC_SECRETS_DEV", "1");
    }
    let core = SecretsCore::builder()
        .tenant("primary")
        .team("payments")
        .build()
        .await
        .unwrap();

    let err = core
        .get_bytes("secrets://dev/primary/support/configs/token")
        .await
        .expect_err("cross-team access should be denied when runtime is team scoped");
    assert!(matches!(err, SecretsError::Builder(_)));
}
