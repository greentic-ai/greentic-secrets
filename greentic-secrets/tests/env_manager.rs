use futures::executor::block_on;
use greentic_secrets::{EnvSecretsManager, SecretsManager};

#[test]
fn read_from_env() {
    const KEY: &str = "TEST_KEY";
    unsafe { std::env::set_var(KEY, "foo") };

    let manager = EnvSecretsManager;
    let bytes = block_on(manager.read(KEY)).expect("read should succeed");
    assert_eq!(bytes, b"foo".to_vec());
}
