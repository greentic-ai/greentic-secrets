use assert_cmd::Command;
use predicates::str::contains;
use tempfile::TempDir;

fn broker_cmd(tmp: &TempDir) -> Command {
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("greentic-secrets-broker");
    cmd.current_dir(tmp.path());
    cmd
}

#[test]
fn help_works() {
    let tmp = TempDir::new().unwrap();
    broker_cmd(&tmp)
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("Usage: greentic-secrets-broker"))
        .stdout(contains("--bind"))
        .stdout(contains("--nats-url"));
}

#[test]
fn env_overrides_are_accepted() {
    let tmp = TempDir::new().unwrap();
    // Just validate clap parsing + early exit; we don't start the broker in tests.
    broker_cmd(&tmp)
        .args([
            "--env",
            "stage",
            "--bind",
            "127.0.0.1:9999",
            "--nats-url",
            "nats://localhost:4222",
        ])
        .arg("--config")
        .arg(tmp.path().join("nonexistent.toml"))
        .assert()
        .failure() // config will fail to load, but flags should parse
        .stderr(contains("broker exited with error"));
}
