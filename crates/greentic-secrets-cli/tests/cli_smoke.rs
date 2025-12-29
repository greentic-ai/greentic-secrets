use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn cli_cmd(tmp: &TempDir) -> Command {
    let root = tmp.path().join("greentic-root");
    let state = root.join("state");
    fs::create_dir_all(&state).expect("state dir");
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("greentic-secrets-cli");
    cmd.current_dir(tmp.path())
        .arg("--greentic-root")
        .arg(root)
        .arg("--state-dir")
        .arg(state);
    cmd
}

#[test]
fn help_works() {
    let tmp = TempDir::new().unwrap();
    cli_cmd(&tmp)
        .arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains("Greentic secrets CLI"));
}

#[test]
fn config_show_defaults() {
    let tmp = TempDir::new().unwrap();
    cli_cmd(&tmp)
        .args(["config", "show"])
        .assert()
        .success()
        .stdout(predicates::str::contains("schema_version"));
}

#[test]
fn ctx_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let mut set = cli_cmd(&tmp);
    set.args([
        "ctx", "set", "--env", "dev", "--tenant", "tenant-a", "--team", "team-a",
    ])
    .assert()
    .success();

    let mut show = cli_cmd(&tmp);
    let output = show
        .args(["ctx", "show"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8_lossy(&output);
    assert!(text.contains("env=dev"));
    assert!(text.contains("tenant=tenant-a"));
    assert!(text.contains("team=team-a"));
}

#[test]
fn dev_store_up_and_down() {
    let tmp = TempDir::new().unwrap();
    let store_path = tmp.path().join("dev-store.db");

    cli_cmd(&tmp)
        .args(["dev", "up", "--store-path", store_path.to_str().unwrap()])
        .assert()
        .success();
    assert!(store_path.exists(), "dev store should be created");

    cli_cmd(&tmp)
        .args([
            "dev",
            "down",
            "--destroy",
            "--store-path",
            store_path.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert!(
        !store_path.exists(),
        "dev store should be removed with --destroy"
    );
}
