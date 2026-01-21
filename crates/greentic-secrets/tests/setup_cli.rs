use predicates::prelude::*;
use std::fs;
use std::path::PathBuf;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[test]
fn setup_generates_scaffold_without_secrets_file() -> Result<()> {
    let pack_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/packs/fixture-provider");
    let out_dir = tempfile::tempdir()?;
    let out_path = out_dir.path().join("setup");

    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("greentic-secrets");
    cmd.args([
        "setup",
        "--pack",
        pack_path.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
    ])
    .write_stdin("dev\n".to_owned() + "us-east-1\n" + "splunk\n" + "audit-ref\n" + "\n")
    .assert()
    .success();

    let main_tf = out_path.join("main.tf");
    let variables_tf = out_path.join("variables.tf");
    let outputs_tf = out_path.join("outputs.tf");
    let readme = out_path.join("README.generated.md");
    let tfvars = out_path.join("terraform.tfvars.json");
    let secrets_tfvars = out_path.join("secrets.auto.tfvars.json");
    let install = out_path.join("provider-install.json");

    assert!(main_tf.exists());
    assert!(variables_tf.exists());
    assert!(outputs_tf.exists());
    assert!(readme.exists());
    assert!(tfvars.exists());
    assert!(!secrets_tfvars.exists());
    assert!(install.exists());

    let readme_contents = fs::read_to_string(&readme)?;
    assert!(readme_contents.contains("tofu init"));

    let tfvars_contents = fs::read_to_string(&tfvars)?;
    let install_contents = fs::read_to_string(&install)?;
    assert!(!readme_contents.contains("SENTINEL_SECRET"));
    assert!(!tfvars_contents.contains("SENTINEL_SECRET"));
    assert!(!install_contents.contains("SENTINEL_SECRET"));

    Ok(())
}

#[test]
fn setup_help_mentions_setup() -> Result<()> {
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("greentic-secrets");
    cmd.args(["--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("setup"));
    Ok(())
}
