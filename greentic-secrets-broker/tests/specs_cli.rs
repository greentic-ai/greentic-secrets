use anyhow::Result;
use assert_cmd::Command;
use serde_json::Value;
use tempfile::tempdir;

#[test]
fn specs_print_json_lists_known_secrets() -> Result<()> {
    let mut cmd = Command::cargo_bin("secrets")?;
    cmd.args(["specs", "print", "--format", "json"]);
    let output = cmd.output()?;

    assert!(
        output.status.success(),
        "print command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("TELEGRAM_TOKEN"));
    assert!(stdout.contains("WEATHERAPI_KEY"));

    Ok(())
}

#[test]
fn specs_check_reports_missing_components() -> Result<()> {
    let dir = tempdir()?;
    let persist_path = dir.path().join("dev.env");

    let mut cmd = Command::cargo_bin("secrets")?;
    cmd.env("GREENTIC_DEV_SECRETS_PATH", &persist_path)
        .env("GREENTIC_DEV_MASTER_KEY", "cli-test-key")
        .args([
            "specs",
            "check",
            "--tenant",
            "example-tenant",
            "--components",
            "telegram",
        ]);

    let output = cmd.output()?;
    assert_eq!(output.status.code(), Some(2));

    let stderr = String::from_utf8(output.stderr)?;
    assert!(
        stderr.contains("Missing secrets"),
        "stderr did not report missing secrets: {stderr}"
    );

    Ok(())
}

#[test]
fn specs_schema_outputs_sorted_properties() -> Result<()> {
    let mut cmd = Command::cargo_bin("secrets")?;
    cmd.args(["specs", "schema"]);
    let output = cmd.output()?;

    assert!(
        output.status.success(),
        "schema command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json: Value = serde_json::from_slice(&output.stdout)?;
    let props = json
        .get("properties")
        .and_then(Value::as_object)
        .expect("properties map");
    let keys: Vec<_> = props.keys().cloned().collect();
    assert_eq!(keys, vec!["TELEGRAM_TOKEN", "WEATHERAPI_KEY"]);

    Ok(())
}
