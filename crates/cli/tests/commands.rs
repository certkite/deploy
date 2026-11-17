use std::{os::unix::fs::PermissionsExt, process::Command};

#[test]
fn executable_help_and_version_match_distribution_contract() {
    let executable = env!("CARGO_BIN_EXE_certkite");
    let output = Command::new(executable).arg("--version").output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        concat!("certkite ", env!("CARGO_PKG_VERSION"))
    );
    let help = Command::new(executable).arg("--help").output().unwrap();
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("service"));
    assert!(!help.contains("\n  run"));
    let removed = Command::new(executable).arg("run").output().unwrap();
    assert_eq!(removed.status.code(), Some(2));
}

#[test]
fn invalid_private_config_returns_json_without_disclosing_credentials() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("client.toml");
    std::fs::write(
        &path,
        "accessKey='fixture-private-value'\nunsupported=true\n",
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_certkite"))
        .arg("--config")
        .arg(path)
        .args(["doctor", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stdout.contains("fixture-private-value"));
    assert!(!stderr.contains("fixture-private-value"));
    let error: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(error["code"], "configuration_invalid");
}

#[test]
fn installer_rejects_missing_arguments_and_invalid_digest_without_side_effects() {
    let script =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/install.sh");
    let missing = Command::new("sh").arg(&script).output().unwrap();
    assert_eq!(missing.status.code(), Some(2));
    let malformed = Command::new("sh")
        .arg(script)
        .args(["--binary", "/nonexistent", "--sha256", "invalid"])
        .output()
        .unwrap();
    assert_eq!(malformed.status.code(), Some(2));
}
