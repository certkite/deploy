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
    assert!(help.contains("\n  run"));
    assert!(!help.contains("\n  service"));
    for action in ["install", "uninstall"] {
        let removed = Command::new(executable)
            .args(["service", action])
            .output()
            .unwrap();
        assert_eq!(removed.status.code(), Some(2));
    }
}

#[test]
fn status_and_logs_read_the_user_state_directory() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("certkite");
    certkite_client::state::write_json(
        &state.join("identity.json"),
        &serde_json::json!({"client_id": "00000000-0000-4000-8000-000000000001"}),
    )
    .unwrap();
    let log = state.join("client.log");
    std::fs::write(
        &log,
        "{\"timestamp\":1,\"level\":\"INFO\",\"message\":\"test log\",\"id\":\"fixture\"}\n",
    )
    .unwrap();
    std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o600)).unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_certkite"));
    command.env("XDG_STATE_HOME", temp.path());
    let status = command.args(["status", "--json"]).output().unwrap();
    assert!(status.status.success(), "{status:?}");
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(
        status["client"]["client_id"],
        "00000000-0000-4000-8000-000000000001"
    );

    let logs = Command::new(env!("CARGO_BIN_EXE_certkite"))
        .env("XDG_STATE_HOME", temp.path())
        .args(["logs", "--json"])
        .output()
        .unwrap();
    assert!(logs.status.success(), "{logs:?}");
    let entry: serde_json::Value = serde_json::from_slice(&logs.stdout).unwrap();
    assert_eq!(entry["message"], "test log");
}

#[cfg(target_os = "linux")]
#[test]
fn run_handles_group_writable_umask_and_recovers_downloads_before_notify() {
    use std::{fs, os::unix::net::UnixDatagram, process::Stdio, time::Duration};

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let config = root.join("config.toml");
    fs::write(&config, "accessKey='local-fixture'\n").unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let socket = root.join("notify.sock");
    let listener = UnixDatagram::bind(&socket).unwrap();
    listener
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let state = root.join("state/certkite/startup.json");
    let data = root.join("data");
    let run_until_ready = || {
        let mut child = Command::new("sh")
            .args([
                "-c",
                "umask 0002; exec \"$@\"",
                "sh",
                env!("CARGO_BIN_EXE_certkite"),
                "run",
                "--config",
            ])
            .arg(&config)
            .env("XDG_STATE_HOME", root.join("state"))
            .env("XDG_DATA_HOME", &data)
            .env("NOTIFY_SOCKET", &socket)
            .env("HTTPS_PROXY", "http://127.0.0.1:1")
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut message = [0; 128];
        let received = listener.recv(&mut message);
        let _ = child.kill();
        let output = child.wait_with_output().unwrap();
        let count = received
            .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stderr)));
        assert!(message[..count].starts_with(b"READY=1\n"));
        let status: serde_json::Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
        assert_eq!(status["ready"], true);
    };
    run_until_ready();
    assert_eq!(
        fs::metadata(&data).unwrap().permissions().mode() & 0o777,
        0o755
    );

    let downloads = data.join("certkite/certificates/downloads");
    fs::create_dir(&downloads).unwrap();
    fs::set_permissions(&downloads, fs::Permissions::from_mode(0o711)).unwrap();
    for (name, mode) in [("private", 0o700), ("v2-shared", 0o750)] {
        let target = downloads.join(name);
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(mode)).unwrap();
        let versions = target.join("versions");
        fs::create_dir(&versions).unwrap();
        fs::set_permissions(&versions, fs::Permissions::from_mode(mode)).unwrap();
        let fingerprint = "a".repeat(64);
        let next = format!("versions/{fingerprint}");
        let previous = (mode == 0o750).then(|| format!("versions/{}", "b".repeat(64)));
        for version in std::iter::once(&next).chain(previous.as_ref()) {
            let path = target.join(version);
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        }
        std::os::unix::fs::symlink(&next, target.join("current")).unwrap();
        let journal = target.join("state.json");
        fs::write(&journal, serde_json::to_vec(&serde_json::json!({
            "task_generation": 1,
            "operations": {"task-1": {"digest": "fixture", "outcome": {"changed": true, "generation": 1, "fingerprint": fingerprint}, "committed": false}},
            "pending": {"operation_id": "task-1", "previous": previous, "next": next}
        })).unwrap()).unwrap();
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
    }
    run_until_ready();
    for name in ["private", "v2-shared"] {
        let target = downloads.join(name);
        let current = target.join("current");
        if name == "v2-shared" {
            assert_eq!(
                fs::read_link(current).unwrap(),
                std::path::PathBuf::from(format!("versions/{}", "b".repeat(64)))
            );
        } else {
            assert_eq!(
                fs::symlink_metadata(current).unwrap_err().kind(),
                std::io::ErrorKind::NotFound
            );
        }
        let journal: serde_json::Value =
            serde_json::from_slice(&fs::read(target.join("state.json")).unwrap()).unwrap();
        assert!(journal["pending"].is_null());
        assert_eq!(journal["operations"]["task-1"]["committed"], false);
    }
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
