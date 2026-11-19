"""Verify upgrade compatibility for an existing system service on a disposable Linux VM."""
import hashlib
import json
import os
import platform
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]
STATE = Path("/var/lib/certkite-client")
BINARY = Path("/usr/local/bin/certkite")


def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs)


def stage(worker, candidate, version, previous, succeeds):
    job_id = str(uuid.uuid4())
    directory = STATE / f"update-{job_id}"
    directory.mkdir(mode=0o700)
    shutil.copy2(candidate, directory / "candidate")
    shutil.copy2(worker, directory / "worker")
    path = directory / "job.json"
    path.write_text(json.dumps({
        "id": job_id, "path": str(path), "status": "queued", "error": None,
        "manifest": {
            "version": version, "platform": "x86_64-unknown-linux-gnu",
            "url": "https://certkite.com/client/fixture", "size": candidate.stat().st_size,
            "sha256": hashlib.sha256(candidate.read_bytes()).hexdigest(),
        },
        "config": "/etc/certkite-client/config.toml", "previous_version": previous,
        "phase": "staged",
    }))
    path.chmod(0o600)
    (STATE / "update-pending").write_text(str(path))
    (STATE / "update-pending").chmod(0o600)
    result = subprocess.run([
        "systemd-run", "--quiet", "--wait", "--collect", "--service-type=oneshot",
        f"--unit=certkite-test-update-{job_id}", str(directory / "worker"),
        "__update-worker", "--job", str(path),
    ], capture_output=True, text=True, timeout=180)
    job = json.loads(path.read_text())
    assert (result.returncode == 0) == succeeds, (job, result.stderr)
    assert job["status"] == ("succeeded" if succeeds else "failed"), job
    assert not (STATE / "update-pending").exists()
    expected = version if succeeds else previous
    assert run(BINARY, "--version").stdout.strip() == f"certkite {expected}"
    startup = json.loads((STATE / "startup.json").read_text())
    pid = run("systemctl", "show", "certkite", "--property=MainPID", "--value").stdout.strip()
    assert startup["pid"] == int(pid) and startup["ready"] and startup["version"] == expected
    assert Path(f"/proc/{pid}/exe").stat().st_ino == BINARY.stat().st_ino
    if not succeeds:
        assert BINARY.read_bytes() == (directory / "backup").read_bytes()


assert platform.system() == "Linux" and os.geteuid() == 0
assert os.environ.get("CERTKITE_DISPOSABLE_VM") == "1", "Run only on a disposable VM"
assert not BINARY.exists() and not STATE.exists(), "Use a clean, disposable VM"
run("systemctl", "start", "nginx")
run("install", "-m", "0755", ROOT / "target/debug/certkite", BINARY)
config = Path("/etc/certkite-client/config.toml")
config.parent.mkdir(mode=0o700)
config.write_text('accessKey = "integration-fixture"\n')
config.chmod(0o600)
Path("/etc/nginx/sites-enabled/default").unlink(missing_ok=True)
Path("/etc/nginx/conf.d/certkite-test.conf").write_text(
    "server { listen 8080; server_name integration.example; }\n"
)
run("systemctl", "reload", "nginx")
certificates = Path("/var/lib/certkite-certificates")
certificates.mkdir(mode=0o711)
unit = Path("/etc/systemd/system/certkite.service")
assert not unit.exists()
unit.write_text(f"""[Unit]
Description=CertKite system service compatibility fixture

[Service]
Type=notify
User=root
Group=root
ExecStart={BINARY} --config {config} __daemon
Restart=on-failure
StateDirectory=certkite-client
StateDirectoryMode=0700
RuntimeDirectory=certkite-client
RuntimeDirectoryMode=0700
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=read-only
ProtectSystem=strict
ReadWritePaths={STATE} /run/certkite-client {certificates} /etc/nginx/conf.d
""")
run("systemctl", "daemon-reload")
run("systemctl", "start", "certkite")
pid = run("systemctl", "show", "certkite", "--property=MainPID", "--value").stdout.strip()
probe = subprocess.run([
    "nsenter", "-t", pid, "-m", "--", "touch", "/usr/local/bin/certkite-write-probe"
], capture_output=True)
assert probe.returncode != 0 and b"Read-only file system" in probe.stderr, probe.stderr

# Synthetic release binaries speak the daemon startup contract. The actual Rust
# worker performs stop/replace/notify/inode verification and rollback against systemd.
fixture = r'''
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("certkite %s\n", VERSION); return 0;
    }
    if (FAIL_START) return 42;
    const char *address = getenv("NOTIFY_SOCKET");
    if (!address) return 43;
    FILE *file = fopen("/var/lib/certkite-client/startup.json", "w");
    if (!file) return 44;
    fprintf(file, "{\"pid\":%d,\"version\":\"%s\",\"build_id\":\"fixture\","
        "\"started_at\":%ld,\"ready\":true}", getpid(), VERSION, time(NULL));
    if (fclose(file)) return 45;
    struct sockaddr_un target = {.sun_family = AF_UNIX};
    if (strlen(address) >= sizeof target.sun_path) return 46;
    strcpy(target.sun_path, address);
    socklen_t length = sizeof(sa_family_t) + strlen(address) + 1;
    if (address[0] == '@') { target.sun_path[0] = 0; --length; }
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0 || sendto(fd, "READY=1", 7, 0, (struct sockaddr*)&target, length) != 7) return 47;
    close(fd);
    for (;;) pause();
}
'''
with tempfile.TemporaryDirectory(prefix="certkite-systemd-", dir="/opt") as temporary:
    directory = Path(temporary)
    worker = directory / "worker"
    shutil.copy2(BINARY, worker)
    source = directory / "fixture.c"
    source.write_text(fixture)
    for version, fail in (("0.1.1", 0), ("0.1.2", 1)):
        candidate = directory / version
        run("cc", f'-DVERSION="{version}"', f"-DFAIL_START={fail}", source, "-o", candidate)
        stage(worker, candidate, version, "0.1.0" if not fail else "0.1.1", not fail)
    run("systemctl", "stop", "certkite")
print("Linux: existing service sandbox, notify startup, update and rollback passed")
