"""Exercise the hosted installer with signed local artifacts and no network."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
assert platform.system() == "Linux" and os.geteuid() != 0, "Run installer qualification as an ordinary Linux user"


def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, **kwargs)


with tempfile.TemporaryDirectory(prefix="certkite-installer-") as temporary:
    root = Path(temporary)
    commands = root / "commands"
    commands.mkdir()
    home = root / "home"
    home.mkdir()
    artifact = root / "artifact"
    # The platform's real ELF executable also exercises the --version contract.
    run("cargo", "build", "--locked", "-p", "certkite-cli", cwd=ROOT)
    shutil.copyfile(ROOT / "target/debug/certkite", artifact)
    target = "aarch64" if platform.machine() in ("aarch64", "arm64") else "x86_64"
    key = root / "key.pem"
    public = root / "key.der"
    run("openssl", "genpkey", "-algorithm", "ED25519", "-out", key)
    run("openssl", "pkey", "-in", key, "-pubout", "-outform", "DER", "-out", public)
    source = (ROOT / "install.sh").read_text().replace(
        'RELEASE_PUBLIC_KEY_HEX=""',
        f'RELEASE_PUBLIC_KEY_HEX="{public.read_bytes()[-32:].hex()}"',
    )
    installer = root / "install.sh"
    installer.write_text(source)
    version = run(ROOT / "target/debug/certkite", "--version").stdout.decode().strip().split()[1]
    manifest = {
        "version": version,
        "platform": f"{target}-unknown-linux-gnu",
        "url": "https://certkite.com/client/artifact",
        "size": artifact.stat().st_size,
        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
    }
    raw = json.dumps(manifest)
    (root / "manifest").write_text(raw)
    run("openssl", "pkeyutl", "-sign", "-inkey", key, "-rawin", "-in", root / "manifest", "-out", root / "signature")
    envelope = {"manifest": raw, "signature": (root / "signature").read_bytes().hex()}
    (root / "envelope").write_text(json.dumps(envelope))
    (commands / "curl").write_text(
        "#!/bin/sh\nset -eu\nurl=\nout=\nwhile [ $# -gt 0 ]; do\n"
        ' case "$1" in\n -o) out=$2; shift 2;;\n https:*) url=$1; shift;;\n *) shift;;\n esac\ndone\n'
        'case "$url" in\n */latest) cp "$FIXTURES/envelope" "$out";;\n'
        ' */artifact) cp "$FIXTURES/artifact" "$out";;\n *) exit 9;;\nesac\n'
    )
    # Any attempt to escalate or manage a service makes this test fail.
    for name in ("sudo", "systemctl"):
        (commands / name).write_text('#!/bin/sh\ntouch "$FIXTURES/privileged-call"\nexit 99\n')
    for path in commands.iterdir():
        path.chmod(0o755)
    env = dict(os.environ, HOME=str(home), FIXTURES=str(root), PATH=f"{commands}:{os.environ['PATH']}")
    result = run("sh", installer, env=env)
    installed = home / ".local/bin/certkite"
    assert installed.read_bytes() == artifact.read_bytes(), result
    assert not (root / "privileged-call").exists()
    before = installed.read_bytes()
    lock = installed.parent / ".certkite-update.lock"
    with lock.open("rb") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        rejected = subprocess.run(["sh", installer], env=env, capture_output=True)
        assert rejected.returncode != 0 and b"installation or update is active" in rejected.stderr
        rejected = subprocess.run([installed, "update"], env=env, capture_output=True)
        assert rejected.returncode != 0 and b"cannot acquire the CertKite installation lock" in rejected.stderr
        assert installed.read_bytes() == before

    newer = installed.with_name("newer")
    newer.write_text("#!/bin/sh\nprintf 'certkite 999999.0.0\\n'\n")
    newer.chmod(0o755)
    newer.replace(installed)
    rejected = subprocess.run(["sh", installer], env=env, capture_output=True)
    assert rejected.returncode != 0 and b"refusing to downgrade" in rejected.stderr
    assert run(installed, "--version").stdout == b"certkite 999999.0.0\n"
    shutil.copyfile(artifact, installed)
    run("sh", installer, env=env)
    assert installed.read_bytes() == before

    envelope["manifest"] = raw + " "
    (root / "envelope").write_text(json.dumps(envelope))
    rejected = subprocess.run(["sh", installer], env=env, capture_output=True)
    assert rejected.returncode != 0 and b"signature verification failed" in rejected.stderr
    assert installed.read_bytes() == before
    envelope["manifest"] = raw
    (root / "envelope").write_text(json.dumps(envelope))
    artifact.write_bytes(b"tampered")
    rejected = subprocess.run(["sh", installer], env=env, capture_output=True)
    assert rejected.returncode != 0
    assert installed.read_bytes() == before
    # A missing trust key must fail before downloading or changing an installation.
    installer.write_text((ROOT / "install.sh").read_text())
    rejected = subprocess.run(["sh", installer], env=env, capture_output=True)
    assert rejected.returncode != 0 and b"key is not configured" in rejected.stderr
    assert installed.read_bytes() == before
print("Installer: signed installation, shared update lock, downgrade and tampering checks passed")
