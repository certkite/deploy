#!/bin/sh
set -eu

# Set this to the same trusted Ed25519 public key embedded in release builds.
RELEASE_PUBLIC_KEY_HEX=""
ORIGIN="https://certkite.com"

die() {
    echo "certkite installer: $*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || die "Linux is required"
case "$(uname -m)" in
    x86_64 | amd64) platform=x86_64-unknown-linux-gnu; machine=62 ;;
    aarch64 | arm64) platform=aarch64-unknown-linux-gnu; machine=183 ;;
    *) die "unsupported architecture: $(uname -m)" ;;
esac

[ "${#RELEASE_PUBLIC_KEY_HEX}" -eq 64 ] || die "release verification key is not configured"
case "$RELEASE_PUBLIC_KEY_HEX" in *[!0-9A-Fa-f]*) die "invalid release verification key" ;; esac
[ -n "${HOME:-}" ] || die "HOME is not set"
for command in curl sha256sum mktemp install stat mv chmod python3 openssl id; do
    command -v "$command" >/dev/null 2>&1 || die "$command is required"
done

temporary=$(mktemp -d "${TMPDIR:-/tmp}/certkite-install.XXXXXX")
stage=
cleanup() {
    [ -z "$stage" ] || rm -f -- "$stage"
    rm -rf -- "$temporary"
}
trap cleanup 0
trap 'exit 1' HUP INT TERM

envelope="$temporary/envelope.json"
manifest="$temporary/manifest.json"
signature="$temporary/signature"
public_key="$temporary/public-key.der"
metadata="$temporary/metadata"
binary="$temporary/certkite"

curl --fail --silent --show-error --retry 3 --proto '=https' --tlsv1.2 \
    --max-time 30 --max-filesize 65536 -H "X-Certkite-Platform: $platform" \
    "$ORIGIN/client/v1/releases/latest" -o "$envelope"
[ "$(stat -c %s "$envelope")" -le 65536 ] || die "release envelope exceeds 64 KiB"

python3 - "$envelope" "$manifest" "$signature" "$public_key" "$RELEASE_PUBLIC_KEY_HEX" <<'PY'
import json
import pathlib
import sys

envelope_path, manifest_path, signature_path, key_path, key_hex = sys.argv[1:]
try:
    envelope = json.loads(pathlib.Path(envelope_path).read_text(encoding="utf-8"))
    if set(envelope) != {"manifest", "signature"} or not isinstance(envelope["manifest"], str):
        raise ValueError("unexpected release envelope")
    signature = bytes.fromhex(envelope["signature"])
    if len(signature) != 64:
        raise ValueError("invalid signature length")
    key = bytes.fromhex(key_hex)
    if len(key) != 32:
        raise ValueError("invalid public key length")
except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
    raise SystemExit(f"invalid signed release envelope: {error}")
pathlib.Path(manifest_path).write_bytes(envelope["manifest"].encode("utf-8"))
pathlib.Path(signature_path).write_bytes(signature)
# SubjectPublicKeyInfo prefix for an Ed25519 raw public key.
pathlib.Path(key_path).write_bytes(bytes.fromhex("302a300506032b6570032100") + key)
PY

openssl pkeyutl -verify -pubin -keyform DER -inkey "$public_key" -rawin \
    -in "$manifest" -sigfile "$signature" >/dev/null 2>&1 \
    || die "release signature verification failed"

python3 - "$manifest" "$metadata" "$platform" <<'PY'
import json
import pathlib
import re
import sys
import urllib.parse

manifest_path, metadata_path, platform = sys.argv[1:]
try:
    manifest = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
    required = {"version", "platform", "url", "size", "sha256"}
    if set(manifest) != required:
        raise ValueError("unexpected manifest fields")
    if manifest["platform"] != platform:
        raise ValueError("release platform mismatch")
    if not isinstance(manifest["version"], str) or not re.fullmatch(
        r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?",
        manifest["version"],
    ):
        raise ValueError("latest release must have a stable semantic version")
    if type(manifest["size"]) is not int or not 0 < manifest["size"] <= 256 * 1024 * 1024:
        raise ValueError("invalid artifact size")
    if not isinstance(manifest["sha256"], str) or not re.fullmatch(r"[0-9a-fA-F]{64}", manifest["sha256"]):
        raise ValueError("invalid artifact digest")
    if not isinstance(manifest["url"], str) or any(ord(c) <= 32 or ord(c) == 127 for c in manifest["url"]):
        raise ValueError("invalid artifact URL")
    url = urllib.parse.urlsplit(manifest["url"])
    if (
        url.scheme != "https"
        or url.hostname != "certkite.com"
        or url.port not in (None, 443)
        or url.username is not None
        or url.password is not None
        or url.fragment
    ):
        raise ValueError("artifact must use the certkite.com HTTPS origin")
except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
    raise SystemExit(f"invalid signed release manifest: {error}")
pathlib.Path(metadata_path).write_text(
    f"{manifest['version']}\n{manifest['url']}\n{manifest['size']}\n{manifest['sha256'].lower()}\n",
    encoding="utf-8",
)
PY

{
    IFS= read -r version
    IFS= read -r artifact_url
    IFS= read -r expected_size
    IFS= read -r expected_sha256
} < "$metadata"

curl --fail --silent --show-error --retry 3 --proto '=https' --tlsv1.2 \
    --max-time 180 --max-filesize "$expected_size" "$artifact_url" -o "$binary"
[ "$(stat -c %s "$binary")" -eq "$expected_size" ] || die "artifact size mismatch"
actual_sha256=$(sha256sum "$binary")
actual_sha256=${actual_sha256%% *}
[ "$actual_sha256" = "$expected_sha256" ] || die "artifact SHA-256 mismatch"

python3 - "$binary" "$machine" <<'PY'
import pathlib
import sys

with pathlib.Path(sys.argv[1]).open("rb") as artifact:
    header = artifact.read(20)
if len(header) != 20 or header[:6] != b"\x7fELF\x02\x01":
    raise SystemExit("artifact is not a 64-bit little-endian ELF executable")
if int.from_bytes(header[18:20], "little") != int(sys.argv[2]):
    raise SystemExit("artifact architecture does not match this host")
PY
chmod 0755 "$binary"
[ "$("$binary" --version)" = "certkite $version" ] || die "artifact version does not match manifest"

install_dir="$HOME/.local/bin"
destination="$install_dir/certkite"
[ -d "$install_dir" ] || install -d -m 0755 "$install_dir"
python3 - "$install_dir" <<'PY'
import os
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
if not path.is_absolute():
    raise SystemExit("HOME must be absolute")
for ancestor in (path, *path.parents):
    metadata = ancestor.lstat()
    if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid not in (0, os.geteuid()):
        raise SystemExit(f"untrusted installation directory: {ancestor}")
    if metadata.st_mode & 0o022 and not metadata.st_mode & stat.S_ISVTX:
        raise SystemExit(f"writable installation directory: {ancestor}")
PY
owner=$(stat -c %u "$install_dir")
mode=$(stat -c %a "$install_dir")
[ "$owner" -eq "$(id -u)" ] && [ $((0$mode & 022)) -eq 0 ] \
    || die "$install_dir must belong to the current user and not be group/world-writable"
if [ -e "$destination" ] || [ -L "$destination" ]; then
    [ -f "$destination" ] && [ ! -L "$destination" ] || die "$destination must be a regular file"
    owner=$(stat -c %u "$destination")
    mode=$(stat -c %a "$destination")
    [ "$owner" -eq "$(id -u)" ] && [ $((0$mode & 022)) -eq 0 ] \
        || die "$destination has unsafe ownership or permissions"
fi
stage=$(mktemp "$install_dir/.certkite-install.XXXXXX")
install -m 0755 "$binary" "$stage"
mv -f -- "$stage" "$destination"
stage=

echo "CertKite CLI installed at $destination"
case ":${PATH:-}:" in
    *":$install_dir:"*) ;;
    *) echo "Add $install_dir to PATH before running certkite." ;;
esac
