#!/bin/sh
# Install an independently verified local artifact; credentials never enter argv.
set -eu

usage() {
    echo "Usage: $0 --binary PATH --sha256 TRUSTED_DIGEST" >&2
    exit 2
}

binary=
digest=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --binary) [ "$#" -ge 2 ] || usage; binary=$2; shift 2 ;;
        --sha256) [ "$#" -ge 2 ] || usage; digest=$2; shift 2 ;;
        *) usage ;;
    esac
done
[ -n "$binary" ] && [ -n "$digest" ] || usage
[ "${#digest}" -eq 64 ] || usage
case "$digest" in *[!0-9a-fA-F]*) usage ;; esac
[ "$(uname -s)" = Linux ] || { echo "Linux is required" >&2; exit 1; }
[ -f "$binary" ] && [ ! -L "$binary" ] || { echo "Binary must be a regular file" >&2; exit 1; }

die() { echo "$*" >&2; exit 1; }

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

# Hash the staged copy that will actually be installed.
stage=$(mktemp "$install_dir/.certkite-install.XXXXXX")
trap 'rm -f -- "$stage"' EXIT
trap 'exit 1' HUP INT TERM
install -m 0755 -- "$binary" "$stage"
actual=$(sha256sum -- "$stage")
actual=${actual%% *}
expected=$(printf '%s' "$digest" | tr 'A-F' 'a-f')
[ "$actual" = "$expected" ] || die "SHA-256 verification failed"
# Create the destination atomically or accept an already identical installation.
if ! ln -T -- "$stage" "$destination" 2>/dev/null; then
    [ -f "$destination" ] && [ ! -L "$destination" ] || die "Unsafe binary at $destination"
    owner=$(stat -c %u "$destination")
    mode=$(stat -c %a "$destination")
    if [ "$owner" -ne "$(id -u)" ] || [ $((0$mode & 022)) -ne 0 ] \
        || ! cmp -s -- "$stage" "$destination"; then
        die "A different or unsafe binary is installed; use certkite update"
    fi
fi
echo "CertKite CLI installed at $destination"
