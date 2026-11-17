#!/bin/sh
# Install an independently verified local artifact; credentials never enter argv.
set -eu

usage() {
    echo "Usage: $0 --binary PATH --sha256 TRUSTED_DIGEST [--config PATH]" >&2
    exit 2
}

binary=
digest=
config=/etc/certkite-client/config.toml
while [ "$#" -gt 0 ]; do
    case "$1" in
        --binary) [ "$#" -ge 2 ] || usage; binary=$2; shift 2 ;;
        --sha256) [ "$#" -ge 2 ] || usage; digest=$2; shift 2 ;;
        --config) [ "$#" -ge 2 ] || usage; config=$2; shift 2 ;;
        *) usage ;;
    esac
done
[ -n "$binary" ] && [ -n "$digest" ] || usage
[ "${#digest}" -eq 64 ] || usage
case "$digest" in *[!0-9a-fA-F]*) usage ;; esac
[ "$(uname -s)" = Linux ] || { echo "Linux with systemd is required" >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo "Run as root" >&2; exit 1; }
[ -f "$binary" ] && [ ! -L "$binary" ] || { echo "Binary must be a regular file" >&2; exit 1; }
if [ -e "$config" ] || [ -L "$config" ]; then
    [ -f "$config" ] && [ ! -L "$config" ] || { echo "Configuration must be a regular file" >&2; exit 1; }
elif [ "$config" != /etc/certkite-client/config.toml ]; then
    echo "Create the custom configuration first" >&2
    exit 1
fi
command -v systemctl >/dev/null 2>&1 || { echo "systemd is required" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required" >&2; exit 1; }
command -v stat >/dev/null 2>&1 || { echo "stat is required" >&2; exit 1; }
secure_root_path() {
    owner=$(stat -c %u -- "$1")
    mode=$(stat -c %a -- "$1")
    [ "$owner" -eq 0 ] && [ $((0$mode & 022)) -eq 0 ]
}
# Hash the private staged copy that will actually be installed.
install -d -m 0755 /usr/local/bin
secure_root_path /usr/local/bin || { echo "/usr/local/bin must be root-owned and not group/world-writable" >&2; exit 1; }
stage=$(mktemp -d /usr/local/bin/.certkite-install.XXXXXX)
trap 'rm -f -- "$stage/binary"; rmdir -- "$stage"' EXIT HUP INT TERM
install -m 0755 -- "$binary" "$stage/binary"
actual=$(sha256sum -- "$stage/binary")
actual=${actual%% *}
expected=$(printf '%s' "$digest" | tr 'A-F' 'a-f')
[ "$actual" = "$expected" ] || { echo "SHA-256 verification failed" >&2; exit 1; }
destination=/usr/local/bin/certkite
if [ -e "$destination" ] || [ -L "$destination" ]; then
    if [ ! -f "$destination" ] || [ -L "$destination" ] || ! secure_root_path "$destination" || ! cmp -s -- "$stage/binary" "$destination"; then
        echo "A different or unsafe binary is installed; use certkite update" >&2
        exit 1
    fi
else
    # An atomic create prevents racing installers from overwriting another binary.
    ln -- "$stage/binary" "$destination"
fi
rm -f -- "$stage/binary"
rmdir -- "$stage"
trap - EXIT HUP INT TERM
exec "$destination" --config "$config" service install
