# CertKite Client

A Rust CLI and systemd service for installing certificates managed by CertKite.
The client connects to `https://certkite.com` using an `accessKey`; it does not
need an inbound port or SSH credentials. Core remains a separate, closed-source
service. This workspace contains no Core source or private dependencies.

Linux amd64/arm64 with systemd is the supported runtime. Active Nginx and Caddy
virtual hosts are detected and configured automatically. macOS can build and run
isolated tests; it cannot run the Linux service or self-updater.

## Build

```sh
cargo build --release --locked -p certkite-cli
./target/release/certkite --help
```

The workspace pins Rust 1.88.0. Building vendored OpenSSL requires a C compiler,
make and Perl. Release binaries statically include OpenSSL; the GNU libc baseline
is determined by the release builder. Build on Ubuntu 22.04 or a compatible image
when distributing to Ubuntu 22.04-class hosts.

| Crate | Responsibility |
| --- | --- |
| `certkite-cli` | clap commands, output, exit codes, systemd integration |
| `certkite-client` | configuration, identity, connection, scheduling and updates |
| `certkite-protocol` | public JSON protocol, limits and result codes |
| `certkite-deploy` | certificate validation, durable publication and recovery |

## Configure

The first `sudo certkite service install` creates
`/etc/certkite-client/config.toml` with mode 0600 when the default configuration
is missing, then exits without installing or starting the service. Fill in only
the access key and run the command again:

```sh
sudo install -d -m 0700 /etc/certkite-client
sudo install -m 0600 packaging/config.example.toml /etc/certkite-client/config.toml
sudoedit /etc/certkite-client/config.toml
```

```toml
accessKey = "replace-with-your-certkite-access-key"
```

Service installation requires at least one active Nginx or Caddy virtual host using the
standard service binary and configuration locations. It validates the running
service configuration, discovers each site's domains, creates a stable
local target ID, and grants the client write access only to the discovered config
directories and managed certificate root. Configuration is mode 0600 and owned by
the running user. Unknown fields, including manual `targets`, are rejected. The
endpoint has no runtime override.

Each discovered virtual host is a separate authorization boundary. The client
reports its target ID, service kind and configured domains to Core without exposing
local paths. Core binds a certificate to that exact target; a deployment is rejected
when its domain does not match the selected local site.

## Install and operate

The hosted installer installs the CLI into `~/.local/bin/certkite` as the current
user. It requires Linux amd64/arm64, Python 3, OpenSSL with Ed25519 support, curl
and GNU core utilities. It verifies the signed release manifest, artifact size,
SHA-256, architecture and version before atomically replacing the CLI:

```sh
sh install.sh
# Or use the published, key-embedded installer:
curl -fsSL https://certkite.com/install.sh | sh
```

The installer does not request sudo, create configuration or start services.
If `~/.local/bin` is outside PATH, add it to your shell configuration:

```sh
export PATH="$HOME/.local/bin:$PATH"
certkite --version
certkite update --check
```

Release builds produce an installer with the trusted public key embedded. The
source installer rejects installation until `RELEASE_PUBLIC_KEY_HEX` is configured.
Rerun the trusted installer to replace a user-installed CLI. System certificate
management still requires a separately installed root service; the signed
`certkite update` command updates that service's `/usr/local/bin/certkite` binary.

To install a verified release binary as the system service:

```sh
sudo install -m 0755 ./certkite /usr/local/bin/certkite
sudo /usr/local/bin/certkite service install
```

If this creates the default configuration, edit the access key before validating
and completing installation:

```sh
sudoedit /etc/certkite-client/config.toml
sudo certkite doctor
sudo certkite service install
```

Alternatively, `packaging/install.sh --binary PATH --sha256 DIGEST --config PATH`
installs a locally obtained binary whose digest you independently verified. The
script does not fetch binaries, accept credentials in arguments or overwrite a
different installed version.

First startup generates a persistent random client ID. Connecting with accessKey
registers or refreshes that server in Core. There is no enroll/unenroll command.
The accessKey is sent only as a sensitive Authorization header over verified TLS;
credentials and private keys are excluded from protocol Debug output.

```text
certkite status [--json]
certkite doctor [--json]
certkite update [--check] [--to VERSION] [--json]
certkite service install
certkite service uninstall
```

Global flags: `--config PATH`, `--log-level LEVEL`, `--help`, `--version`.
The daemon entry point is private; use systemd for service lifecycle and logs:

```sh
sudo certkite status --json
sudo systemctl restart certkite
sudo journalctl -u certkite -f
```

Status includes timestamped snapshots, not a claim of current platform connectivity.
Doctor checks configuration, automatic service discovery, target storage, the
Nginx/Caddy configuration and platform identity without publishing certificates
or reloading services.
Uninstall removes the service and preserves binary, identity, configuration and
certificates. Never copy identity.json to another live server.

Exit codes: 0 success, 1 operation failure, 2 command usage error, 3 configuration
failure for the daemon, doctor or service installation, and 4 when doctor completes with
failed checks. Creating the initial configuration template is successful but does not
install or start the service.
JSON command results go to stdout; logs go to stderr.

## Certificate publication

The client validates SAN coverage (including IPs and single-label wildcards),
certificate validity, key matching and supplied chain structure. The supplied last
issuer is a deployment trust anchor; public PKI trust and revocation are not checked.
Certificates are stored under `/var/lib/certkite-certificates/<target-id>` in
immutable version directories before an atomic `current` switch.

For Nginx, the matching `server` block receives or updates `listen 443 ssl`,
`ssl_certificate` and `ssl_certificate_key`. For Caddy, the matching site block
receives or updates its `tls` directive. The client validates the complete service
configuration and reloads its systemd unit. Config edits and certificate publication
are journaled and rolled back together when validation, reload or recovery fails.
Ambiguous duplicate sites, imported Caddy site definitions and complex Caddy
`tls { ... }` blocks are rejected rather than guessed.

Task retries reuse an operation ID. Content conflicts and older generations are
rejected; the last 256 operation receipts are retained per target. Interrupted
publication is recovered before the service announces readiness. Network disconnects
do not cancel an in-flight file publication. After a successful commit, certificate
storage retains the current and immediately previous versions; older versions and
abandoned version staging directories are pruned. Operation receipts remain valid
after their certificate files have been pruned.
Before each update, completed update jobs are pruned to one prior job, so at most
the new job and one prior job remain after completion.

## Updates

```sh
certkite update --check
sudo certkite update
sudo certkite update --to 1.2.3
```

Updates require a release public key embedded at build time. Builds without
`CERTKITE_RELEASE_PUBLIC_KEY_HEX` reject updates explicitly. The independent systemd
worker verifies the signed manifest and artifact, drains operations, stops the old
service, atomically replaces the binary, and checks Type=notify readiness, actual
process inode and version. Startup failure attempts verified rollback. Configuration,
identity and certificates are preserved. See [signed updates](docs/update.md) for
release publishing, inspection and interrupted-update recovery.

## Core integration

Core must implement the [public protocol](docs/protocol.md), including the new
`/client/v1/` endpoints, server registration, authorization, monotonically increasing
per-target generations and deployment scheduling. These endpoints are a separate
contract from the existing `/deploy/v2/ws` protocol; this client does not fall back
to legacy protocols or send account credentials in URLs. A Core deployment without
the adapter cannot register this client or provide update metadata.

The workspace test suite runs against local mock services and needs no private
repository, production accessKey or real certificate issuance.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Release artifacts are built by a manually triggered workflow after Linux
qualification passes. Each platform artifact contains `certkite-TARGET`, its
SHA-256 file and a key-embedded `install.sh`. Configure the trusted public key for
release builds, sign manifests in your release system, and publish the installer,
release endpoints and artifacts at the fixed CertKite origin. The workflow prepares
assets without publishing to production.

The Linux qualification workflow runs the installer as an ordinary user against
local signed fixtures, then uses a disposable Ubuntu VM with real systemd and Nginx.
It starts the generated service and drives the actual update worker through
replacement, Type=notify readiness, process-inode checks and failed-start rollback.
Synthetic release executables supply the startup contract; no Core credentials or
production release signing key are required.

## Security and license

See [SECURITY.md](SECURITY.md). Licensed under [Apache-2.0](LICENSE).
