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

Service installation detects active Nginx and Caddy virtual hosts using the
standard service binary and configuration locations. It validates detected
service configurations, discovers each site's domains, creates a stable
local target ID, and grants the client write access only to the discovered config
directories and managed certificate root. Servers without detected virtual hosts
can install and run the client to download certificates. Configuration is mode 0600 and owned by
the running user. The optional `downloadGroup` field accepts a numeric local group
ID and authorizes that group to read download-only certificates and private keys.
Unknown fields, including manual `targets`, are rejected. The endpoint has no runtime override.

With Core v2, the client selects a discovered Nginx or Caddy virtual host by
certificate domain and deploys only when exactly one site matches. The certificate
must cover all domains on that site. Core's file-only target saves certificates under
the managed `downloads` directory by domain and applies the configured `downloadGroup`.

With `/client/v1/connect`, the client reports each target's ID, kind and domains
without exposing local paths. Core binds the certificate to an exact target ID.
If that target is absent, the client validates and saves the certificate and
reports that deployment was skipped.

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

First startup generates a persistent random client ID. The daemon registers with
Core when it connects and refreshes that registration on each reconnect. There
is no enroll/unenroll command. `certkite status` reports the connection as active
after Core acknowledges registration. `certkite doctor` verifies the access key
using the certificate-list OpenAPI with Bearer authentication. If that route
returns HTTP 404 or 405, it uses the `/client/v1/identity` endpoint.

```text
certkite status [--json]
certkite logs [-n LINES] [-f] [--level LEVEL] [--json]
certkite doctor [--json]
certkite update [--check] [--to VERSION] [--json]
certkite service install
certkite service uninstall
```

Global flags: `--config PATH`, `--log-level LEVEL`, `--help`, `--version`.
The daemon entry point is private; use systemd for service lifecycle:

```sh
sudo certkite status --json
sudo systemctl restart certkite
sudo certkite logs -f
```

### Logs

The daemon records startup, Core connection, operation progress, results and failures.
Logs are sanitized before writing to private JSON Lines files in
`/var/lib/certkite-client/`: `client.log` and one rotated file, `client.log.1`.
Each file is capped at 2 MiB and uses mode 0600. A shared process lock keeps reads
consistent with appends and rotation. Logging also writes to stderr,
which systemd captures in its journal. Configuration failures before logging starts
remain available with `journalctl -u certkite`.

```sh
sudo certkite logs                  # Latest 100 records
sudo certkite logs -n 200           # Latest 200 records (maximum 1000)
sudo certkite logs -f               # Follow new records; Ctrl+C exits
sudo certkite logs --level error    # Exact severity filter
sudo certkite logs --json           # One JSON record per line
```

Records include a unique ID, Unix millisecond timestamp, severity and message.
Supported severity filters are `error`, `warn`, `info` and `debug`; trace events
are represented as DEBUG. The global `--log-level` controls collection, so debug
records require starting the service with `--log-level debug`.

The daemon independently uploads logs to `POST https://certkite.com/api/logs`
over verified TLS using its access key in the `X-Access-Key` header. Requests contain
`type: "deploy"`, `clientId`, a Unix millisecond `timestamp`, `level` and `message`.
Core accepts logs for an existing active deployment client owned by the access key's
account; deployment connections register the client and maintain online status.
Uploads before registration or after deletion receive HTTP 403 and remain local.
In Core Web, open **Deployment → client → Client logs** for history,
severity/time/search filters and live updates. Certificate/private-key material and
the configured access key are redacted locally, with additional sanitization in Core.

Delivery uses a 256-record memory queue and up to three attempts for transient
failures. Queue overflow and failed uploads remain in local files; they are not
replayed automatically after a restart or reconnect. A slow log server cannot
block certificate publication. Shutdown allows up to five seconds to finish uploads.
Local rotation and Core retention are independent; Core uses its configured log store.

Remote viewing uses Core's existing `/api/logs` endpoint and deployment log store.
The log endpoint is independent of the `/client/v1/connect` adapter; Core must have
an active registration for the same client ID before it accepts uploads. Remote
logs are tied to that registration. The log viewer shows records with verified
registration ownership. Older records without that ownership remain in storage
for their configured retention period.

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
JSON command results and `certkite logs` output go to stdout; diagnostic output goes
to stderr.

## Certificate publication

The client validates SAN coverage (including IPs and single-label wildcards),
certificate validity, key matching and supplied chain structure. The supplied last
issuer is a deployment trust anchor; public PKI trust and revocation are not checked.
Certificates are stored under `/var/lib/certkite-certificates/<target-id>` in
immutable version directories before an atomic `current` switch. Certificates
downloaded for unavailable targets are stored separately under
`/var/lib/certkite-certificates/downloads/<target-id>`. Services use the stable paths
`current/fullchain.pem` and `current/privkey.pem`. Downloads have their own operation
receipts and generation checks, and do not read or modify service deployment journals,
configuration backups or service directory permissions.

Download-only targets default to root-only access (0700 directories, 0600 files).
To let other service accounts read them, create a dedicated group and add only the
authorized accounts:

```sh
sudo groupadd --system certkite-tls
sudo usermod -aG certkite-tls <service-user>
getent group certkite-tls
```

Set `downloadGroup = <numeric-GID>` in `/etc/certkite-client/config.toml`, using the
third field from `getent`, then restart `certkite` and the consuming service so its
process picks up the group membership. On the next download, all retained versions
for that target receive 0750 directories and 0640 certificate/key files owned by
root and the configured group. Renewal preserves that access; removing the setting
restores root-only access on the next download for each target. The certificate root
and `downloads` container use 0711 so service users can traverse known paths.
Journals and lock files remain 0600. Every member of the group can read all
download-only targets published with that group.

Verify with the actual service account and target ID:

```sh
sudo -u <service-user> test -r /var/lib/certkite-certificates/downloads/<target-id>/current/fullchain.pem
sudo -u <service-user> test -r /var/lib/certkite-certificates/downloads/<target-id>/current/privkey.pem
```

Consuming services must reload certificates after renewal. For containers, mount
the target directory, including `versions` and `current`, and provide the same
numeric GID to the container process. Service sandboxing, SELinux and AppArmor must
also permit access to the mounted path.

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

Core v2 registration, heartbeats, and certificate deployments use
`wss://certkite.com/deploy/v2/ws` with the client ID in the query string and the
access key in the TLS handshake's `Authorization: Bearer` header. Deploy the Core
backend with Bearer handshake support and v2 task generations before rolling
out the client. Reverse proxies must forward the `Authorization` header.

If the v2 handshake returns HTTP 404 or 401, the client tries the
`/client/v1/connect` endpoint with Bearer authentication. Both protocols reject
older deployments within their own generation sequence. Signed updates use
the `/client/v1/releases/` endpoints.

The workspace test suite runs against local mock services and needs no private
repository, production accessKey or real certificate issuance.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Release artifacts are built by a manually triggered workflow after workspace
formatting, lint and test checks pass. Each platform artifact contains `certkite-TARGET`, its
SHA-256 file and a key-embedded `install.sh`. Configure the trusted public key for
release builds, sign manifests in your release system, and publish the installer,
release endpoints and artifacts at the fixed CertKite origin. The workflow prepares
assets without publishing to production.

## Security and license

See [SECURITY.md](SECURITY.md). Licensed under [Apache-2.0](LICENSE).
