# CertKite Client

A Rust CLI that downloads and renews certificates managed by CertKite.
The client connects to `https://certkite.com` using an `accessKey`; it does not
need an inbound port or SSH credentials. Core remains a separate, closed-source
service. This workspace contains no Core source or private dependencies.

The client runs on Linux amd64/arm64 from a regular user account. It can run in
the foreground or under a user-level systemd service. macOS can build and run
isolated tests.

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
| `certkite-cli` | clap commands, output, exit codes, systemd status |
| `certkite-client` | configuration, identity, connection, scheduling and updates |
| `certkite-protocol` | local deployment commands, validation limits and result codes |
| `certkite-deploy` | certificate validation, durable publication and recovery |

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

Add `~/.local/bin` to your shell configuration if it is outside PATH:

```sh
export PATH="$HOME/.local/bin:$PATH"
certkite --version
certkite update --check
```

Release builds produce an installer with the trusted public key embedded. The
source installer rejects installation until `RELEASE_PUBLIC_KEY_HEX` is configured.
You can also install a locally obtained binary using a SHA-256 digest you verified
independently:

```sh
sh packaging/install.sh --binary PATH --sha256 DIGEST
```

### Configure and run

Create a private configuration owned by the account that runs CertKite:

```sh
config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/certkite"
install -d -m 0700 "$config_dir"
if [ ! -e "$config_dir/config.toml" ]; then
    install -m 0600 packaging/config.example.toml "$config_dir/config.toml"
fi
"${EDITOR:-vi}" "$config_dir/config.toml"
certkite doctor
certkite run
```

Create `config.toml` with `accessKey = "your-certkite-access-key"` if the example
file is unavailable. Configuration files must use mode 0600 or stricter. `--config PATH` selects a
specific file. Unknown fields, including manual `targets`, are rejected. The
endpoint has no runtime override.

CertKite uses absolute XDG base directories when set. Default paths are:

| Data | Default directory | Override |
| --- | --- | --- |
| Configuration | `~/.config/certkite` | `XDG_CONFIG_HOME` |
| Identity, state and logs | `~/.local/state/certkite` | `XDG_STATE_HOME` |
| Certificates | `~/.local/share/certkite/certificates` | `XDG_DATA_HOME` |

### Run in the background

On hosts with a user systemd manager, save the following as
`${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/certkite.service`. If you set custom
XDG directories for CertKite, pass the same values to the user service using
`Environment=`.

```ini
[Unit]
Description=CertKite certificate client

[Service]
Type=notify
ExecStart=%h/.local/bin/certkite run
Restart=on-failure
RestartSec=5s
TimeoutStopSec=300s
UMask=0077

[Install]
WantedBy=default.target
```

```sh
systemctl --user daemon-reload
systemctl --user enable --now certkite.service
```

The user manager's lifetime determines whether the service keeps running after
logout. Check the host's lingering policy if certificates must renew while no one
is logged in. To stop the service and remove its startup link, use
`systemctl --user disable --now certkite.service`.

First startup generates a persistent random client ID. The daemon registers with
Core when it connects and refreshes that registration on each reconnect. There
is no enroll/unenroll command. `certkite status` reports the connection as active
after Core acknowledges registration. `certkite doctor` verifies the access key
using the certificate-list OpenAPI with Bearer authentication.

```text
certkite run
certkite status [--json]
certkite logs [-n LINES] [-f] [--level LEVEL] [--json]
certkite doctor [--json]
certkite update [--check] [--to VERSION] [--json]
```

Global flags include `--config PATH`, `--log-level LEVEL`, `--help` and `--version`.
Run these commands as the same account as the client:

```sh
certkite status --json
certkite logs -f
systemctl --user restart certkite.service  # If running under user systemd
```

### Logs

The daemon records startup, Core connection, operation progress, results and failures.
Logs are sanitized before writing to private JSON Lines files in
the user state directory: `client.log` and one rotated file, `client.log.1`.
Each file is capped at 2 MiB and uses mode 0600. A shared process lock keeps reads
consistent with appends and rotation. Logging also writes to stderr,
which systemd captures in its journal when used. For a user service, see
`journalctl --user -u certkite.service` for failures before the log file opens.

```sh
certkite logs                  # Latest 100 records
certkite logs -n 200           # Latest 200 records (maximum 1000)
certkite logs -f               # Follow new records; Ctrl+C exits
certkite logs --level error    # Exact severity filter
certkite logs --json           # One JSON record per line
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
Core accepts uploads from client IDs with an active registration and ties the
logs to that registration. The log viewer shows records with verified
registration ownership. Older records without that ownership remain in storage
for their configured retention period.

Status includes timestamped snapshots. Doctor checks the private configuration and
platform identity. Never copy `identity.json` to another live client.

Exit codes are 0 for success, 1 for operation failure, 2 for command usage errors,
3 for invalid configuration, and 4 when doctor completes with failed checks.
JSON command results and `certkite logs` output go to stdout. Diagnostic output
uses stderr.

## Certificate publication

Select the file-only deployment target for this client in Core. The client validates
SAN coverage (including IPs and single-label wildcards), certificate validity, key
matching and chain structure. The last supplied issuer is the deployment trust
anchor. Public PKI trust and revocation are outside this validation.

Each target publishes immutable versions under the user data directory, at
`~/.local/share/certkite/certificates/downloads/<target-id>/` by default. Consumers use the stable
paths `current/fullchain.pem` and `current/privkey.pem`. Renewals atomically switch
`current` to the new version. Consumers that cache certificates must reload after
renewal. For containers, mount the target directory including `versions` and `current`.

The target's directories and certificate files default to `0700` and `0600`.
`downloadGroup = <numeric-GID>` grants an existing group read access by setting
retained target directories to `0750` and certificate/key files to `0640` on the
next download. The running account must be able to assign that group, and consumers
must be able to traverse the certificate path. Every member of the group can read
all private keys shared with that group. Removing `downloadGroup` restores private
access on the next download for each target.

Task retries reuse an operation ID. Content conflicts and older generations are
rejected; the last 256 operation receipts are retained per target. Interrupted
publication is recovered before the service announces readiness. Network disconnects
do not cancel an in-flight file publication. After a successful commit, certificate
storage retains the current and immediately previous versions; older versions and
abandoned version staging directories are pruned. Operation receipts remain valid
after their certificate files have been pruned.

## Updates

```sh
certkite update --check
certkite update
certkite update --to 1.2.3
```

Updates require `CERTKITE_RELEASE_PUBLIC_KEY_HEX` at build time. The client checks the
signed release manifest and validates the replacement binary before atomically
installing it at `~/.local/bin/certkite`. Restart `certkite run` or the user service
after the update to use the new executable.

## Existing system installations

Existing root-managed services using `/usr/local/bin/certkite` and `__daemon`
keep their original configuration, identity, certificate paths, automatic system
Nginx/Caddy deployment and signed system updates. Managing that system service
and changing or reloading system-owned Nginx/Caddy still requires the host's
administrator permissions. The user client registers independently and publishes
renewed certificate files to its own directory.

## Core integration

Core registration, heartbeats, and certificate deployments use
`wss://certkite.com/deploy/v2/ws` with the client ID in the query string and the
access key in the TLS handshake's `Authorization: Bearer` header. Deploy the Core
backend with Bearer handshake support and task generations before rolling
out the client. Reverse proxies must forward the `Authorization` header.

After a connection failure the daemon retries the deployment endpoint with backoff.
The client rejects older deployment generations for each target. Signed updates
use the `/client/v1/releases/` endpoints.

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
