# certkite-deploy

Unix certificate deployment library with automatic Nginx and Caddy site discovery.
`discover` inspects active systemd services, parses their standard configuration,
and returns one stable target per virtual host. Local paths and service commands
remain client-controlled.

The user client stores file targets under `~/.local/share/certkite/certificates/downloads` by
default. Existing system installs use `/var/lib/certkite-certificates/<target-id>`
for Nginx and Caddy targets.
An immutable `versions/<sha256>` directory is fsynced before an atomic `current`
symlink switch. Nginx targets use root-only 0700/0600 storage. Caddy targets use
0750 directories and 0640 certificate files owned by root and the service group,
so the unprivileged Caddy process can read the private key without making it public.
`SharedFiles` uses the same group access without editing or reloading a service.
`prepare` reconciles all retained file-target versions to the selected access
policy; journals and lock files remain private. `prepare_certificate_root` creates
or upgrades a runtime-owned 0700/0711 container to 0711 for path traversal.
Fingerprint is a length-framed SHA-256 over both PEM byte strings.

Each new deployment reconciles the matching Nginx `server` block's
`listen 443 ssl`, `ssl_certificate` and `ssl_certificate_key` directives, including
all IPv4/IPv6 port 443 listeners. Leading-dot server names expand to the root domain
and its wildcard. Configuration drift is repaired even when certificate bytes match. The matching Caddy
site block receives or updates its `tls` directive. Existing unrelated directives
are retained. Ambiguous duplicate sites, imported Caddy site definitions and complex
Caddy `tls { ... }` blocks are rejected instead of guessed.

Configuration replacement is atomic and preserves ownership and mode. A private
backup is written and fsynced before editing. The configured binary validates the
complete configuration, followed by fixed `/usr/bin/systemctl reload -- <unit>`.
No shell is used. Commands have deadlines of at most 30 seconds; their process groups
are killed on timeout or excessive output and every exit status is checked.
Discovery output is bounded to 16 MiB per stream. Configuration and certificate state are
restored together when validation or reload fails, including recovery after a crash.

A global Nginx lock serializes Nginx targets using
`/run/certkite-client/nginx.lock` on Linux and a UID-scoped temp directory on
macOS/tests. Each target also has an fs2 lock. `check` validates storage, journal,
current link and service configuration without switching links or reloading.

The journal stores operation IDs, digests, generations, prior/next relative links
and outcomes, with no private keys. The latest 256 operations are retained.
Retained successful retransmissions return their original outcome; older evicted
retransmissions are rejected as stale. After a committed publication, cleanup keeps
the current and immediately previous versions and removes older versions and
abandoned staging directories. Pending recovery finishes before cleanup; retained
receipts still return their original outcome after old certificate files are pruned.

Validation uses SAN only, supports IPs and one-label DNS wildcards, requires exact
wildcard SANs for wildcard task domains, matches keys, checks every certificate's
validity, issuer order, signatures and duplicates, and uses OpenSSL partial-chain
verification for CA/key-usage/path-length constraints. A non-self-signed leaf must
include an issuer. The final supplied issuer is the explicit trust anchor: this
validates material structure, not public WebPKI trust or revocation. No network
access is performed.

Use `classify(&anyhow::Error)` for stable `Failure` categories. Error chains retain
details, including both application and rollback errors.

Run `cargo +stable test -p certkite-deploy` from the workspace. All test keys and
certificates are locally generated; service commands are replaced by test scripts.
