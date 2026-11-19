# Security policy

The user client handles TLS private keys. Keep the accessKey configuration owned
by the running user and mode 0600. Local state and logs are private to that user.
File targets use 0700 directories and 0600 certificate/key files by default.
Targets with `downloadGroup` use 0750 directories and 0640 files owned by the
running user and the authorized group. The certificate root and downloads
container use 0711 for path traversal. Journals and locks remain 0600. Limit group
membership to trusted service accounts. New group settings apply on the next
download for each target. Existing system installations run as root and retain
their root-owned state and managed server configuration.
Treat a shared account accessKey as having the account permissions Core
assigns to it; rotate it and close active sessions if a server is compromised.

Report vulnerabilities privately through CertKite’s security contact/support
channel at https://certkite.com. Do not post accessKeys, private keys, full deployment
messages or exploitable details in public issues. Include affected client version,
platform, reproduction steps using synthetic credentials and expected impact.

The client trusts authorized Core certificate deployments within locally configured
targets. Core cannot choose arbitrary paths or commands through the protocol.
Update binaries require a separately trusted release signing key; HTTPS alone is
not accepted as executable authenticity. Initial installations must come through
a trusted distribution channel.

Certificate validation checks the supplied chain, SANs, dates and matching key.
It does not establish public CA trust or query revocation services. Root compromise,
malicious local configuration, another administrator modifying managed directories
and a compromised release signing authority are outside these boundaries.

The existing system updater verifies systemd startup readiness. User updates verify
the signed binary and its version before replacement, and take effect on restart.
