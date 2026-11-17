# Security policy

The installed service runs as root and handles TLS private keys. Keep accessKey
configuration root-owned and mode 0600, and certificate target directories mode
0700. Treat a shared account accessKey as having the account permissions Core
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

Real systemd/Nginx integration requires Linux qualification before production rollout.
Updates verify startup readiness, not every application behavior or external TLS endpoint.
