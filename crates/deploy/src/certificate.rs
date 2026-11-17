use anyhow::{Context, Result, ensure};
use openssl::{
    asn1::Asn1Time,
    pkey::PKey,
    stack::Stack,
    x509::{X509, X509StoreContext, store::X509StoreBuilder, verify::X509VerifyFlags},
};
use std::{cmp::Ordering, net::IpAddr};

#[cfg(test)]
pub(crate) fn validate(domain: &str, pem: &str, key: &str) -> Result<()> {
    validate_all(&[domain], pem, key)
}

pub(crate) fn validate_all(domains: &[&str], pem: &str, key: &str) -> Result<()> {
    for domain in domains {
        ensure!(
            !domain.is_empty() && domain.is_ascii(),
            "domain must be an ASCII DNS name or IP address"
        );
        if domain.parse::<IpAddr>().is_err() {
            let dns = domain.strip_suffix('.').unwrap_or(domain);
            let dns = dns.strip_prefix("*.").unwrap_or(dns);
            ensure!(
                dns.len() <= 253
                    && dns.split('.').all(|label| {
                        !label.is_empty()
                            && label.len() <= 63
                            && !label.starts_with('-')
                            && !label.ends_with('-')
                            && label
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    }),
                "invalid DNS name"
            );
        }
    }
    let certs = X509::stack_from_pem(pem.as_bytes()).context("parse certificate chain")?;
    ensure!(!certs.is_empty(), "empty certificate chain");
    ensure!(
        certs.len() > 1 || certs[0].issuer_name().to_der()? == certs[0].subject_name().to_der()?,
        "non-self-signed leaf requires its issuer chain"
    );
    let private = PKey::private_key_from_pem(key.as_bytes()).context("parse private key")?;
    ensure!(
        certs[0].public_key()?.public_eq(&private),
        "certificate private key mismatch"
    );
    let now = Asn1Time::days_from_now(0)?;
    for (i, cert) in certs.iter().enumerate() {
        ensure!(
            cert.not_before().compare(&now)? != Ordering::Greater
                && cert.not_after().compare(&now)? == Ordering::Greater,
            "certificate {i} is outside its validity period"
        );
        for previous in &certs[..i] {
            ensure!(
                previous.to_der()? != cert.to_der()?,
                "duplicate certificate in chain"
            );
        }
        if let Some(issuer) = certs.get(i + 1) {
            ensure!(
                cert.issuer_name().to_der()? == issuer.subject_name().to_der()?,
                "chain issuer ordering mismatch"
            );
            let issuer_key = issuer.public_key()?;
            ensure!(cert.verify(&issuer_key)?, "invalid chain signature");
        } else if cert.issuer_name().to_der()? == cert.subject_name().to_der()? {
            let own_key = cert.public_key()?;
            ensure!(cert.verify(&own_key)?, "invalid self-signed certificate");
        }
    }
    // The provided final issuer is an explicit deployment trust anchor. This checks
    // signatures, CA constraints, key usage and path length without network access.
    let mut store = X509StoreBuilder::new()?;
    store.add_cert(certs.last().unwrap().clone())?;
    store.set_flags(X509VerifyFlags::PARTIAL_CHAIN)?;
    let mut untrusted = Stack::new()?;
    for cert in certs.iter().skip(1) {
        untrusted.push(cert.clone())?;
    }
    let mut ctx = X509StoreContext::new()?;
    let verified = ctx.init(&store.build(), &certs[0], &untrusted, |c| c.verify_cert())?;
    ensure!(
        verified,
        "certificate chain validation failed: {}",
        ctx.error()
    );
    let sans = certs[0]
        .subject_alt_names()
        .context("certificate has no SAN extension")?;
    for domain in domains {
        let ip = domain.parse::<IpAddr>().ok();
        let matched = sans.iter().any(|san| {
            if let Some(ip) = ip {
                return san.ipaddress().is_some_and(|bytes| match ip {
                    IpAddr::V4(ip) => bytes == ip.octets(),
                    IpAddr::V6(ip) => bytes == ip.octets(),
                });
            }
            san.dnsname().is_some_and(|name| dns_matches(name, domain))
        });
        ensure!(matched, "certificate SAN does not cover {domain}");
    }
    Ok(())
}
fn dns_matches(pattern: &str, domain: &str) -> bool {
    let pattern = pattern.trim_end_matches('.');
    let domain = domain.trim_end_matches('.');
    if domain.starts_with("*.") {
        return pattern.eq_ignore_ascii_case(domain);
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        !suffix.contains('*')
            && domain
                .split_once('.')
                .is_some_and(|(label, rest)| !label.is_empty() && rest.eq_ignore_ascii_case(suffix))
    } else {
        !pattern.contains('*') && pattern.eq_ignore_ascii_case(domain)
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn wildcard() {
        assert!(super::dns_matches("*.example.com", "a.example.com"));
        assert!(!super::dns_matches("*.example.com", "a.b.example.com"));
        assert!(!super::dns_matches("*.example.com", "example.com"));
    }
}
