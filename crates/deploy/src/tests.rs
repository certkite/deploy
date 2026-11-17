use super::*;
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, KeyUsage, SubjectAlternativeName},
    },
};
use std::os::unix::fs::PermissionsExt;
fn dir() -> tempfile::TempDir {
    let dir = tempfile::Builder::new()
        .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
fn certificate(names: &[&str]) -> (String, String) {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let cert = make_cert(&key, names, None, 0, 3);
    (
        String::from_utf8(cert.to_pem().unwrap()).unwrap(),
        String::from_utf8(key.private_key_to_pem_pkcs8().unwrap()).unwrap(),
    )
}
fn make_cert(
    key: &PKey<Private>,
    names: &[&str],
    issuer: Option<(&X509, &PKey<Private>)>,
    start: u32,
    end: u32,
) -> X509 {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text(
        "CN",
        if issuer.is_some() {
            "leaf.example"
        } else {
            "ignored.example"
        },
    )
    .unwrap();
    let name = name.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    let serial = BigNum::from_u32(if issuer.is_some() { 2 } else { 1 })
        .unwrap()
        .to_asn1_integer()
        .unwrap();
    b.set_serial_number(&serial).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(issuer.map(|(c, _)| c.subject_name()).unwrap_or(&name))
        .unwrap();
    b.set_pubkey(key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(start).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(end).unwrap())
        .unwrap();
    if issuer.is_none() {
        b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        b.append_extension(
            KeyUsage::new()
                .key_cert_sign()
                .digital_signature()
                .build()
                .unwrap(),
        )
        .unwrap();
    }
    let mut san = SubjectAlternativeName::new();
    for name in names {
        if name.parse::<std::net::IpAddr>().is_ok() {
            san.ip(name);
        } else {
            san.dns(name);
        }
    }
    b.append_extension(
        san.build(&b.x509v3_context(issuer.map(|(c, _)| c.as_ref()), None))
            .unwrap(),
    )
    .unwrap();
    b.sign(
        issuer.map(|(_, k)| k).unwrap_or(key),
        MessageDigest::sha256(),
    )
    .unwrap();
    b.build()
}
fn request<'a>(op: &'a str, generation: u64, cert: &'a str, key: &'a str) -> Deployment<'a> {
    Deployment {
        operation_id: op,
        generation,
        domain: "a.example.com",
        fullchain_pem: cert,
        private_key_pem: key,
    }
}
#[test]
fn publish_deduplicate_and_generations() {
    let root = dir();
    let target = TargetConfig::Files {
        directory: root.path().into(),
    };
    let (cert, key) = certificate(&["*.example.com"]);
    check(&target).unwrap();
    let first = deploy(&target, &request("one", 1, &cert, &key)).unwrap();
    assert!(first.changed);
    assert_eq!(
        fs::read_to_string(root.path().join("current/privkey.pem")).unwrap(),
        key
    );
    assert_eq!(
        fs::metadata(root.path().join("current/privkey.pem"))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        deploy(&target, &request("one", 1, &cert, &key)).unwrap(),
        first
    );
    assert!(deploy(&target, &request("two", 1, &cert, &key)).is_err());
    assert!(deploy(&target, &request("one", 2, &cert, &key)).is_err());
    let second = deploy(&target, &request("two", 2, &cert, &key)).unwrap();
    assert!(!second.changed);
    assert_eq!(
        deploy(&target, &request("one", 1, &cert, &key)).unwrap(),
        first
    );
    let journal = fs::read_to_string(root.path().join("state.json")).unwrap();
    assert!(!journal.contains("PRIVATE KEY"));
}

#[test]
fn file_group_access_survives_renewal_and_can_be_revoked() {
    let root = dir();
    let directory = root.path().join("downloads");
    let private = TargetConfig::Files {
        directory: directory.clone(),
    };
    private.prepare().unwrap();
    let (cert, key) = certificate(&["a.example.com"]);
    deploy(&private, &request("one", 1, &cert, &key)).unwrap();
    let first = fs::read_link(directory.join("current")).unwrap();
    let gid = fs::metadata(root.path()).unwrap().gid();
    let shared = TargetConfig::SharedFiles {
        directory: directory.clone(),
        service_group: gid,
    };
    shared.prepare().unwrap();
    let (next, next_key) = certificate(&["a.example.com"]);
    deploy(&shared, &request("two", 2, &next, &next_key)).unwrap();
    shared.prepare().unwrap();
    deploy(&shared, &request("two", 2, &next, &next_key)).unwrap();
    for path in [
        directory.clone(),
        directory.join("versions"),
        directory.join(&first),
        fs::canonicalize(directory.join("current")).unwrap(),
    ] {
        let metadata = fs::metadata(path).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o750);
        assert_eq!(metadata.gid(), gid);
    }
    for entry in fs::read_dir(directory.join("versions")).unwrap() {
        for name in ["fullchain.pem", "privkey.pem"] {
            let metadata = fs::metadata(entry.as_ref().unwrap().path().join(name)).unwrap();
            assert_eq!(metadata.mode() & 0o777, 0o640);
            assert_eq!(metadata.gid(), gid);
        }
    }
    for name in ["state.json", ".lock"] {
        assert_eq!(
            fs::metadata(directory.join(name)).unwrap().mode() & 0o777,
            0o600
        );
    }
    private.prepare().unwrap();
    deploy(&private, &request("three", 3, &next, &next_key)).unwrap();
    assert_eq!(
        fs::metadata(directory.join("current/privkey.pem"))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(directory.join(&first)).unwrap().mode() & 0o777,
        0o700
    );
}

#[test]
fn repeated_file_preparation_preserves_existing_access_metadata() {
    let root = dir();
    let directory = root.path().join("shared");
    let target = TargetConfig::SharedFiles {
        directory: directory.clone(),
        service_group: fs::metadata(root.path()).unwrap().gid(),
    };
    target.prepare().unwrap();
    let (cert, key) = certificate(&["a.example.com"]);
    deploy(&target, &request("one", 1, &cert, &key)).unwrap();
    let version = fs::canonicalize(directory.join("current")).unwrap();
    let paths = [
        directory.clone(),
        directory.join("versions"),
        version.clone(),
        version.join("fullchain.pem"),
        version.join("privkey.pem"),
    ];
    let before = paths.each_ref().map(|path| fs::metadata(path).unwrap());
    for _ in 0..16 {
        target.prepare().unwrap();
    }
    for (path, before) in paths.iter().zip(before) {
        let after = fs::metadata(path).unwrap();
        assert_eq!(
            (after.ctime(), after.ctime_nsec()),
            (before.ctime(), before.ctime_nsec()),
            "unchanged authorization must not rewrite permissions: {}",
            path.display()
        );
    }
}

#[test]
fn file_access_migration_rejects_symlinks_without_changing_permissions() {
    let root = dir();
    let directory = root.path().join("target");
    paths::directory(&directory).unwrap();
    paths::directory(&directory.join("versions")).unwrap();
    let outside = root.path().join("outside");
    fs::write(&outside, "private").unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
    let version = directory.join("versions").join("a".repeat(64));
    paths::directory(&version).unwrap();
    symlink(&outside, version.join("privkey.pem")).unwrap();
    let target = TargetConfig::SharedFiles {
        directory: directory.clone(),
        service_group: fs::metadata(root.path()).unwrap().gid(),
    };
    assert!(target.prepare().is_err());
    assert_eq!(fs::metadata(&outside).unwrap().mode() & 0o777, 0o600);
    assert_eq!(fs::metadata(&directory).unwrap().mode() & 0o777, 0o700);
    assert!(prepare_certificate_root(&version.join("privkey.pem")).is_err());
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires root in a disposable Linux environment"]
fn service_group_can_read_downloads_after_renewal() {
    use std::{os::unix::process::CommandExt, process::Command};
    assert_eq!(paths::uid(), 0, "run this test as root");
    let root = dir();
    prepare_certificate_root(root.path()).unwrap();
    let downloads = root.path().join("downloads");
    paths::directory(&downloads).unwrap();
    prepare_certificate_root(&downloads).unwrap();
    let private = TargetConfig::Files {
        directory: downloads.join("site"),
    };
    private.prepare().unwrap();
    let (cert, mut previous_key) = certificate(&["a.example.com"]);
    deploy(&private, &request("initial", 1, &cert, &previous_key)).unwrap();
    let target = TargetConfig::SharedFiles {
        directory: downloads.join("site"),
        service_group: 62001,
    };
    for generation in 2..=3 {
        prepare_certificate_root(&downloads).unwrap();
        target.prepare().unwrap();
        let output = Command::new("/bin/cat")
            .arg(target.directory().join("current/privkey.pem"))
            .uid(65534)
            .gid(62001)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "existing certificate is unreadable after preparation"
        );
        assert_eq!(output.stdout, previous_key.as_bytes());
        let (cert, key) = certificate(&["a.example.com"]);
        previous_key = key.clone();
        deploy(
            &target,
            &request(&format!("op-{generation}"), generation, &cert, &key),
        )
        .unwrap();
        for (name, expected) in [("fullchain.pem", cert), ("privkey.pem", key)] {
            let path = target.directory().join("current").join(name);
            let output = Command::new("/bin/cat")
                .arg(&path)
                .uid(65534)
                .gid(62001)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "authorized service cannot read {name}"
            );
            assert_eq!(output.stdout, expected.as_bytes());
            let output = Command::new("/bin/cat")
                .arg(&path)
                .uid(65534)
                .gid(62002)
                .output()
                .unwrap();
            assert!(
                !output.status.success(),
                "unrelated service can read {name}"
            );
        }
        for name in ["state.json", ".lock"] {
            let output = Command::new("/bin/cat")
                .arg(target.directory().join(name))
                .uid(65534)
                .gid(62001)
                .output()
                .unwrap();
            assert!(!output.status.success(), "service can read private {name}");
        }
    }
    TargetConfig::SharedFiles {
        directory: target.directory().to_owned(),
        service_group: 62002,
    }
    .prepare()
    .unwrap();
    for (gid, allowed) in [(62001, false), (62002, true)] {
        let output = Command::new("/bin/cat")
            .arg(target.directory().join("current/privkey.pem"))
            .uid(65534)
            .gid(gid)
            .output()
            .unwrap();
        assert_eq!(output.status.success(), allowed);
        if allowed {
            assert_eq!(output.stdout, previous_key.as_bytes());
        }
    }
}

#[test]
fn retains_only_current_and_previous_certificate_versions() {
    let root = dir();
    let target = TargetConfig::Files {
        directory: root.path().into(),
    };
    let mut published = Vec::new();
    for generation in 1..=3 {
        let (cert, key) = certificate(&["a.example.com"]);
        deploy(
            &target,
            &request(&format!("op-{generation}"), generation, &cert, &key),
        )
        .unwrap();
        published.push((
            cert,
            key,
            fs::read_link(root.path().join("current")).unwrap(),
        ));
    }
    let (cert, key, _) = &published[0];
    deploy(&target, &request("return-to-first", 4, cert, key)).unwrap();
    assert_eq!(
        fs::read_dir(root.path().join("versions")).unwrap().count(),
        2
    );
    assert!(root.path().join(&published[0].2).is_dir());
    assert!(root.path().join(&published[2].2).is_dir());
    assert!(!root.path().join(&published[1].2).exists());
    // Receipts survive pruning and never reactivate the old certificate.
    deploy(
        &target,
        &request("op-2", 2, &published[1].0, &published[1].1),
    )
    .unwrap();
    assert_eq!(
        fs::read_link(root.path().join("current")).unwrap(),
        published[0].2
    );
}
#[test]
fn rejects_wrong_domain_key_and_future_certificate() {
    let root = dir();
    let target = TargetConfig::Files {
        directory: root.path().into(),
    };
    let (cert, key) = certificate(&["elsewhere.example"]);
    let (_, other) = certificate(&["a.example.com"]);
    assert!(deploy(&target, &request("one", 1, &cert, &key)).is_err());
    assert!(deploy(&target, &request("one", 1, &cert, &other)).is_err());
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let future = make_cert(&key, &["a.example.com"], None, 1, 2);
    assert!(
        certificate::validate(
            "a.example.com",
            &String::from_utf8(future.to_pem().unwrap()).unwrap(),
            &String::from_utf8(key.private_key_to_pem_pkcs8().unwrap()).unwrap()
        )
        .is_err()
    );
    assert!(!root.path().join("current").exists());
}
#[test]
fn san_ip_and_chain_structure() {
    let (cert, key) = certificate(&["127.0.0.1", "::1", "*.example.com"]);
    certificate::validate("127.0.0.1", &cert, &key).unwrap();
    certificate::validate("::1", &cert, &key).unwrap();
    assert!(certificate::validate("a.b.example.com", &cert, &key).is_err());
    assert!(certificate::validate("ignored.example", &cert, &key).is_err());
    assert!(certificate::validate("a.example.com", &format!("{cert}{cert}"), &key).is_err());
    let ca_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let ca = make_cert(&ca_key, &["ca.example"], None, 0, 3);
    let leaf_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let leaf = make_cert(&leaf_key, &["a.example.com"], Some((&ca, &ca_key)), 0, 2);
    let chain = format!(
        "{}{}",
        String::from_utf8(leaf.to_pem().unwrap()).unwrap(),
        String::from_utf8(ca.to_pem().unwrap()).unwrap()
    );
    let leaf_pem = String::from_utf8(leaf_key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    certificate::validate("a.example.com", &chain, &leaf_pem).unwrap();
    let (other_ca, _) = certificate(&["ca.example"]);
    assert!(
        certificate::validate(
            "a.example.com",
            &format!(
                "{}{other_ca}",
                String::from_utf8(leaf.to_pem().unwrap()).unwrap()
            ),
            &leaf_pem
        )
        .is_err()
    );
}
#[test]
fn paths_and_permissions() {
    let root = dir();
    let container = root.path().join("downloads");
    paths::directory(&container).unwrap();
    prepare_certificate_root(&container).unwrap();
    assert_eq!(fs::metadata(&container).unwrap().mode() & 0o777, 0o711);
    let invalid = TargetConfig::SharedFiles {
        directory: root.path().join("invalid"),
        service_group: u32::MAX,
    };
    assert!(invalid.prepare().is_err());
    assert!(!invalid.directory().exists());
    let real = root.path().join("real");
    paths::directory(&real).unwrap();
    symlink(&real, root.path().join("link")).unwrap();
    assert!(
        TargetConfig::Files {
            directory: root.path().join("link")
        }
        .validate()
        .is_err()
    );
    assert!(
        TargetConfig::Files {
            directory: real.join("..")
        }
        .validate()
        .is_err()
    );
    fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(TargetConfig::Files { directory: real }.validate().is_err());
    symlink("/etc/passwd", root.path().join("state.json")).unwrap();
    assert!(
        check(&TargetConfig::Files {
            directory: root.path().into()
        })
        .is_err()
    );
}
fn script(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
#[test]
fn nginx_failure_rolls_back_and_retries() {
    let root = dir();
    let binary = root.path().join("nginx");
    script(&binary, "exit 0");
    script(&root.path().join("test-systemctl"), "exit 0");
    let target = TargetConfig::Nginx {
        directory: root.path().into(),
        nginx_binary: binary.clone(),
        systemd_unit: "nginx.service".into(),
    };
    let (cert, key) = certificate(&["a.example.com"]);
    let (next, next_key) = certificate(&["a.example.com"]);
    deploy(&target, &request("one", 1, &cert, &key)).unwrap();
    let old = fs::read_link(root.path().join("current")).unwrap();
    script(&binary, "echo configuration-broken >&2; exit 9");
    let error = deploy(&target, &request("two", 2, &next, &next_key)).unwrap_err();
    assert!(format!("{error:#}").contains("rollback failed"));
    assert_eq!(fs::read_link(root.path().join("current")).unwrap(), old);
    assert!(state(&target).unwrap().pending.is_some());
    script(&binary, "exit 0");
    recover(&target).unwrap();
    assert!(deploy(&target, &request("two", 2, &cert, &key)).is_err());
    deploy(&target, &request("two", 2, &next, &next_key)).unwrap();
}
#[test]
fn reload_failure_initial_publication_and_recovery() {
    let root = dir();
    let binary = root.path().join("nginx");
    script(&binary, "exit 0");
    script(
        &root.path().join("test-systemctl"),
        "echo reload-broken >&2; exit 7",
    );
    let target = TargetConfig::Nginx {
        directory: root.path().into(),
        nginx_binary: binary,
        systemd_unit: "nginx.service".into(),
    };
    let (cert, key) = certificate(&["a.example.com"]);
    let error = deploy(&target, &request("one", 1, &cert, &key)).unwrap_err();
    assert!(format!("{error:#}").contains("reload-broken"));
    assert!(fs::symlink_metadata(root.path().join("current")).is_err());
    assert!(state(&target).unwrap().pending.is_some());
    script(&root.path().join("test-systemctl"), "exit 0");
    recover(&target).unwrap();
    deploy(&target, &request("one", 1, &cert, &key)).unwrap();
}
#[test]
fn discovered_nginx_site_is_configured_and_restored_on_reload_failure() {
    let root = dir();
    let binary = root.path().join("nginx");
    script(&binary, "exit 0");
    script(
        &root.path().join("test-systemctl"),
        "echo reload-broken >&2; exit 7",
    );
    let config_file = root.path().join("site.conf");
    let original = "server {\n    listen 80;\n    server_name a.example.com;\n}\n";
    fs::write(&config_file, original).unwrap();
    fs::set_permissions(&config_file, fs::Permissions::from_mode(0o600)).unwrap();
    let target = TargetConfig::NginxSite {
        directory: root.path().into(),
        nginx_binary: binary,
        systemd_unit: "nginx.service".into(),
        config_file: config_file.clone(),
        domains: vec!["a.example.com".into()],
    };
    let (cert, key) = certificate(&["a.example.com"]);
    assert!(deploy(&target, &request("one", 1, &cert, &key)).is_err());
    assert_eq!(fs::read_to_string(&config_file).unwrap(), original);
    assert!(!root.path().join("config-backup.json").exists());
}

#[test]
fn identical_certificate_repairs_drifted_site_configuration() {
    let root = dir();
    let binary = root.path().join("nginx");
    script(&binary, "exit 0");
    script(&root.path().join("test-systemctl"), "exit 0");
    let config_file = root.path().join("site.conf");
    let original = "server {\n    listen 80;\n    server_name a.example.com;\n}\n";
    fs::write(&config_file, original).unwrap();
    fs::set_permissions(&config_file, fs::Permissions::from_mode(0o600)).unwrap();
    let target = TargetConfig::NginxSite {
        directory: root.path().into(),
        nginx_binary: binary,
        systemd_unit: "nginx.service".into(),
        config_file: config_file.clone(),
        domains: vec!["a.example.com".into()],
    };
    let (cert, key) = certificate(&["a.example.com"]);
    deploy(&target, &request("one", 1, &cert, &key)).unwrap();
    fs::write(&config_file, original).unwrap();

    let outcome = deploy(&target, &request("two", 2, &cert, &key)).unwrap();

    assert!(!outcome.changed);
    assert!(
        fs::read_to_string(config_file)
            .unwrap()
            .contains("ssl_certificate ")
    );
}

#[test]
fn discovered_site_requires_certificate_to_cover_every_configured_domain() {
    let root = dir();
    let binary = root.path().join("nginx");
    script(&binary, "exit 0");
    let config_file = root.path().join("site.conf");
    fs::write(
        &config_file,
        "server { server_name a.example.com b.example.com; }\n",
    )
    .unwrap();
    fs::set_permissions(&config_file, fs::Permissions::from_mode(0o600)).unwrap();
    let target = TargetConfig::NginxSite {
        directory: root.path().into(),
        nginx_binary: binary,
        systemd_unit: "nginx.service".into(),
        config_file,
        domains: vec!["a.example.com".into(), "b.example.com".into()],
    };
    let (cert, key) = certificate(&["a.example.com"]);
    assert_eq!(
        classify(&deploy(&target, &request("one", 1, &cert, &key)).unwrap_err()),
        Failure::CertificateInvalid
    );
}

#[test]
fn interrupted_recovery_preserves_retry_metadata() {
    let root = dir();
    let target = TargetConfig::Files {
        directory: root.path().into(),
    };
    let (cert, key) = certificate(&["a.example.com"]);
    let result = deploy(&target, &request("one", 1, &cert, &key)).unwrap();
    let mut journal = state(&target).unwrap();
    journal.operations.get_mut("one").unwrap().committed = false;
    journal.pending = Some(Pending {
        operation_id: "one".into(),
        previous: None,
        next: PathBuf::from(format!("versions/{}", result.fingerprint)),
    });
    save(&target, &journal).unwrap();
    recover(&target).unwrap();
    assert!(fs::symlink_metadata(root.path().join("current")).is_err());
    assert!(state(&target).unwrap().operations.contains_key("one"));
    deploy(&target, &request("one", 1, &cert, &key)).unwrap();
}

#[test]
fn wildcard_request_and_typed_failures() {
    let root = dir();
    let target = TargetConfig::Files {
        directory: root.path().into(),
    };
    let (cert, key) = certificate(&["*.example.com"]);
    let mut req = request("wild", 1, &cert, &key);
    req.domain = "*.example.com";
    deploy(&target, &req).unwrap();
    let conflict = deploy(&target, &request("wild", 2, &cert, &key)).unwrap_err();
    assert_eq!(classify(&conflict), Failure::Conflict);
    assert_eq!(
        classify(&deploy(&target, &request("old", 1, &cert, &key)).unwrap_err()),
        Failure::StaleOperation
    );
    let (exact, exact_key) = certificate(&["a.example.com"]);
    assert!(certificate::validate("*.example.com", &exact, &exact_key).is_err());
    assert_eq!(
        classify(&deploy(&target, &request("bad", 2, &exact, &key)).unwrap_err()),
        Failure::CertificateInvalid
    );
}

#[test]
fn reload_failure_with_successful_rollback() {
    let root = dir();
    let binary = root.path().join("nginx");
    script(&binary, "exit 0");
    let ctl = root.path().join("test-systemctl");
    script(
        &ctl,
        "if [ -f \"$0.fail\" ]; then rm \"$0.fail\"; echo one-shot-failure >&2; exit 5; fi\nexit 0",
    );
    let target = TargetConfig::Nginx {
        directory: root.path().into(),
        nginx_binary: binary,
        systemd_unit: "nginx.service".into(),
    };
    let (cert, key) = certificate(&["a.example.com"]);
    deploy(&target, &request("one", 1, &cert, &key)).unwrap();
    let old = fs::read_link(root.path().join("current")).unwrap();
    let (next, next_key) = certificate(&["a.example.com"]);
    fs::write(root.path().join("test-systemctl.fail"), "").unwrap();
    let error = deploy(&target, &request("two", 2, &next, &next_key)).unwrap_err();
    assert_eq!(classify(&error), Failure::LocalPublishFailed);
    assert!(format!("{error:#}").contains("one-shot-failure"));
    assert_eq!(fs::read_link(root.path().join("current")).unwrap(), old);
    assert!(state(&target).unwrap().pending.is_none());
    deploy(&target, &request("two", 2, &next, &next_key)).unwrap();
}

#[test]
fn expired_issuer_is_rejected() {
    let ca_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let ca = make_cert(&ca_key, &["ca.example"], None, 0, 0);
    let leaf_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let leaf = make_cert(&leaf_key, &["a.example.com"], Some((&ca, &ca_key)), 0, 3);
    let chain = format!(
        "{}{}",
        String::from_utf8(leaf.to_pem().unwrap()).unwrap(),
        String::from_utf8(ca.to_pem().unwrap()).unwrap()
    );
    let key = String::from_utf8(leaf_key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    assert!(certificate::validate("a.example.com", &chain, &key).is_err());
}
