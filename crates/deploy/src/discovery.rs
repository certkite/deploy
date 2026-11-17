use crate::{CERTIFICATE_ROOT, DiscoveredTarget, TargetConfig, command, paths, site};
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

const NGINX_UNIT: &str = "nginx.service";
const CADDY_UNIT: &str = "caddy.service";

pub(crate) fn discover() -> Result<Vec<DiscoveredTarget>> {
    ensure_certificate_root()?;
    let mut targets = Vec::new();
    if service_active(NGINX_UNIT)? {
        targets.extend(discover_nginx()?);
    }
    if service_active(CADDY_UNIT)? {
        targets.extend(discover_caddy()?);
    }
    targets.sort_by(|left, right| left.id.cmp(&right.id));
    ensure!(
        targets.len() <= 64,
        "more than 64 local deployment targets were discovered"
    );
    ensure!(
        targets.iter().all(|target| target.domains.len() <= 128),
        "a local deployment target has more than 128 domains"
    );
    let mut ids = BTreeSet::new();
    ensure!(
        targets.iter().all(|target| ids.insert(target.id.clone())),
        "discovered duplicate deployment target"
    );
    Ok(targets)
}

fn ensure_certificate_root() -> Result<()> {
    let root = Path::new(CERTIFICATE_ROOT);
    match fs::create_dir(root) {
        Ok(()) => {
            fs::set_permissions(root, fs::Permissions::from_mode(0o711))?;
            fs::File::open(root.parent().context("certificate root has no parent")?)?.sync_all()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(root)?;
    // SAFETY: geteuid has no arguments, pointer requirements or failure state.
    let effective_uid = unsafe { libc::geteuid() };
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == effective_uid
            && metadata.mode() & 0o777 == 0o711,
        "certificate root must be owned by the runtime user and mode 0711"
    );
    Ok(())
}

fn service_active(unit: &str) -> Result<bool> {
    Ok(command::capture(
        Path::new("/usr/bin/systemctl"),
        &["is-active", "--quiet", unit],
        Duration::from_secs(10),
        16 * 1024,
    )
    .with_context(|| format!("detect {unit}"))?
    .status
    .success())
}

fn executable(candidates: &[&str]) -> Result<PathBuf> {
    for candidate in candidates {
        let path = PathBuf::from(candidate);
        if path.exists() && command::binary(&path).is_ok() {
            return Ok(path);
        }
    }
    bail!("active service executable was not found in a trusted standard path")
}

fn output(binary: &Path, arguments: &[&str]) -> Result<String> {
    let output = command::capture(binary, arguments, Duration::from_secs(30), 16 * 1024 * 1024)
        .with_context(|| format!("inspect {} configuration", binary.display()))?;
    ensure!(
        output.status.success(),
        "{} configuration inspection failed: {}",
        binary.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut combined =
        String::from_utf8(output.stdout).context("configuration output is not UTF-8")?;
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(combined)
}

fn target_id(kind: &str, path: &Path, domains: &[String]) -> String {
    let mut digest = Sha256::new();
    digest.update(kind.as_bytes());
    digest.update([0]);
    digest.update(path.as_os_str().as_encoded_bytes());
    for domain in domains {
        digest.update([0]);
        digest.update(domain.as_bytes());
    }
    format!("{kind}-{}", &hex::encode(digest.finalize())[..24])
}

fn target_directory(id: &str) -> PathBuf {
    Path::new(CERTIFICATE_ROOT).join(id)
}

fn validate_config_file(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path)?;
    ensure!(
        metadata.is_file()
            && metadata.len() <= 1024 * 1024
            && metadata.nlink() == 1
            && metadata.uid() == paths::uid()
            && metadata.mode() & 0o022 == 0,
        "unsafe web-server configuration file: {}",
        path.display()
    );
    Ok(())
}

fn discover_nginx() -> Result<Vec<DiscoveredTarget>> {
    // shortcut: service binaries must use standard installation paths;
    // add validated systemd ExecStart parsing when custom binary paths are required.
    let binary = executable(&["/usr/sbin/nginx", "/usr/bin/nginx"])?;
    let dump = output(&binary, &["-T"])?;
    let mut files = BTreeSet::new();
    for line in dump.lines() {
        let Some(path) = line.strip_prefix("# configuration file ") else {
            continue;
        };
        let Some(path) = path.strip_suffix(':') else {
            continue;
        };
        let canonical = fs::canonicalize(path)
            .with_context(|| format!("resolve nginx configuration {path}"))?;
        files.insert(canonical);
    }
    let mut targets = Vec::new();
    for config_file in files {
        validate_config_file(&config_file)?;
        let source = fs::read_to_string(&config_file)
            .with_context(|| format!("read nginx configuration {}", config_file.display()))?;
        for discovered in site::nginx_sites(&source) {
            let id = target_id("nginx", &config_file, &discovered.domains);
            let config = TargetConfig::NginxSite {
                directory: target_directory(&id),
                nginx_binary: binary.clone(),
                systemd_unit: NGINX_UNIT.into(),
                config_file: config_file.clone(),
                domains: discovered.domains.clone(),
            };
            config.prepare()?;
            config.validate()?;
            targets.push(DiscoveredTarget {
                id,
                kind: "nginx",
                domains: discovered.domains,
                config,
            });
        }
    }
    Ok(targets)
}

fn discover_caddy() -> Result<Vec<DiscoveredTarget>> {
    // shortcut: automatic Caddy discovery supports the standard systemd Caddyfile path;
    // add ExecStart parsing when non-standard config locations are required.
    let binary = executable(&["/usr/bin/caddy", "/usr/local/bin/caddy"])?;
    let config_file = fs::canonicalize("/etc/caddy/Caddyfile")
        .context("active Caddy service requires /etc/caddy/Caddyfile")?;
    validate_config_file(&config_file)?;
    let source = fs::read_to_string(&config_file).context("read Caddyfile")?;
    // shortcut: site blocks must be declared directly in the main Caddyfile;
    // add import expansion when imported site definitions need automatic editing.
    let service_group = service_group(CADDY_UNIT)?;
    let mut targets = Vec::new();
    for discovered in site::caddy_sites(&source) {
        let id = target_id("caddy", &config_file, &discovered.domains);
        let config = TargetConfig::CaddySite {
            directory: target_directory(&id),
            caddy_binary: binary.clone(),
            systemd_unit: CADDY_UNIT.into(),
            config_file: config_file.clone(),
            domains: discovered.domains.clone(),
            service_group,
        };
        config.prepare()?;
        config.validate()?;
        targets.push(DiscoveredTarget {
            id,
            kind: "caddy",
            domains: discovered.domains,
            config,
        });
    }
    Ok(targets)
}

fn service_group(unit: &str) -> Result<u32> {
    let property = |name: &str| -> Result<String> {
        let property = format!("--property={name}");
        let output = command::capture(
            Path::new("/usr/bin/systemctl"),
            &["show", unit, &property, "--value"],
            Duration::from_secs(10),
            16 * 1024,
        )?;
        ensure!(
            output.status.success(),
            "cannot inspect {unit} service account"
        );
        Ok(String::from_utf8(output.stdout)?.trim().to_owned())
    };
    let group = property("Group")?;
    let user = property("User")?;
    let account = if group.is_empty() { &user } else { &group };
    ensure!(
        !account.is_empty(),
        "Caddy service must declare Group or User"
    );
    let output = command::capture(
        Path::new("/usr/bin/id"),
        &["-g", account],
        Duration::from_secs(5),
        16 * 1024,
    )?;
    ensure!(
        output.status.success(),
        "cannot resolve Caddy service group"
    );
    String::from_utf8(output.stdout)?
        .trim()
        .parse()
        .context("Caddy service group ID is invalid")
}
