use anyhow::{Result, bail, ensure};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Site {
    pub start: usize,
    pub end: usize,
    pub domains: Vec<String>,
}

#[derive(Debug, Clone)]
struct Token {
    value: String,
    start: usize,
    end: usize,
}

fn tokens(source: &str) -> Vec<Token> {
    let bytes = source.as_bytes();
    let mut result = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b if b.is_ascii_whitespace() => index += 1,
            b'#' => {
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b'{' | b'}' | b';' => {
                result.push(Token {
                    value: (bytes[index] as char).to_string(),
                    start: index,
                    end: index + 1,
                });
                index += 1;
            }
            b'\'' | b'"' => {
                let start = index;
                let quote = bytes[index];
                index += 1;
                let content = index;
                while index < bytes.len() {
                    if bytes[index] == b'\\' {
                        index = (index + 2).min(bytes.len());
                    } else if bytes[index] == quote {
                        break;
                    } else {
                        index += 1;
                    }
                }
                let end_content = index;
                if index < bytes.len() {
                    index += 1;
                }
                result.push(Token {
                    value: source[content..end_content].to_owned(),
                    start,
                    end: index,
                });
            }
            _ => {
                let start = index;
                while index < bytes.len()
                    && !bytes[index].is_ascii_whitespace()
                    && !matches!(bytes[index], b'{' | b'}' | b';' | b'#')
                {
                    index += 1;
                }
                result.push(Token {
                    value: source[start..index].to_owned(),
                    start,
                    end: index,
                });
            }
        }
    }
    result
}

fn normalized_domain(value: &str) -> Option<String> {
    let mut value = value
        .trim()
        .trim_end_matches('.')
        .trim_end_matches(',')
        .to_ascii_lowercase();
    if let Some((_, host)) = value.split_once("://") {
        value = host.to_owned();
    }
    if value.starts_with('[') {
        if let Some(end) = value.find(']') {
            value = value[1..end].to_owned();
        }
    } else if let Some((host, port)) = value.rsplit_once(':')
        && port.bytes().all(|byte| byte.is_ascii_digit())
    {
        value = host.to_owned();
    }
    if value.is_empty()
        || value.len() > 253
        || !value.is_ascii()
        || value == "_"
        || value.starts_with('~')
        || value.contains('$')
        || value.contains('/')
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return None;
    }
    Some(value)
}

fn sorted_domains(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut values: Vec<_> = values.into_iter().collect();
    values.sort();
    values.dedup();
    values
}

fn normalized_nginx_domains(value: &str) -> Vec<String> {
    let Some(domain) = normalized_domain(value) else {
        return Vec::new();
    };
    match domain.strip_prefix('.') {
        Some(root) if !root.is_empty() => vec![root.to_owned(), format!("*.{root}")],
        _ => vec![domain],
    }
}

pub(crate) fn nginx_sites(source: &str) -> Vec<Site> {
    let tokens = tokens(source);
    let mut result = Vec::new();
    let mut index = 0;
    while index + 1 < tokens.len() {
        if tokens[index].value != "server" || tokens[index + 1].value != "{" {
            index += 1;
            continue;
        }
        let open = index + 1;
        let mut depth = 1usize;
        let mut close = None;
        let mut cursor = open + 1;
        while cursor < tokens.len() {
            match tokens[cursor].value.as_str() {
                "{" => depth += 1,
                "}" => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(cursor);
                        break;
                    }
                }
                _ => {}
            }
            cursor += 1;
        }
        let Some(close) = close else { break };
        let domains = nginx_directives(&tokens, open, close)
            .into_iter()
            .filter(|directive| directive.name == "server_name")
            .flat_map(|directive| directive.args)
            .flat_map(|domain| normalized_nginx_domains(&domain))
            .collect::<Vec<_>>();
        let domains = sorted_domains(domains);
        if !domains.is_empty() {
            result.push(Site {
                start: tokens[index].start,
                end: tokens[close].start,
                domains,
            });
        }
        index = close + 1;
    }
    result
}

#[derive(Debug)]
struct Directive {
    name: String,
    args: Vec<String>,
    start: usize,
    end: usize,
}

fn nginx_directives(tokens: &[Token], open: usize, close: usize) -> Vec<Directive> {
    let mut result = Vec::new();
    let mut depth = 1usize;
    let mut index = open + 1;
    while index < close {
        match tokens[index].value.as_str() {
            "{" => {
                depth += 1;
                index += 1;
            }
            "}" => {
                depth = depth.saturating_sub(1);
                index += 1;
            }
            _ if depth != 1 => index += 1,
            ";" => index += 1,
            _ => {
                let start = index;
                let mut end = index;
                while end < close && tokens[end].value != ";" && tokens[end].value != "{" {
                    end += 1;
                }
                if end < close && tokens[end].value == ";" {
                    result.push(Directive {
                        name: tokens[start].value.clone(),
                        args: tokens[start + 1..end]
                            .iter()
                            .map(|token| token.value.clone())
                            .collect(),
                        start: tokens[start].start,
                        end: tokens[end].end,
                    });
                    index = end + 1;
                } else {
                    index += 1;
                }
            }
        }
    }
    result
}

fn indentation(source: &str, position: usize) -> String {
    let line_start = source[..position].rfind('\n').map_or(0, |value| value + 1);
    let closing = &source[line_start..position];
    format!(
        "{}    ",
        closing
            .chars()
            .take_while(|char| char.is_whitespace())
            .collect::<String>()
    )
}

pub(crate) fn configure_nginx(
    source: &str,
    expected_domains: &[String],
    certificate: &Path,
    private_key: &Path,
) -> Result<String> {
    let sites = nginx_sites(source);
    let matches: Vec<_> = sites
        .iter()
        .filter(|site| site.domains == expected_domains)
        .collect();
    ensure!(
        matches.len() == 1,
        "nginx site configuration changed or is ambiguous"
    );
    let site = matches[0];
    let all = tokens(source);
    let open = all
        .iter()
        .position(|token| token.start >= site.start && token.value == "{")
        .ok_or_else(|| anyhow::anyhow!("nginx server block is malformed"))?;
    let close = all
        .iter()
        .position(|token| token.start == site.end && token.value == "}")
        .ok_or_else(|| anyhow::anyhow!("nginx server block is malformed"))?;
    let directives = nginx_directives(&all, open, close);
    let indent = indentation(source, site.end);
    let certificate = certificate.display();
    let private_key = private_key.display();
    let mut replacements: Vec<(usize, usize, String)> = Vec::new();
    let mut has_certificate = false;
    let mut has_private_key = false;
    let mut has_port_443_listener = false;
    for directive in directives {
        match directive.name.as_str() {
            "ssl_certificate" => {
                has_certificate = true;
                replacements.push((
                    directive.start,
                    directive.end,
                    format!("ssl_certificate {certificate};"),
                ));
            }
            "ssl_certificate_key" => {
                has_private_key = true;
                replacements.push((
                    directive.start,
                    directive.end,
                    format!("ssl_certificate_key {private_key};"),
                ));
            }
            "listen" => {
                let port_443 = directive
                    .args
                    .iter()
                    .any(|arg| arg == "443" || arg.ends_with(":443") || arg.contains(":443]"));
                if port_443 {
                    has_port_443_listener = true;
                    if !directive.args.iter().any(|arg| arg == "ssl") {
                        let original = source[directive.start..directive.end]
                            .trim_end_matches(';')
                            .trim_end();
                        replacements.push((
                            directive.start,
                            directive.end,
                            format!("{original} ssl;"),
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    let mut additions = Vec::new();
    if !has_port_443_listener {
        additions.push(format!("{indent}listen 443 ssl;"));
    }
    if !has_certificate {
        additions.push(format!("{indent}ssl_certificate {certificate};"));
    }
    if !has_private_key {
        additions.push(format!("{indent}ssl_certificate_key {private_key};"));
    }
    if !additions.is_empty() {
        replacements.push((site.end, site.end, format!("{}\n", additions.join("\n"))));
    }
    replacements.sort_by_key(|replacement| std::cmp::Reverse(replacement.0));
    let mut configured = source.to_owned();
    for (start, end, replacement) in replacements {
        configured.replace_range(start..end, &replacement);
    }
    Ok(configured)
}

pub(crate) fn caddy_sites(source: &str) -> Vec<Site> {
    let bytes = source.as_bytes();
    let mut result = Vec::new();
    let mut depth = 0usize;
    let mut index = 0usize;
    let mut line_start = 0usize;
    let mut quote = None;
    let mut escaped = false;
    let mut comment = false;
    let mut current: Option<(usize, Vec<String>)> = None;
    while index < bytes.len() {
        let byte = bytes[index];
        if comment {
            if byte == b'\n' {
                comment = false;
                line_start = index + 1;
            }
            index += 1;
            continue;
        }
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == active_quote {
                quote = None;
            }
            index += 1;
            continue;
        }
        match byte {
            b'#' => comment = true,
            b'\'' | b'"' => quote = Some(byte),
            b'\n' => line_start = index + 1,
            b'{' => {
                if depth == 0 {
                    let header = source[line_start..index].trim();
                    if !header.is_empty() && !header.starts_with('(') {
                        let domains = sorted_domains(
                            header
                                .split(|char: char| char.is_whitespace() || char == ',')
                                .filter(|address| !address.starts_with("http://"))
                                .filter_map(normalized_domain),
                        );
                        if !domains.is_empty() {
                            current = Some((line_start, domains));
                        }
                    }
                }
                depth += 1;
            }
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0
                    && let Some((start, domains)) = current.take()
                {
                    result.push(Site {
                        start,
                        end: index,
                        domains,
                    });
                }
            }
            _ => {}
        }
        index += 1;
    }
    result
}

pub(crate) fn configure_caddy(
    source: &str,
    expected_domains: &[String],
    certificate: &Path,
    private_key: &Path,
) -> Result<String> {
    let sites = caddy_sites(source);
    let matches: Vec<_> = sites
        .iter()
        .filter(|site| site.domains == expected_domains)
        .collect();
    ensure!(
        matches.len() == 1,
        "Caddy site configuration changed or is ambiguous"
    );
    let site = matches[0];
    let body_start = source[site.start..site.end]
        .find('{')
        .map(|position| site.start + position + 1)
        .ok_or_else(|| anyhow::anyhow!("Caddy site block is malformed"))?;
    let mut depth = 1usize;
    let mut offset = body_start;
    let mut replacement = None;
    for line in source[body_start..site.end].split_inclusive('\n') {
        let trimmed = line.trim();
        if depth == 1 && (trimmed == "tls" || trimmed.starts_with("tls ")) {
            if trimmed.contains('{') {
                bail!("complex Caddy tls blocks require manual configuration");
            }
            let indent: String = line
                .chars()
                .take_while(|char| char.is_whitespace())
                .collect();
            replacement = Some((
                offset,
                offset + line.trim_end_matches('\n').len(),
                format!(
                    "{indent}tls {} {}",
                    certificate.display(),
                    private_key.display()
                ),
            ));
            break;
        }
        depth += line.bytes().filter(|byte| *byte == b'{').count();
        depth = depth.saturating_sub(line.bytes().filter(|byte| *byte == b'}').count());
        offset += line.len();
    }
    let mut configured = source.to_owned();
    if let Some((start, end, value)) = replacement {
        configured.replace_range(start..end, &value);
    } else {
        let indent = indentation(source, site.end);
        configured.insert_str(
            site.end,
            &format!(
                "{indent}tls {} {}\n",
                certificate.display(),
                private_key.display()
            ),
        );
    }
    Ok(configured)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nginx_discovers_and_configures_matching_server() {
        let source = "http {\n server {\n  listen 80;\n  server_name example.com www.example.com;\n  location / { return 200; }\n }\n}\n";
        let sites = nginx_sites(source);
        assert_eq!(sites[0].domains, ["example.com", "www.example.com"]);
        let configured = configure_nginx(
            source,
            &sites[0].domains,
            Path::new("/cert/current/fullchain.pem"),
            Path::new("/cert/current/privkey.pem"),
        )
        .unwrap();
        assert!(configured.contains("listen 443 ssl;"));
        assert!(configured.contains("ssl_certificate /cert/current/fullchain.pem;"));
        assert!(configured.contains("ssl_certificate_key /cert/current/privkey.pem;"));
    }

    #[test]
    fn caddy_discovers_and_configures_matching_site() {
        let source = "example.com, www.example.com {\n    reverse_proxy localhost:3000\n}\n";
        let sites = caddy_sites(source);
        assert_eq!(sites[0].domains, ["example.com", "www.example.com"]);
        let configured = configure_caddy(
            source,
            &sites[0].domains,
            Path::new("/cert/current/fullchain.pem"),
            Path::new("/cert/current/privkey.pem"),
        )
        .unwrap();
        assert!(configured.contains("tls /cert/current/fullchain.pem /cert/current/privkey.pem"));
        assert!(caddy_sites("http://plain.example.com { respond ok }").is_empty());
    }

    #[test]
    fn nginx_replaces_existing_certificate_paths_without_duplicates() {
        let source = "server {\n listen 443 ssl;\n server_name example.com;\n ssl_certificate /old/cert.pem;\n ssl_certificate_key /old/key.pem;\n}\n";
        let configured = configure_nginx(
            source,
            &["example.com".into()],
            Path::new("/new/fullchain.pem"),
            Path::new("/new/privkey.pem"),
        )
        .unwrap();
        assert_eq!(configured.matches("ssl_certificate ").count(), 1);
        assert_eq!(configured.matches("ssl_certificate_key ").count(), 1);
        assert!(!configured.contains("/old/"));
    }

    #[test]
    fn nginx_enables_tls_on_every_443_listener() {
        let source = "server {\n listen 443;\n listen [::]:443;\n server_name example.com;\n}\n";
        let configured = configure_nginx(
            source,
            &["example.com".into()],
            Path::new("/cert.pem"),
            Path::new("/key.pem"),
        )
        .unwrap();
        assert!(configured.contains("listen 443 ssl;"));
        assert!(configured.contains("listen [::]:443 ssl;"));
    }

    #[test]
    fn nginx_expands_leading_dot_server_names() {
        let sites = nginx_sites("server { server_name .example.com; }");
        assert_eq!(sites[0].domains, ["*.example.com", "example.com"]);
    }

    #[test]
    fn ambiguous_sites_and_complex_caddy_tls_are_rejected() {
        let nginx = "server { server_name example.com; }\nserver { server_name example.com; }\n";
        assert!(
            configure_nginx(
                nginx,
                &["example.com".into()],
                Path::new("/cert.pem"),
                Path::new("/key.pem")
            )
            .is_err()
        );
        let caddy = "example.com {\n tls {\n  protocols tls1.3\n }\n}\n";
        assert!(
            configure_caddy(
                caddy,
                &["example.com".into()],
                Path::new("/cert.pem"),
                Path::new("/key.pem")
            )
            .is_err()
        );
    }
}
