//! Minimal OpenSSH `~/.ssh/config` importer.
//!
//! Supports the directives that matter for connecting: Host, HostName, User,
//! Port, IdentityFile, ProxyJump. Ignores everything else.

use std::path::Path;

use crate::error::Result;
use crate::models::{new_id, now_ms, Host};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshConfigHost {
    pub patterns: Vec<String>,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_files: Vec<String>,
    pub proxy_jump: Option<String>,
}

/// Parse an ssh_config file. `~` is expanded when `home` is provided.
pub fn parse(content: &str, home: Option<&Path>) -> Vec<SshConfigHost> {
    let mut hosts: Vec<SshConfigHost> = Vec::new();
    for raw in content.lines() {
        let line = strip_comment(raw);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (key, rest) = match line.split_once(char::is_whitespace) {
            Some((k, r)) => (k, r.trim()),
            None => (line, ""),
        };
        let key = key.to_ascii_lowercase();
        match key.as_str() {
            "host" => {
                hosts.push(SshConfigHost {
                    patterns: rest.split_whitespace().map(expand_tilde_str).collect(),
                    ..Default::default()
                });
            }
            "hostname" => set_last(&mut hosts, |h| h.hostname = Some(rest.to_string())),
            "user" => set_last(&mut hosts, |h| h.user = Some(rest.to_string())),
            "port" => set_last(&mut hosts, |h| {
                if let Ok(p) = rest.parse() {
                    h.port = Some(p);
                }
            }),
            "identityfile" => set_last(&mut hosts, |h| {
                h.identity_files.push(expand_tilde(rest, home))
            }),
            "proxyjump" => set_last(&mut hosts, |h| h.proxy_jump = Some(rest.to_string())),
            _ => {}
        }
    }
    hosts
}

fn set_last<F: FnOnce(&mut SshConfigHost)>(hosts: &mut [SshConfigHost], f: F) {
    if let Some(last) = hosts.last_mut() {
        f(last);
    }
}

fn strip_comment(line: &str) -> &str {
    match line.split_once('#') {
        Some((before, _)) => before,
        None => line,
    }
}

fn expand_tilde_str(s: &str) -> String {
    s.to_string()
}

fn expand_tilde(s: &str, home: Option<&Path>) -> String {
    if let Some(rest) = s.strip_prefix("~/") {
        if let Some(h) = home {
            // Use '/' separators so the path is portable across host OSes.
            let base = h.to_string_lossy().trim_end_matches(['/', '\\']).to_string();
            return format!("{base}/{rest}");
        }
    }
    s.to_string()
}

/// Convert parsed ssh_config entries into Vera [`Host`] records. Wildcard
/// patterns (`*`, `?`) are skipped — they are match patterns, not real hosts.
pub fn into_hosts(parsed: &[SshConfigHost]) -> Vec<Host> {
    let mut out = Vec::new();
    for c in parsed {
        // Use the first concrete pattern as the label/hostname.
        let concrete = c.patterns.iter().find(|p| !p.contains('*') && !p.contains('?'));
        let Some(name) = concrete else { continue };
        let h = Host {
            id: new_id(),
            label: c.hostname.clone().unwrap_or_else(|| name.clone()),
            hostname: c.hostname.clone().unwrap_or_else(|| name.clone()),
            port: c.port.unwrap_or(22),
            username: c.user.clone().unwrap_or_else(|| "root".into()),
            updated_at: now_ms(),
            ..Default::default()
        };
        out.push(h);
    }
    out
}

/// Convenience: read a file and produce hosts. Missing file yields empty.
pub fn import_file(path: &Path, home: Option<&Path>) -> Result<Vec<Host>> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Ok(Vec::new()),
    };
    Ok(into_hosts(&parse(&content, home)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_config() {
        let cfg = r#"
# a comment
Host web
    HostName 10.0.0.5
    User deploy
    Port 2222

Host db
    HostName db.internal
    IdentityFile ~/.ssh/id_ed25519
"#;
        let parsed = parse(cfg, Some(Path::new("/home/u")));
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].hostname.as_deref(), Some("10.0.0.5"));
        assert_eq!(parsed[0].user.as_deref(), Some("deploy"));
        assert_eq!(parsed[0].port, Some(2222));
        assert_eq!(parsed[1].identity_files, vec!["/home/u/.ssh/id_ed25519".to_string()]);
    }

    #[test]
    fn skips_wildcards() {
        let cfg = "Host *\n    User me\nHost real\n    HostName r.example.com\n";
        let hosts = into_hosts(&parse(cfg, None));
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].hostname, "r.example.com");
    }
}
