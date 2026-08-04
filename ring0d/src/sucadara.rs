//! Suricata-style rule ingestion + popular DNS/IP blocklist providers.
//!
//! Everything here is compiled down to kernel primitives (CIDRs, ports, hashed
//! domains) and synced into eBPF maps for sub-millisecond enforcement.

use std::collections::HashSet;

use tracing::{info, warn};

/// FNV-1a 64-bit — must match the kernel hash in ring0-ebpf.
pub fn fnv1a_hash(s: &str) -> u64 {
    let s = s.trim_end_matches('.');
    let mut h: u64 = 14695981039346656037;
    for b in s.bytes() {
        h ^= u64::from(b.to_ascii_lowercase());
        h = h.wrapping_mul(1099511628211);
    }
    h
}

/// Return the registrable domain (last two labels, or last three for
/// country-code TLDs such as `example.co.uk`).
pub fn registrable_domain(domain: &str) -> String {
    let d = domain.trim_end_matches('.').to_lowercase();
    let labels: Vec<&str> = d.split('.').collect();
    if labels.len() <= 2 {
        return d;
    }
    let tld = labels[labels.len() - 1];
    if tld.len() == 2 && labels.len() >= 3 {
        labels[labels.len() - 3..].join(".")
    } else {
        labels[labels.len() - 2..].join(".")
    }
}

pub struct SyncPayload {
    pub cidrs: Vec<(u32, u8)>,
    pub domains: Vec<String>,
    pub ports: Vec<u16>,
}

pub struct SyncReport {
    pub rules_parsed: usize,
    pub domains: usize,
    pub cidrs: usize,
    pub ports: usize,
    pub sources_ok: usize,
    pub sources_failed: usize,
}

impl SyncReport {
    fn new() -> Self {
        Self {
            rules_parsed: 0,
            domains: 0,
            cidrs: 0,
            ports: 0,
            sources_ok: 0,
            sources_failed: 0,
        }
    }
}

const DNS_PROVIDERS: &[(&str, &str)] = &[
    (
        "stevenblack",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    ),
    ("oisd", "https://big.oisd.nl/domainswild2"),
    (
        "firebog-tick",
        "https://v.firebog.net/hosts/lists?type=tick",
    ),
    ("urlhaus", "https://urlhaus.abuse.ch/downloads/hostfile/"),
];

const IP_PROVIDERS: &[(&str, &str)] = &[
    (
        "feodo",
        "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
    ),
    (
        "sslbl",
        "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
    ),
    ("spamhaus-drop", "https://www.spamhaus.org/drop/drop.txt"),
    (
        "et-compromised",
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    ),
];

const SURICATA_RULESETS: &[(&str, &str)] = &[(
    "et-open",
    "https://rules.emergingthreats.net/open/suricata-7.0/emerging-all.rules",
)];

async fn fetch_text(client: &reqwest::Client, url: &str) -> Option<String> {
    match client.get(url).send().await {
        Ok(resp) => match resp.text().await {
            Ok(t) => Some(t),
            Err(_) => None,
        },
        Err(_) => None,
    }
}

/// Parse a hosts-file style blocklist (lines like `0.0.0.0 domain` or bare domains).
fn parse_hosts(text: &str, domains: &mut HashSet<String>) -> usize {
    let mut n = 0;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let candidate = if line.contains(char::is_whitespace) {
            line.split_whitespace()
                .find(|tok| {
                    *tok != "0.0.0.0"
                        && *tok != "127.0.0.1"
                        && *tok != "::1"
                        && tok.contains('.')
                        && !tok.starts_with("0.")
                })
                .unwrap_or("")
        } else {
            line
        };
        let domain = candidate.trim_matches('.').to_lowercase();
        if domain.contains('.')
            && !domain
                .chars()
                .any(|c| c.is_whitespace() || c == '/' || c == ':')
        {
            domains.insert(registrable_domain(&domain));
            n += 1;
        }
    }
    n
}

/// Parse plain domain lists (one domain per line).
fn parse_domains(text: &str, domains: &mut HashSet<String>) -> usize {
    let mut n = 0;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let d = line.trim_matches('.').to_lowercase();
        if d.contains('.') && !d.chars().any(|c| c.is_whitespace() || c == '/' || c == ':') {
            domains.insert(registrable_domain(&d));
            n += 1;
        }
    }
    n
}

fn parse_ip_cidrs(text: &str, cidrs: &mut HashSet<(u32, u8)>) -> usize {
    let mut n = 0;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let line = line.split(';').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some((ip_str, prefix)) = line.split_once('/') {
            if let Ok(ip) = ip_str.trim().parse::<std::net::Ipv4Addr>() {
                if let Ok(p) = prefix.trim().parse::<u8>() {
                    if (1..=32).contains(&p) {
                        cidrs.insert((u32::from(ip), p));
                        n += 1;
                    }
                }
            }
        } else if let Ok(ip) = line.parse::<std::net::Ipv4Addr>() {
            // Spamhaus DROP uses CIDR; bare IPs are treated as /32.
            let first = u32::from(ip).to_be();
            if first & 0xff000000 != 0x7f000000 {
                cidrs.insert((u32::from(ip), 32));
                n += 1;
            }
        }
    }
    n
}

/// Parse a Suricata/ET rule line, extracting kernel-primitive constraints.
fn parse_suricata_rule(
    line: &str,
    cidrs: &mut HashSet<(u32, u8)>,
    ports: &mut HashSet<u16>,
    domains: &mut HashSet<String>,
) -> bool {
    let line = line.trim();
    if !line.starts_with("alert") && !line.starts_with("drop") && !line.starts_with("reject") {
        return false;
    }
    // IPv4 CIDRs from ip:/srcip:/dstip: options.
    for opt in ["ip:", "srcip:", "dstip:"] {
        if let Some(start) = line.find(opt) {
            let rest = &line[start + opt.len()..];
            let end = rest.find(';').unwrap_or(rest.len());
            for tok in rest[..end].split(',') {
                let tok = tok.trim().trim_matches(['[', ']', '"']);
                if let Some((ip, prefix)) = tok.split_once('/') {
                    if let Ok(ip) = ip.parse::<std::net::Ipv4Addr>() {
                        if let Ok(p) = prefix.parse::<u8>() {
                            cidrs.insert((u32::from(ip), p));
                        }
                    }
                }
            }
        }
    }
    // Ports in the rule head: `-> $EXTERNAL_NET 443,8443 (msg:...`
    if let Some(arrow) = line.find("->") {
        if let Some(paren) = line.find('(') {
            let head = &line[arrow + 2..paren];
            if let Some(last_tok) = head.split_whitespace().last() {
                for tok in last_tok.split(',') {
                    let tok = tok.trim();
                    if let Ok(p) = tok.parse::<u16>() {
                        if p > 0 {
                            ports.insert(p);
                        }
                    }
                }
            }
        }
    }
    // Ports from dport:/sport: options.
    for opt in ["dport:", "sport:"] {
        if let Some(start) = line.find(opt) {
            let rest = &line[start + opt.len()..];
            let end = rest.find(';').unwrap_or(rest.len());
            for tok in rest[..end].split(',') {
                let tok = tok.trim().trim_matches(['[', ']', '"']);
                if let Ok(p) = tok.parse::<u16>() {
                    if p > 0 {
                        ports.insert(p);
                    }
                }
            }
        }
    }
    // DNS domains from content:"..." on rules with the dns.query keyword.
    if line.contains("dns.query") || line.contains("content:") {
        for m in line.match_indices("content:") {
            let rest = &line[m.0 + 8..];
            if let Some(q) = rest.strip_prefix('"') {
                let end = q.find('"').unwrap_or(q.len());
                let content = &q[..end];
                // A domain-looking literal (contains a dot, letters/digits/hyphen/underscore).
                let is_domain = content.contains('.')
                    && content
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_');
                if is_domain {
                    domains.insert(registrable_domain(content));
                }
            }
        }
    }
    true
}

fn parse_suricata_ruleset(
    text: &str,
    cidrs: &mut HashSet<(u32, u8)>,
    ports: &mut HashSet<u16>,
    domains: &mut HashSet<String>,
) -> usize {
    let mut parsed = 0;
    for line in text.lines() {
        if parse_suricata_rule(line, cidrs, ports, domains) {
            parsed += 1;
        }
    }
    parsed
}

/// Fetch all providers + rulesets and build the kernel sync payload.
pub async fn fetch_all() -> (SyncReport, SyncPayload) {
    let mut report = SyncReport::new();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("Ring0-Sucadara/1.0")
        .build()
        .unwrap_or_default();

    let mut domains: HashSet<String> = HashSet::new();
    let mut cidrs: HashSet<(u32, u8)> = HashSet::new();
    let mut ports: HashSet<u16> = HashSet::new();

    // ── DNS blocklist providers ──
    for (name, url) in DNS_PROVIDERS {
        match fetch_text(&client, url).await {
            Some(text) => {
                let n = if *name == "oisd" {
                    parse_domains(&text, &mut domains)
                } else {
                    parse_hosts(&text, &mut domains)
                };
                report.sources_ok += 1;
                info!("[blocklist] {name}: {n} domains");
            }
            None => {
                report.sources_failed += 1;
                warn!("[blocklist] {name}: fetch failed");
            }
        }
    }

    // ── IP blocklist providers ──
    for (name, url) in IP_PROVIDERS {
        match fetch_text(&client, url).await {
            Some(text) => {
                let n = parse_ip_cidrs(&text, &mut cidrs);
                report.sources_ok += 1;
                info!("[blocklist] {name}: {n} CIDRs");
            }
            None => {
                report.sources_failed += 1;
                warn!("[blocklist] {name}: fetch failed");
            }
        }
    }

    // ── Suricata / ET rulesets ──
    for (name, url) in SURICATA_RULESETS {
        match fetch_text(&client, url).await {
            Some(text) => {
                let n = parse_suricata_ruleset(&text, &mut cidrs, &mut ports, &mut domains);
                report.sources_ok += 1;
                report.rules_parsed += n;
                info!(
                    "[sucadara] {name}: parsed {n} rules → {} cidrs, {} ports, {} domains",
                    cidrs.len(),
                    ports.len(),
                    domains.len()
                );
            }
            None => {
                report.sources_failed += 1;
                warn!("[sucadara] {name}: fetch failed");
            }
        }
    }

    report.domains = domains.len();
    report.cidrs = cidrs.len();
    report.ports = ports.len();
    let payload = SyncPayload {
        cidrs: cidrs.into_iter().collect(),
        domains: domains.into_iter().collect(),
        ports: ports.into_iter().collect(),
    };
    (report, payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv_hash_is_stable() {
        // The kernel computes FNV-1a over the lowercased name including dots.
        let h = fnv1a_hash("evil.com");
        assert_eq!(h, fnv1a_hash("EVIL.COM"), "hash must be case-insensitive");
        assert_eq!(h, fnv1a_hash("evil.com."), "trailing dot must be stripped");
        assert_ne!(h, fnv1a_hash("notevil.com"));
    }

    #[test]
    fn registrable_domain_strips_subdomains() {
        assert_eq!(registrable_domain("www.evil.com"), "evil.com");
        assert_eq!(registrable_domain("a.b.c.example.co.uk"), "example.co.uk");
        assert_eq!(registrable_domain("evil.com"), "evil.com");
    }

    #[test]
    fn parses_hosts_format() {
        let text =
            "# comment\n0.0.0.0 evil.com\n127.0.0.1 tracker.example.org\n0.0.0.0 127.0.0.1\n";
        let mut domains = HashSet::new();
        parse_hosts(text, &mut domains);
        assert!(domains.contains("evil.com"));
        assert!(domains.contains("example.org"));
        assert!(!domains.contains("127.0.0.1"));
    }

    #[test]
    fn parses_suricata_rule_ip_port_domain() {
        let rule = r#"alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE CnC"; dns.query; content:"malware-c2.example"; nocase; classtype:trojan-activity; sid:2024242; rev:1;)"#;
        let mut cidrs = HashSet::new();
        let mut ports = HashSet::new();
        let mut domains = HashSet::new();
        assert!(parse_suricata_rule(
            rule,
            &mut cidrs,
            &mut ports,
            &mut domains
        ));
        assert!(domains.contains("malware-c2.example"));
    }

    #[test]
    fn parses_suricata_rule_ports() {
        let rule =
            "alert tcp $HOME_NET any -> $EXTERNAL_NET 443,8443 (msg:\"test\"; sid:1; rev:1;)";
        let mut cidrs = HashSet::new();
        let mut ports = HashSet::new();
        let mut domains = HashSet::new();
        parse_suricata_rule(rule, &mut cidrs, &mut ports, &mut domains);
        assert!(ports.contains(&443));
        assert!(ports.contains(&8443));
    }

    #[test]
    fn parses_ip_cidr_list() {
        let text = "1.2.3.0/24\n5.6.7.8\n# comment\n";
        let mut cidrs = HashSet::new();
        parse_ip_cidrs(text, &mut cidrs);
        assert!(cidrs.contains(&(0x01020300, 24)));
        assert!(cidrs.contains(&(0x05060708, 32)));
    }
}
