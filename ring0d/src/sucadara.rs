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
    /// Literal `content:` signatures extracted from the Suricata ruleset,
    /// compiled into the userspace DPI engine (observe-only). (sid, pattern,
    /// severity).
    pub dpi_patterns: Vec<(u32, String, u8)>,
}

pub struct SyncReport {
    pub rules_parsed: usize,
    pub domains: usize,
    pub cidrs: usize,
    pub ports: usize,
    pub dpi_patterns: usize,
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
            dpi_patterns: 0,
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

/// Ceiling on literal content signatures promoted to the DPI engine from one
/// ruleset fetch. This is a RESOURCE guard only (compile time / hyperscan
/// memory), not a throughput or coverage cap: it never skips or queues
/// packets, and the full et-open ruleset (~28.5k unique literals) fits far
/// below this bound so every extractable signature is compiled.
const MAX_DPI_PATTERNS: usize = 65536;

/// Max bytes accepted from a blocklist feed. A hijacked or oversized feed
/// (e.g. oisd's multi-hundred-MB list) must not exhaust daemon memory (E10).
const MAX_FEED_BYTES: usize = 256 * 1024 * 1024;

async fn fetch_text(client: &reqwest::Client, url: &str) -> Option<String> {
    let resp = client.get(url).send().await.ok()?;
    if let Some(cl) = resp.content_length() {
        if cl > MAX_FEED_BYTES as u64 {
            warn!("feed {url}: content-length {cl} exceeds cap {MAX_FEED_BYTES} — skipping");
            return None;
        }
    }
    use futures_util::StreamExt;
    let mut body: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.ok()?;
        if body.len().saturating_add(chunk.len()) > MAX_FEED_BYTES {
            warn!("feed {url}: exceeded {MAX_FEED_BYTES} byte cap — aborting download");
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).ok()
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
///
/// CRITICAL SEMANTIC: only `drop`/`reject` rules may feed the kernel
/// blocklists. `alert` rules express detection intent — promoting their ports
/// into `BLOCKED_PORTS` previously made the kernel drop ALL traffic on common
/// ports (80/443/53/…) the moment the ET ruleset synced, a self-inflicted
/// connectivity outage.
/// Common Suricata port variables (ET/default fasttrack config). Rules use
/// `$HTTP_PORTS` etc. in place of literal port lists; resolving them lets the
/// port-blocklist catch rules that would otherwise contribute nothing.
fn port_var(name: &str) -> &'static [u16] {
    match name {
        "$HTTP_PORTS" | "$SHELLCODE_PORTS" => &[80, 8080, 443],
        "$FTP_PORTS" => &[21],
        "$SSH_PORTS" => &[22],
        "$SMTP_PORTS" => &[25, 465, 587],
        "$DNS_SERVERS" => &[53],
        "$MYSQL_PORTS" => &[3306],
        "$ORACLE_PORTS" => &[1521],
        "$MSSQL_PORTS" => &[1433, 1434],
        "$SIP_PORTS" => &[5060, 5061],
        "$RDP_PORTS" => &[3389],
        "$TELNET_PORTS" => &[23],
        "$POP3_PORTS" => &[110, 995],
        "$IMAP_PORTS" => &[143, 993],
        "$IKE_PORTS" => &[500, 4500],
        _ => &[],
    }
}

/// Extract blockable ports from a Suricata port token: a bare number, a
/// bracket list `[443,8443]`, a range `1024:65535` (blocked as a range is not
/// representable in the exact-port kernel map, so ranges are skipped), or a
/// known `$VAR`.
fn extract_ports_tokens(tok: &str, ports: &mut HashSet<u16>) {
    let tok = tok.trim();
    if tok.is_empty() || tok == "any" {
        return;
    }
    let inner = tok.trim_matches(['[', ']', '"']);
    for part in inner.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if part.starts_with('$') {
            for &p in port_var(part) {
                if is_blockable_port(p) {
                    ports.insert(p);
                }
            }
            continue;
        }
        if part.contains(':') {
            // Range (e.g. 1024:65535) — the exact-port kernel map cannot
            // represent it; skip rather than block one endpoint.
            continue;
        }
        if let Ok(p) = part.parse::<u16>() {
            if is_blockable_port(p) {
                ports.insert(p);
            }
        }
    }
}

/// Extract `sid:<n>;` from a rule; falls back to a FNV-derived id so
/// DPI matches always carry a stable-ish identifier.
fn extract_sid(line: &str) -> u32 {
    for (i, _) in line.match_indices("sid:") {
        let rest = &line[i + 4..];
        let end = rest.find(';').unwrap_or(rest.len());
        if let Ok(sid) = rest[..end].trim().parse::<u32>() {
            return sid;
        }
    }
    (fnv1a_hash(line) & 0xFFFF) as u32
}

/// First literal `content:"..."` pattern (no `|..|` hex escapes, length >= 4,
/// printable ASCII) plus whether the `nocase` modifier follows it. Returns
/// None when the rule's first content is hex-encoded or unsuitable.
fn first_literal_content(line: &str) -> Option<String> {
    for (m0, _) in line.match_indices("content:") {
        let rest = &line[m0 + 8..];
        let rest = rest.trim_start();
        if !rest.starts_with('"') {
            continue;
        }
        let q = &rest[1..];
        let end = q.find('"')?;
        let content = &q[..end];
        if content.contains('|')
            || content.len() < 4
            || content.bytes().any(|b| b < 0x20 || b == 0x7f || b == b'\\')
        {
            return None; // hex-encoded or regex-y literal — skip the rule
        }
        let tail = &q[end + 1..];
        let nocase = tail.starts_with(';') && tail[..tail.len().min(32)].contains("nocase");
        // Hyperscan compiles these as regexes, so regex metacharacters in the
        // literal must be escaped; `(?i)` encodes Suricata's `nocase` inline.
        let mut pattern = String::with_capacity(content.len() + 8);
        if nocase {
            pattern.push_str("(?i)");
        }
        for c in content.chars() {
            if "\\^$.|?*+()[]{}".contains(c) {
                pattern.push('\\');
            }
            pattern.push(c);
        }
        return Some(pattern);
    }
    None
}

fn parse_suricata_rule(
    line: &str,
    cidrs: &mut HashSet<(u32, u8)>,
    ports: &mut HashSet<u16>,
    domains: &mut HashSet<String>,
    patterns: &mut Vec<(u32, String, u8)>,
) -> bool {
    let line = line.trim();
    let enforce = line.starts_with("drop") || line.starts_with("reject");
    if !enforce && !line.starts_with("alert") {
        return false;
    }
    let sid = extract_sid(line);
    // Every rule contributes its first literal `content:` signature to the
    // DPI engine (observe-only detection), not just enforce rules.
    if let Some(pat) = first_literal_content(line) {
        if !patterns.iter().any(|(_, p, _)| p == &pat) {
            patterns.push((sid, pat, if enforce { 3 } else { 2 }));
        }
    }
    if !enforce {
        // Detection-only rule: nothing may be promoted to a kernel block map.
        return true;
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
    // Ports in the rule head: `-> $EXTERNAL_NET 443,8443 (msg:...` or
    // `-> $EXTERNAL_NET [443,8443,8080]` or `-> any [1024:65535]`.
    // Suricata allows bracket lists and ranges; bare variables ($HTTP_PORTS)
    // resolve through the small ET-default table below.
    if let Some(arrow) = line.find("->") {
        if let Some(paren) = line.find('(') {
            let head = &line[arrow + 2..paren];
            if let Some(last_tok) = head.split_whitespace().last() {
                extract_ports_tokens(last_tok, ports);
            }
        }
    }
    // Ports from dport:/sport: options.
    for opt in ["dport:", "sport:"] {
        if let Some(start) = line.find(opt) {
            let rest = &line[start + opt.len()..];
            let end = rest.find(';').unwrap_or(rest.len());
            extract_ports_tokens(&rest[..end], ports);
        }
    }
    // DNS domains from content:"..." on rules with the dns.query keyword.
    if line.contains("dns.query") || line.contains("content:") {
        for m in line.match_indices("content:") {
            let rest = &line[m.0 + 8..];
            if let Some(q) = rest.strip_prefix('"') {
                let end = q.find('"').unwrap_or(q.len());
                let content = &q[..end];
                // Reject hex-escaped (|..|), whitespace-containing, or
                // punctuation-laden literals — they are not domains and would
                // only poison the hash blocklist.
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

/// Ports that must never be kernel-blocked: the daemon's XDP path drops any
/// packet where EITHER endpoint uses a blocked port, so blocking common
/// service ports would disable the host's own connectivity (DNS, HTTPS, SSH…).
fn is_blockable_port(p: u16) -> bool {
    if p == 0 || p == 53 || p == 80 || p == 443 || p == 853 || p == 22 || p == 8080 || p == 8443 {
        return false;
    }
    !matches!(
        p,
        20 | 21 | 23 | 25 | 110 | 143 | 465 | 587 | 993 | 995 | 4433
    )
}

fn parse_suricata_ruleset(
    text: &str,
    cidrs: &mut HashSet<(u32, u8)>,
    ports: &mut HashSet<u16>,
    domains: &mut HashSet<String>,
    patterns: &mut Vec<(u32, String, u8)>,
) -> usize {
    let mut parsed = 0;
    for line in text.lines() {
        if parse_suricata_rule(line, cidrs, ports, domains, patterns) {
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
    let mut dpi_patterns: Vec<(u32, String, u8)> = Vec::new();
    let mut pattern_seen: HashSet<String> = HashSet::new();

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
                let mut ruleset_patterns = Vec::new();
                let n = parse_suricata_ruleset(
                    &text,
                    &mut cidrs,
                    &mut ports,
                    &mut domains,
                    &mut ruleset_patterns,
                );
                for (sid, pat, sev) in ruleset_patterns {
                    if pattern_seen.insert(pat.clone()) && dpi_patterns.len() < MAX_DPI_PATTERNS {
                        dpi_patterns.push((sid, pat, sev));
                    }
                }
                report.sources_ok += 1;
                report.rules_parsed += n;
                info!(
                    "[sucadara] {name}: parsed {n} rules → {} cidrs, {} ports, {} domains, {} dpi patterns",
                    cidrs.len(),
                    ports.len(),
                    domains.len(),
                    dpi_patterns.len()
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
    report.dpi_patterns = dpi_patterns.len();
    let payload = SyncPayload {
        cidrs: cidrs.into_iter().collect(),
        domains: domains.into_iter().collect(),
        ports: ports.into_iter().collect(),
        dpi_patterns,
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

    /// Simulate the (corrected) kernel DNS qname hasher from ring0-ebpf
    /// `dns_query_blocked`: the wire name `\x04evil\x03com\0` is hashed by
    /// synthesizing one '.' between labels, then FNV-1a over the lowercased
    /// bytes. This MUST produce the same values as `fnv1a_hash` on the same
    /// textual name — that is the parity contract the kernel fix restores.
    fn kernel_style_qname_hash(labels: &[&str]) -> u64 {
        let mut name = String::new();
        for (i, l) in labels.iter().enumerate() {
            if i > 0 {
                name.push('.');
            }
            name.push_str(l);
        }
        fnv1a_hash(&name)
    }

    #[test]
    fn fnv_parity_with_kernel_qname_hasher() {
        // Full name.
        assert_eq!(
            kernel_style_qname_hash(&["www", "evil", "com"]),
            fnv1a_hash("www.evil.com")
        );
        // Last-two-labels (what the kernel checks for "www.evil.com").
        assert_eq!(
            kernel_style_qname_hash(&["evil", "com"]),
            fnv1a_hash("evil.com")
        );
        // Last-three-labels for a ccTLD-style name.
        assert_eq!(
            kernel_style_qname_hash(&["example", "co", "uk"]),
            fnv1a_hash("example.co.uk")
        );
        // Case normalization on the wire must match the userspace lowercase.
        assert_eq!(
            kernel_style_qname_hash(&["WWW", "EVIL", "COM"]),
            fnv1a_hash("www.evil.com")
        );
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

    fn parse_with_patterns(
        rule: &str,
    ) -> (
        HashSet<(u32, u8)>,
        HashSet<u16>,
        HashSet<String>,
        Vec<(u32, String, u8)>,
    ) {
        let mut cidrs = HashSet::new();
        let mut ports = HashSet::new();
        let mut domains = HashSet::new();
        let mut patterns = Vec::new();
        parse_suricata_rule(rule, &mut cidrs, &mut ports, &mut domains, &mut patterns);
        (cidrs, ports, domains, patterns)
    }

    #[test]
    fn parses_suricata_rule_ip_port_domain() {
        let rule = r#"drop dns $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE CnC"; dns.query; content:"malware-c2.example"; nocase; classtype:trojan-activity; sid:2024242; rev:1;)"#;
        let (cidrs, ports, domains, patterns) = parse_with_patterns(rule);
        assert!(domains.contains("malware-c2.example"));
        // The content literal must also become a DPI pattern with the rule sid.
        assert!(patterns.iter().any(|(sid, _, _)| *sid == 2024242));
        // Regex metacharacters in the literal are escaped and nocase becomes (?i).
        assert!(patterns
            .iter()
            .any(|(_, p, _)| p.contains(r"malware-c2\.example") && p.starts_with("(?i)")));
        let _ = (cidrs, ports);
    }

    #[test]
    fn parses_suricata_rule_ports() {
        // A *drop* rule's blockable ports feed the blocklist…
        let drop_rule =
            "drop tcp $HOME_NET any -> $EXTERNAL_NET 4444,5555 (msg:\"test\"; sid:1; rev:1;)";
        let (_, ports, _, _) = parse_with_patterns(drop_rule);
        assert!(ports.contains(&4444));
        assert!(ports.contains(&5555));

        // …but an *alert* rule must NOT promote ports into kernel blocklists.
        let alert_rule =
            "alert tcp $HOME_NET any -> $EXTERNAL_NET 4444 (msg:\"test\"; sid:2; rev:1;)";
        let (_, ports, _, _) = parse_with_patterns(alert_rule);
        assert!(
            ports.is_empty(),
            "alert rules must not feed kernel blocklists"
        );

        // …and well-known service ports are never blockable even on drop rules.
        let dangerous = "drop tcp $HOME_NET any -> $EXTERNAL_NET 443,53,22 (msg:\"x\"; sid:3;)";
        let (_, ports, _, _) = parse_with_patterns(dangerous);
        assert!(ports.is_empty(), "well-known ports must be protected");
    }

    #[test]
    fn parses_bracket_and_variable_ports() {
        // Suricata bracket lists + ranges + variables.
        let (_, ports, _, _) = parse_with_patterns(
            "drop tcp any any -> any [4444,5555,6666:9999] (msg:\"x\"; sid:4;)",
        );
        assert!(ports.contains(&4444));
        assert!(ports.contains(&5555));
        assert!(
            !ports.contains(&6666),
            "ranges must be skipped, not blocked"
        );
        assert!(
            !ports.contains(&9999),
            "ranges must be skipped, not blocked"
        );

        let (_, ports, _, _) =
            parse_with_patterns("drop tcp any any -> any $MYSQL_PORTS (msg:\"x\"; sid:5;)");
        assert!(ports.contains(&3306));
    }

    #[test]
    fn extracts_dpi_content_patterns() {
        // Literal content becomes an escaped regex pattern; hex/too-short is skipped.
        let (_, _, _, patterns) = parse_with_patterns(
            "alert http any any -> any any (msg:\"x\"; content:\"GET /cgi-bin/\"; sid:10;)",
        );
        assert!(patterns.iter().any(|(_, p, _)| p == "GET /cgi-bin/"));
        let (_, _, _, patterns) = parse_with_patterns(
            "alert http any any -> any any (msg:\"x\"; content:\"|68 65 6c 6c 6f|\"; sid:11;)",
        );
        assert!(patterns.is_empty(), "hex-encoded content must be skipped");
        let (_, _, _, patterns) = parse_with_patterns(
            "alert http any any -> any any (msg:\"x\"; content:\"hi\"; sid:12;)",
        );
        assert!(
            patterns.is_empty(),
            "patterns shorter than 4 bytes must be skipped"
        );
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
