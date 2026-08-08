use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::Arc;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use parking_lot::RwLock;
use tracing::{info, warn};

const THREAT_FEEDS: &[(&str, &str)] = &[
    (
        "c2-domains",
        "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s.txt",
    ),
    (
        "ransomware",
        "https://raw.githubusercontent.com/blacklist/Lists/master/ransomware-domains.txt",
    ),
    (
        "phishing",
        "https://raw.githubusercontent.com/xRuffKez/NEW-Phish-Domains/main/domainlist.txt",
    ),
    (
        "malware",
        "https://raw.githubusercontent.com/elliotwutingfeng/GlobalAntiScan/master/domains.txt",
    ),
];

pub struct ThreatBlocklist {
    domains: Arc<RwLock<HashSet<String>>>,
    ac_matcher: Arc<RwLock<Option<AhoCorasick>>>,
    feed_stats: Arc<RwLock<HashMap<String, FeedStat>>>,
    last_sync: Arc<RwLock<String>>,
    ports: Arc<RwLock<HashSet<u16>>>,
}

struct FeedStat {
    total: u32,
    added: u32,
    error: String,
}

impl ThreatBlocklist {
    pub fn new() -> Self {
        Self {
            domains: Arc::new(RwLock::new(HashSet::new())),
            ac_matcher: Arc::new(RwLock::new(None)),
            feed_stats: Arc::new(RwLock::new(HashMap::new())),
            last_sync: Arc::new(RwLock::new("Never".into())),
            ports: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    pub fn check_ports(&self, src: u16, dst: u16) -> bool {
        let ports = self.ports.read();
        ports.contains(&src) || ports.contains(&dst)
    }

    pub fn block_port(&self, port: u16) {
        self.ports.write().insert(port);
    }

    pub fn unblock_port(&self, port: u16) {
        self.ports.write().remove(&port);
    }

    pub fn port_count(&self) -> usize {
        self.ports.read().len()
    }

    pub async fn sync_all_feeds(&self) -> usize {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("Ring0-ThreatBlocklist/1.0")
            .build()
            .unwrap_or_default();

        let mut all_domains: HashSet<String> = HashSet::new();
        let mut stats = HashMap::new();

        for (name, url) in THREAT_FEEDS {
            let result = self.sync_single_feed(&client, name, url).await;
            let (added, total, err) = match result {
                Ok(domains) => {
                    let count = domains.len();
                    for d in &domains {
                        all_domains.insert(d.clone());
                    }
                    (count as u32, count as u32, String::new())
                }
                Err(e) => (0u32, 0u32, e),
            };
            stats.insert(
                name.to_string(),
                FeedStat {
                    total,
                    added,
                    error: err,
                },
            );
            info!("ThreatBlocklist: feed {name}: +{added} domains (total {total})");
        }

        let before = self.domains.read().len();
        *self.domains.write() = all_domains.clone();
        *self.feed_stats.write() = stats;
        *self.last_sync.write() = chrono::Utc::now().to_rfc3339();

        self.rebuild_ac_matcher();

        let count = all_domains.len();
        info!(
            "ThreatBlocklist: {count} total domains ({})",
            count.saturating_sub(before)
        );
        count
    }

    async fn sync_single_feed(
        &self,
        client: &reqwest::Client,
        _name: &str,
        url: &str,
    ) -> Result<Vec<String>, String> {
        const MAX_FEED_BYTES: usize = 128 * 1024 * 1024;
        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("HTTP: {e}"))?;
        // E10: cap the downloaded body so a hostile/hijacked feed cannot
        // exhaust daemon memory.
        if let Some(cl) = resp.content_length() {
            if cl > MAX_FEED_BYTES as u64 {
                return Err(format!("feed too large: {cl} bytes"));
            }
        }
        use futures_util::StreamExt;
        let mut body: Vec<u8> = Vec::new();
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| format!("Body: {e}"))?;
            if body.len().saturating_add(chunk.len()) > MAX_FEED_BYTES {
                return Err("feed exceeds size cap".into());
            }
            body.extend_from_slice(&chunk);
        }
        let body = String::from_utf8_lossy(&body).into_owned();

        let mut domains = Vec::new();
        for line in body.lines() {
            let t = line.trim().to_lowercase();
            if t.is_empty() || t.starts_with('#') || t.starts_with("//") {
                continue;
            }
            let cleaned = t.trim_end_matches('.').to_string();
            if cleaned.contains('.') && !cleaned.contains(' ') && !cleaned.contains('/') {
                domains.push(cleaned);
            }
        }
        Ok(domains)
    }

    fn rebuild_ac_matcher(&self) {
        let domains = self.domains.read();
        let patterns: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();
        if patterns.is_empty() {
            *self.ac_matcher.write() = None;
            return;
        }
        match AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(&patterns)
        {
            Ok(ac) => {
                *self.ac_matcher.write() = Some(ac);
                info!(
                    "ThreatBlocklist: rebuilt Aho-Corasick matcher with {} patterns",
                    patterns.len()
                );
            }
            Err(e) => warn!("ThreatBlocklist: Aho-Corasick build failed: {e}"),
        }
    }

    pub fn check_domain(&self, domain: &str) -> bool {
        let lower = domain.to_lowercase();
        let domains = self.domains.read();
        if domains.contains(&lower) {
            return true;
        }
        let matcher = self.ac_matcher.read();
        if let Some(ref ac) = *matcher {
            ac.is_match(&lower)
        } else {
            false
        }
    }

    pub fn domain_count(&self) -> usize {
        self.domains.read().len()
    }

    pub fn feed_stats(&self) -> Vec<(String, u32, u32, String)> {
        let stats = self.feed_stats.read();
        stats
            .iter()
            .map(|(k, v)| (k.clone(), v.total, v.added, v.error.clone()))
            .collect()
    }

    pub fn last_sync(&self) -> String {
        self.last_sync.read().clone()
    }

    pub fn load_local_file(&self, path: &str) -> usize {
        let p = Path::new(path);
        if !p.exists() {
            return 0;
        }
        let content = match fs::read_to_string(p) {
            Ok(c) => c,
            Err(e) => {
                warn!("ThreatBlocklist: cannot read {path}: {e}");
                return 0;
            }
        };
        let mut count = 0usize;
        {
            let mut domains = self.domains.write();
            for line in content.lines() {
                let t = line.trim().to_lowercase();
                if !t.is_empty() && !t.starts_with('#') && t.contains('.') {
                    if domains.insert(t) {
                        count += 1;
                    }
                }
            }
        }
        // Note: the write lock must be dropped before rebuilding the matcher;
        // `rebuild_ac_matcher` takes the read lock and parking_lot RwLocks are
        // not reentrant  -  holding the write lock here used to deadlock the
        // daemon at startup.
        info!("ThreatBlocklist: loaded {count} domains from {path}");
        self.rebuild_ac_matcher();
        count
    }
}
