use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use parking_lot::RwLock;
use tokio::sync::watch;
use tracing::{info, warn};

const FEED_URLS: &[(&str, &str)] = &[
    (
        "feodo",
        "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
    ),
    ("urlhaus", "https://urlhaus.abuse.ch/downloads/csv_recent/"),
    (
        "sslbl",
        "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
    ),
];

const YARA_DIR: &str = "/etc/ring0/yara";
const INTEL_DB_CF: &str = "intel";

#[derive(Debug, Clone)]
pub struct IntelFeedState {
    pub feed_name: String,
    pub entries_added: u32,
    pub entries_total: u32,
    pub last_sync: String,
    pub success: bool,
    pub error_message: String,
}

pub struct IntelManager {
    yara_compiled: ArcSwap<Option<Vec<u8>>>,
    yara_rules_count: RwLock<u32>,
    ip_blocklist: ArcSwap<Vec<(u32, u8)>>,
    feed_states: RwLock<Vec<IntelFeedState>>,
    sync_tx: watch::Sender<bool>,
    db: Arc<rocksdb::DB>,
}

impl IntelManager {
    pub fn new(db: Arc<rocksdb::DB>) -> Self {
        let (sync_tx, _sync_rx) = watch::channel(false);
        let _ = db.cf_handle(INTEL_DB_CF).or_else(|| {
            warn!("Intel DB CF not found at runtime — column families must be created at DB open");
            db.cf_handle(INTEL_DB_CF)
        });

        Self {
            yara_compiled: ArcSwap::new(Arc::new(None)),
            yara_rules_count: RwLock::new(0),
            ip_blocklist: ArcSwap::new(Arc::new(Vec::new())),
            feed_states: RwLock::new(Vec::new()),
            sync_tx,
            db,
        }
    }

    pub fn load_yara_rules(&self) -> Result<u32> {
        let dir = Path::new(YARA_DIR);
        if !dir.exists() {
            fs::create_dir_all(dir).context("Failed to create YARA directory")?;
            info!("Created YARA directory at {YARA_DIR}");
            return Ok(0);
        }

        let mut count = 0u32;

        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path
                    .extension()
                    .map(|e| e == "yar" || e == "yara")
                    .unwrap_or(false)
                {
                    count += 1;
                }
            }
        }

        *self.yara_rules_count.write() = count;
        info!("Loaded {count} YARA rule files from {YARA_DIR}");
        Ok(count)
    }

    pub async fn sync_feeds(&self) -> Result<Vec<IntelFeedState>> {
        let mut states = Vec::new();

        for (name, url) in FEED_URLS {
            let state = self.sync_single_feed(name, url).await;
            info!(
                "Feed {}: {} entries (success={})",
                name, state.entries_added, state.success
            );
            states.push(state);
        }

        *self.feed_states.write() = states.clone();
        let _ = self.sync_tx.send(true);
        Ok(states)
    }

    async fn sync_single_feed(&self, name: &str, url: &str) -> IntelFeedState {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("Ring0-Intel/1.0")
            .build()
            .unwrap_or_default();

        let response = match client.get(url).send().await {
            Ok(r) => r,
            Err(e) => {
                return IntelFeedState {
                    feed_name: name.to_string(),
                    entries_added: 0,
                    entries_total: 0,
                    last_sync: chrono::Utc::now().to_rfc3339(),
                    success: false,
                    error_message: format!("HTTP request failed: {e}"),
                };
            }
        };

        let body = match response.text().await {
            Ok(b) => b,
            Err(e) => {
                return IntelFeedState {
                    feed_name: name.to_string(),
                    entries_added: 0,
                    entries_total: 0,
                    last_sync: chrono::Utc::now().to_rfc3339(),
                    success: false,
                    error_message: format!("Failed to read response body: {e}"),
                };
            }
        };

        let mut entries = Vec::new();
        let mut total = 0u32;

        for line in body.lines().take(10000) {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            total += 1;
            if let Some(ip_str) = trimmed.split(',').next() {
                if let Ok(ip) = ip_str.trim().parse::<std::net::Ipv4Addr>() {
                    entries.push((u32::from(ip), 32u8));
                }
            }
        }

        if !entries.is_empty() {
            let blocklist = self.ip_blocklist.load();
            let mut combined: Vec<(u32, u8)> = blocklist.iter().copied().collect();
            combined.extend(entries.iter().copied());
            combined.sort();
            combined.dedup();
            self.ip_blocklist.store(Arc::new(combined));
        }

        if let Some(cf) = self.db.cf_handle(INTEL_DB_CF) {
            let key = format!("feed:{}", name);
            let val = format!(
                "{{\"entries\":{},\"time\":\"{}\"}}",
                entries.len(),
                chrono::Utc::now().to_rfc3339()
            );
            let _ = self.db.put_cf(&cf, key.as_bytes(), val.as_bytes());
        }

        IntelFeedState {
            feed_name: name.to_string(),
            entries_added: entries.len() as u32,
            entries_total: total,
            last_sync: chrono::Utc::now().to_rfc3339(),
            success: true,
            error_message: String::new(),
        }
    }

    pub fn get_blocklist(&self) -> Vec<(u32, u8)> {
        self.ip_blocklist.load().iter().copied().collect()
    }

    pub fn get_feed_states(&self) -> Vec<IntelFeedState> {
        self.feed_states.read().clone()
    }

    pub fn yara_rule_count(&self) -> u32 {
        *self.yara_rules_count.read()
    }

    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.sync_tx.subscribe()
    }

    /// Scan a binary with the loaded YARA rules.
    ///
    /// Returns an explicit error because the YARA engine is not implemented
    /// yet: returning an empty result here would make callers believe the
    /// binary was scanned and found clean, which is a false sense of security.
    pub fn scan_binary(&self, _path: &str) -> Result<Vec<String>, String> {
        Err("YARA engine not implemented — binary was not scanned".to_string())
    }
}
