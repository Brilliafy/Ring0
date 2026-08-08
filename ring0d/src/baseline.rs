use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;
use rocksdb::DB;
use tracing::{info, warn};

const BASELINE_CF: &str = "baseline";
const LEARNING_PERIOD_SECS: u64 = 86400;

pub struct BaselineEngine {
    db: Arc<DB>,
    start_time: RwLock<Instant>,
    learning_mode: AtomicBool,
    learned_exec_paths: Arc<RwLock<HashMap<String, u64>>>,
    learned_parent_pairs: Arc<RwLock<HashMap<(String, String), u64>>>,
    learned_connections: Arc<RwLock<HashMap<(u32, u16), u64>>>,
    anomaly_count: Arc<RwLock<u64>>,
}

impl BaselineEngine {
    pub fn new(db: Arc<DB>) -> Self {
        let cf = match db.cf_handle(BASELINE_CF) {
            Some(cf) => {
                info!("Baseline column family already exists");
                cf
            }
            None => {
                warn!("Baseline column family not found  -  skipping (not available at runtime)");
                return Self {
                    db,
                    start_time: RwLock::new(Instant::now()),
                    learning_mode: AtomicBool::new(true),
                    learned_exec_paths: Arc::new(RwLock::new(HashMap::new())),
                    learned_parent_pairs: Arc::new(RwLock::new(HashMap::new())),
                    learned_connections: Arc::new(RwLock::new(HashMap::new())),
                    anomaly_count: Arc::new(RwLock::new(0u64)),
                };
            }
        };

        let learned_exec_paths = Arc::new(RwLock::new(HashMap::new()));
        let learned_parent_pairs = Arc::new(RwLock::new(HashMap::new()));
        let learned_connections = Arc::new(RwLock::new(HashMap::new()));
        let anomaly_count = Arc::new(RwLock::new(0u64));

        Self::load_persisted(
            &db,
            cf,
            &learned_exec_paths,
            &learned_parent_pairs,
            &learned_connections,
        );

        Self {
            db,
            start_time: RwLock::new(Instant::now()),
            learning_mode: AtomicBool::new(true),
            learned_exec_paths,
            learned_parent_pairs,
            learned_connections,
            anomaly_count,
        }
    }

    fn load_persisted(
        db: &DB,
        cf: &rocksdb::ColumnFamily,
        exec_paths: &Arc<RwLock<HashMap<String, u64>>>,
        parent_pairs: &Arc<RwLock<HashMap<(String, String), u64>>>,
        connections: &Arc<RwLock<HashMap<(u32, u16), u64>>>,
    ) {
        let iter = db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        for result in iter {
            let (key, val) = match result {
                Ok(kv) => kv,
                Err(e) => {
                    warn!("Baseline DB iteration error: {e}");
                    continue;
                }
            };
            let key_str = match std::str::from_utf8(&key) {
                Ok(s) => s.to_string(),
                Err(_) => continue,
            };
            let count = u64::from_be_bytes(match val.as_ref().try_into() {
                Ok(c) => c,
                Err(_) => continue,
            });

            if let Some(path) = key_str.strip_prefix("exec:") {
                exec_paths.write().insert(path.to_string(), count);
            } else if let Some(pair) = key_str.strip_prefix("parent:") {
                if let Some((parent, child)) = pair.split_once('|') {
                    parent_pairs
                        .write()
                        .insert((parent.to_string(), child.to_string()), count);
                }
            } else if let Some(conn) = key_str.strip_prefix("conn:") {
                if let Some((ip_str, port_str)) = conn.split_once(':') {
                    if let (Ok(ip), Ok(port)) = (ip_str.parse::<u32>(), port_str.parse::<u16>()) {
                        connections.write().insert((ip, port), count);
                    }
                }
            }
        }
    }

    pub fn record_exec(&self, binary: &str, parent_binary: Option<&str>) {
        let count = {
            let mut paths = self.learned_exec_paths.write();
            let n = paths.entry(binary.to_string()).or_insert(0);
            *n += 1;
            *n
        };
        self.persist_count(b"exec:", binary.as_bytes(), count);
        if let Some(parent) = parent_binary {
            let count = {
                let mut pairs = self.learned_parent_pairs.write();
                let n = pairs
                    .entry((parent.to_string(), binary.to_string()))
                    .or_insert(0);
                *n += 1;
                *n
            };
            let mut key = b"parent:".to_vec();
            key.extend_from_slice(parent.as_bytes());
            key.push(b'|');
            key.extend_from_slice(binary.as_bytes());
            self.persist_count_raw(&key, count);
        }
    }

    pub fn record_connection(&self, dst_ip: u32, dst_port: u16) {
        let count = {
            let mut conns = self.learned_connections.write();
            let n = conns.entry((dst_ip, dst_port)).or_insert(0);
            *n += 1;
            *n
        };
        let mut key = b"conn:".to_vec();
        key.extend_from_slice(dst_ip.to_string().as_bytes());
        key.push(b':');
        key.extend_from_slice(dst_port.to_string().as_bytes());
        self.persist_count_raw(&key, count);
    }

    /// Persist a counter value under `prefix ++ suffix` (replacing the previous value).
    fn persist_count(&self, prefix: &[u8], suffix: &[u8], count: u64) {
        let mut key = prefix.to_vec();
        key.extend_from_slice(suffix);
        self.persist_count_raw(&key, count);
    }

    fn persist_count_raw(&self, key: &[u8], count: u64) {
        if let Some(cf) = self.db.cf_handle(BASELINE_CF) {
            let val = count.to_be_bytes();
            if let Err(e) = self.db.put_cf(&cf, key, val) {
                warn!("Baseline persist failed: {e}");
            }
        }
    }

    pub fn check_exec_anomaly(&self, binary: &str, parent_binary: Option<&str>) -> Option<String> {
        if self.learning_mode.load(Ordering::Relaxed) {
            return None;
        }

        let paths = self.learned_exec_paths.read();
        if !paths.contains_key(binary) {
            let entropy = compute_shannon_entropy(binary.as_bytes());
            let msg = format!(
                "Unseen Execution Path: binary={} entropy={:.2}",
                binary, entropy
            );
            let mut count = self.anomaly_count.write();
            *count += 1;
            info!("BASELINE ANOMALY: {msg}");
            return Some(msg);
        }

        if let Some(parent) = parent_binary {
            let pairs = self.learned_parent_pairs.read();
            if !pairs.contains_key(&(parent.to_string(), binary.to_string())) {
                let parent_entropy = compute_shannon_entropy(parent.as_bytes());
                let child_entropy = compute_shannon_entropy(binary.as_bytes());
                let msg = format!(
                    "Anomalous Parent/Child Spawn: parent={} (e={:.2}) child={} (e={:.2})",
                    parent, parent_entropy, binary, child_entropy
                );
                let mut count = self.anomaly_count.write();
                *count += 1;
                info!("BASELINE ANOMALY: {msg}");
                return Some(msg);
            }
        }

        None
    }

    pub fn check_connection_anomaly(&self, dst_ip: u32, dst_port: u16) -> Option<String> {
        if self.learning_mode.load(Ordering::Relaxed) {
            return None;
        }

        let conns = self.learned_connections.read();
        if !conns.contains_key(&(dst_ip, dst_port)) {
            let msg = format!(
                "Unseen Connection Destination: {}.{}.{}.{}:{}",
                (dst_ip >> 24) & 0xFF,
                (dst_ip >> 16) & 0xFF,
                (dst_ip >> 8) & 0xFF,
                dst_ip & 0xFF,
                dst_port
            );
            let mut count = self.anomaly_count.write();
            *count += 1;
            info!("BASELINE ANOMALY: {msg}");
            return Some(msg);
        }
        None
    }

    pub fn finish_learning(&self) {
        self.learning_mode.store(false, Ordering::Relaxed);
        let elapsed = self.start_time.read().elapsed();
        info!(
            "Baseline learning finished after {:.2}s  -  switching to anomaly detection. \
             Learned: {} exec paths, {} parent pairs, {} connections",
            elapsed.as_secs_f64(),
            self.learned_exec_paths.read().len(),
            self.learned_parent_pairs.read().len(),
            self.learned_connections.read().len()
        );
    }

    pub fn is_learning(&self) -> bool {
        self.learning_mode.load(Ordering::Relaxed)
    }

    pub fn learning_progress(&self) -> f64 {
        let elapsed = self.start_time.read().elapsed().as_secs_f64();
        (elapsed / LEARNING_PERIOD_SECS as f64).min(1.0)
    }

    pub fn anomaly_count(&self) -> u64 {
        *self.anomaly_count.read()
    }

    pub fn force_learning(&self) {
        self.learning_mode.store(true, Ordering::Relaxed);
        *self.start_time.write() = Instant::now();
        info!("Baseline learning mode re-enabled");
    }
}

fn compute_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in freq.iter() {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}
