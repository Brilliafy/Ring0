use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use parking_lot::RwLock;
use tracing::{info, warn};

const WINDOW_NS: u64 = 30_000_000_000;
const WINDOW_EXEC_NS: u64 = 10_000_000_000;
const WINDOW_CRED_NS: u64 = 5_000_000_000;

static NEXT_CORRELATION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct ExecRecord {
    pub timestamp: u64,
    pub pid: u32,
    pub ppid: u32,
    pub binary_path: String,
    pub cmdline: String,
}

#[derive(Debug, Clone)]
pub struct ConnectRecord {
    pub timestamp: u64,
    pub pid: u32,
    pub dst_ip: u32,
    pub dst_port: u16,
}

#[derive(Debug, Clone)]
pub struct FileRecord {
    pub timestamp: u64,
    pub pid: u32,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct CorrelationAlert {
    pub id: u64,
    pub pattern_id: u32,
    pub pattern_name: String,
    pub mitre_tactic: String,
    pub mitre_technique: String,
    pub severity: u8,
    pub root_pid: u32,
    pub description: String,
    pub timestamp: u64,
}

pub struct CorrelationEngine {
    execs: DashMap<u32, Vec<ExecRecord>>,
    connects: DashMap<u32, Vec<ConnectRecord>>,
    files: DashMap<u32, Vec<FileRecord>>,
    proc_tree: Arc<RwLock<HashMap<u32, u32>>>,
    alerts: Arc<RwLock<Vec<CorrelationAlert>>>,
}

impl CorrelationEngine {
    pub fn new() -> Self {
        Self {
            execs: DashMap::new(),
            connects: DashMap::new(),
            files: DashMap::new(),
            proc_tree: Arc::new(RwLock::new(HashMap::new())),
            alerts: Arc::new(RwLock::new(Vec::with_capacity(1024))),
        }
    }

    pub fn push_exec(&self, pid: u32, ppid: u32, binary: &str, cmdline: &str) {
        self.proc_tree.write().insert(pid, ppid);
        let now = Instant::now();
        self.execs.entry(pid).or_default().push(ExecRecord {
            timestamp: nano_now(),
            pid,
            ppid,
            binary_path: binary.to_string(),
            cmdline: cmdline.to_string(),
        });
        self.evict_old(&self.execs, WINDOW_NS);
    }

    pub fn push_connect(&self, pid: u32, dst_ip: u32, dst_port: u16) {
        self.connects.entry(pid).or_default().push(ConnectRecord {
            timestamp: nano_now(),
            pid,
            dst_ip,
            dst_port,
        });
        self.evict_old(&self.connects, WINDOW_NS);
    }

    pub fn push_file(&self, pid: u32, path: &str) {
        self.files.entry(pid).or_default().push(FileRecord {
            timestamp: nano_now(),
            pid,
            path: path.to_string(),
        });
        self.evict_old(&self.files, WINDOW_NS);
    }

    pub fn eval(&self) -> Vec<CorrelationAlert> {
        let mut results = Vec::new();
        let now = nano_now();

        for entry in self.execs.iter() {
            let pid = *entry.key();
            let records = entry.value();
            if records.is_empty() {
                continue;
            }
            let latest = records.last().unwrap();

            let ppid = latest.ppid;
            let parent_connects: Vec<ConnectRecord> = self
                .connects
                .get(&ppid)
                .map(|v| {
                    v.iter()
                        .filter(|c| now.saturating_sub(c.timestamp) < WINDOW_EXEC_NS)
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();

            let child_execs: Vec<ExecRecord> = self
                .execs
                .iter()
                .filter(|e| {
                    *e.key() != pid && e.value().last().map(|r| r.ppid == pid).unwrap_or(false)
                })
                .flat_map(|e| e.value().last().cloned())
                .filter(|r| now.saturating_sub(r.timestamp) < WINDOW_EXEC_NS)
                .collect();

            if !parent_connects.is_empty() && !child_execs.is_empty() {
                let id = NEXT_CORRELATION_ID.fetch_add(1, Ordering::Relaxed);
                let is_shell = latest.binary_path.contains("/sh")
                    || latest.binary_path.contains("python")
                    || latest.binary_path.contains("perl");
                let alert = CorrelationAlert {
                    id,
                    pattern_id: if is_shell { 1001 } else { 1002 },
                    pattern_name: if is_shell {
                        "Reverse Shell Chain".into()
                    } else {
                        "Suspicious Process Chain".into()
                    },
                    mitre_tactic: "Execution".into(),
                    mitre_technique: if is_shell {
                        "T1059.004".into()
                    } else {
                        "T1059".into()
                    },
                    severity: 3,
                    root_pid: ppid,
                    description: format!(
                        "PID {} ({}) connected outward then spawned child {}",
                        ppid,
                        latest.binary_path,
                        child_execs
                            .last()
                            .map(|c| &c.binary_path)
                            .unwrap_or(&"?".into())
                    ),
                    timestamp: now,
                };
                results.push(alert);
                self.alerts.write().push(alert.clone());
            }
        }

        for entry in self.files.iter() {
            let pid = *entry.key();
            let file_records: Vec<FileRecord> = entry
                .value()
                .iter()
                .filter(|f| now.saturating_sub(f.timestamp) < WINDOW_CRED_NS)
                .filter(|f| f.path.contains("/etc/shadow") || f.path.contains(".ssh/id_"))
                .cloned()
                .collect();
            if file_records.is_empty() {
                continue;
            }

            let recent_connects: Vec<ConnectRecord> = self
                .connects
                .get(&pid)
                .map(|v| {
                    v.iter()
                        .filter(|c| now.saturating_sub(c.timestamp) < WINDOW_CRED_NS)
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();

            if !recent_connects.is_empty() {
                let id = NEXT_CORRELATION_ID.fetch_add(1, Ordering::Relaxed);
                let alert = CorrelationAlert {
                    id,
                    pattern_id: 1003,
                    pattern_name: "Credential Harvesting Chain".into(),
                    mitre_tactic: "Credential Access".into(),
                    mitre_technique: "T1003 / T1041".into(),
                    severity: 3,
                    root_pid: pid,
                    description: format!(
                        "PID {} accessed {} then opened outbound connection",
                        pid, file_records[0].path
                    ),
                    timestamp: now,
                };
                results.push(alert);
                self.alerts.write().push(alert.clone());
            }
        }

        results
    }

    pub fn recent_alerts(&self) -> Vec<CorrelationAlert> {
        self.alerts.read().iter().rev().take(100).cloned().collect()
    }

    fn evict_old<T>(&self, map: &DashMap<u32, Vec<T>>, window: u64)
    where
        T: HasTimestamp,
    {
        let now = nano_now();
        map.retain(|_, v| {
            v.retain(|r| now.saturating_sub(r.timestamp()) < window);
            !v.is_empty()
        });
    }
}

pub trait HasTimestamp {
    fn timestamp(&self) -> u64;
}
impl HasTimestamp for ExecRecord {
    fn timestamp(&self) -> u64 {
        self.timestamp
    }
}
impl HasTimestamp for ConnectRecord {
    fn timestamp(&self) -> u64 {
        self.timestamp
    }
}
impl HasTimestamp for FileRecord {
    fn timestamp(&self) -> u64 {
        self.timestamp
    }
}

fn nano_now() -> u64 {
    chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64
}
