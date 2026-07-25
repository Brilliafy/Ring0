use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};

const FIM_DIRS: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib64",
    "/usr/lib",
    "/etc/pam.d",
    "/etc/security",
];

pub struct FimEngine {
    baseline: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    db: Arc<rocksdb::DB>,
    enabled: Arc<std::sync::atomic::AtomicBool>,
}

impl FimEngine {
    pub fn new(db: Arc<rocksdb::DB>) -> Self {
        let engine = Self {
            baseline: Arc::new(RwLock::new(HashMap::new())),
            db,
            enabled: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        };
        let _ = db.cf_handle("fim_baseline").or_else(|| {
            db.create_cf("fim_baseline", &rocksdb::Options::default())
                .ok();
            db.cf_handle("fim_baseline")
        });
        engine.load_persisted_baseline();
        engine
    }

    pub fn scan_and_baseline(&self) -> usize {
        let mut count = 0usize;
        let mut baseline = self.baseline.write();
        baseline.clear();

        for dir in FIM_DIRS {
            let path = Path::new(dir);
            if !path.is_dir() {
                continue;
            }
            count += self.hash_directory(path, &mut baseline);
        }

        self.persist_baseline(&baseline);
        info!("FIM: scanned and baselined {count} files");
        count
    }

    fn hash_directory(&self, dir: &Path, baseline: &mut HashMap<String, Vec<u8>>) -> usize {
        let mut count = 0usize;
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Ok(data) = fs::read(&path) {
                        let hash = Sha256::digest(&data).to_vec();
                        let path_str = path.display().to_string();
                        baseline.insert(path_str, hash);
                        count += 1;
                    }
                }
            }
        }
        count
    }

    fn persist_baseline(&self, baseline: &HashMap<String, Vec<u8>>) {
        if let Some(cf) = self.db.cf_handle("fim_baseline") {
            for (path, hash) in baseline {
                let _ = self.db.put_cf(&cf, path.as_bytes(), hash);
            }
        }
    }

    fn load_persisted_baseline(&self) {
        let cf = match self.db.cf_handle("fim_baseline") {
            Some(c) => c,
            None => return,
        };
        let mut baseline = self.baseline.write();
        baseline.clear();
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        for item in iter {
            if let Ok((key, val)) = item {
                let path = String::from_utf8_lossy(&key).to_string();
                baseline.insert(path, val.to_vec());
            }
        }
        info!("FIM: loaded {} baselines from database", baseline.len());
    }

    pub fn verify_file(&self, path: &str) -> Option<String> {
        if !self.enabled.load(std::sync::atomic::Ordering::Relaxed) {
            return None;
        }

        let baseline = self.baseline.read();
        let stored_hash = baseline.get(path)?;

        let current_data = fs::read(path).ok()?;
        let current_hash = Sha256::digest(&current_data).to_vec();

        if current_hash != *stored_hash {
            let msg = format!("FIM: file {path} has been modified — hash mismatch");
            warn!("{msg}");
            return Some(msg);
        }

        None
    }

    pub fn enable(&self) {
        self.enabled
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn disable(&self) {
        self.enabled
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn file_count(&self) -> usize {
        self.baseline.read().len()
    }
}
