use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

// /etc first: tiny, high-value config hashes land before the (large) binary
// trees, so a byte-capped first run still covers the configs.
const FIM_DIRS: &[&str] = &[
    "/etc/pam.d",
    "/etc/security",
    "/etc/ssh",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib64",
    "/usr/lib",
];

/// Cap on total bytes hashed by the FIRST baseline run. A full /usr tree is
/// multi-GB; on a spinning disk an uncapped scan saturates the disk for many
/// minutes and makes every other program on the machine freeze. The baseline
/// is used for exec-anomaly integrity checks, so capping to the configs +
/// the most common executables degrades gracefully (large binaries simply
/// have no stored hash until a later incremental pass).
const MAX_FIM_BASELINE_BYTES: u64 = 512 * 1024 * 1024;

/// Files larger than this are skipped by the baseline scan: hashing a
/// multi-hundred-MB shared library adds little detection value while making
/// the startup scan take minutes.
const MAX_FIM_FILE_SIZE: u64 = 256 * 1024 * 1024;

#[derive(Clone)]
pub struct FimEngine {
    baseline: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    db: Arc<rocksdb::DB>,
    enabled: Arc<std::sync::atomic::AtomicBool>,
}

impl FimEngine {
    pub fn new(db: Arc<rocksdb::DB>) -> Self {
        let engine = Self {
            baseline: Arc::new(RwLock::new(HashMap::new())),
            db: db.clone(),
            enabled: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        };
        let _ = db.cf_handle("fim_baseline").or_else(|| {
            warn!(
                "FIM baseline CF not found at runtime  -  column families must be created at DB open"
            );
            db.cf_handle("fim_baseline")
        });
        engine.load_persisted_baseline();
        engine
    }

    pub fn scan_and_baseline(&self) -> usize {
        let mut count = 0usize;
        let mut hashed_bytes = 0u64;
        let mut baseline = self.baseline.write();
        baseline.clear();

        for dir in FIM_DIRS {
            let path = Path::new(dir);
            if !path.is_dir() {
                continue;
            }
            if hashed_bytes >= MAX_FIM_BASELINE_BYTES {
                info!(
                    "FIM: baseline byte budget exhausted ({MAX_FIM_BASELINE_BYTES} MB)  -  remaining dirs deferred"
                );
                break;
            }
            let (n, bytes) = self.hash_directory(path, &mut baseline, hashed_bytes);
            count += n;
            hashed_bytes = hashed_bytes.saturating_add(bytes);
        }

        self.persist_baseline(&baseline);
        info!(
            "FIM: scanned and baselined {count} files ({hashed_bytes} MB)  -  budget {MAX_FIM_BASELINE_BYTES} MB"
        );
        count
    }

    fn hash_directory(
        &self,
        dir: &Path,
        baseline: &mut HashMap<String, Vec<u8>>,
        budget_used: u64,
    ) -> (usize, u64) {
        let mut count = 0usize;
        let mut bytes = 0u64;
        if let Ok(entries) = fs::read_dir(dir) {
            let mut batch_start = std::time::Instant::now();
            for entry in entries.flatten() {
                let path = entry.path();
                // Follow nothing: `d_type` from the directory entry (skips
                // symlinks, which would duplicate the target's hash).
                let is_regular = entry.file_type().map(|ft| ft.is_file()).unwrap_or(false);
                if !is_regular {
                    continue;
                }
                // Skip oversized files (e.g. huge shared libraries).
                if entry
                    .metadata()
                    .map(|m| m.len() > MAX_FIM_FILE_SIZE)
                    .unwrap_or(false)
                {
                    continue;
                }
                // /usr/bin, /usr/sbin, /usr/lib64, /usr/lib contain mostly
                // data (locales, icons, gconv, …) and shared libraries that
                // have no exec-anomaly value: libraries are dlopen'd, never
                // exec'd, so the baseline's only consumer (exec anomaly
                // checks) can never consult their hashes. Hashing 6.5 GB of
                // them (libLLVM, libxul, …) made the startup baseline take
                // ~15 minutes on a spinning disk at the throttled duty cycle.
                // Restrict those trees to ELF EXECUTABLES; the /etc config
                // trees stay fully tracked.
                if !dir.starts_with("/etc") {
                    let is_elf = Self::is_elf_file(&path);
                    let is_shared_lib = path.to_string_lossy().contains(".so");
                    if !is_elf || is_shared_lib {
                        continue;
                    }
                }
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                if budget_used + bytes >= MAX_FIM_BASELINE_BYTES {
                    // Budget exhausted mid-directory: stop hashing. The
                    // caller breaks out of the dir loop on the next iteration.
                    return (count, bytes);
                }
                let hash = match Self::sha256_file(&path) {
                    Some(h) => h,
                    None => continue,
                };
                let path_str = path.display().to_string();
                baseline.insert(path_str, hash);
                count += 1;
                bytes = bytes.saturating_add(size);
                // Duty-cycle throttle: an unthrottled baseline over /usr/lib64
                // saturates a core for minutes, which trips the power governor
                // into Critical (sampling off) and starves the very security
                // work the baseline is supposed to support. Every 16 files we
                // sleep for twice the time the batch took (~33% duty cycle),
                // keeping the scan at a fraction of a core.
                if count % 16 == 0 {
                    let batch = batch_start.elapsed();
                    if !batch.is_zero() {
                        std::thread::sleep(batch.saturating_mul(2));
                    }
                    batch_start = std::time::Instant::now();
                }
            }
        }
        (count, bytes)
    }

    /// True when `path` starts with the ELF magic bytes (\x7fELF).
    fn is_elf_file(path: &Path) -> bool {
        use std::io::Read;
        let mut f = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let mut magic = [0u8; 4];
        f.read_exact(&mut magic).is_ok() && &magic == b"\x7fELF"
    }

    /// SHA-256 of a file, computed with a streaming reader (bounded memory).
    fn sha256_file(path: &Path) -> Option<Vec<u8>> {
        let file = fs::File::open(path).ok()?;
        let mut reader = std::io::BufReader::with_capacity(128 * 1024, file);
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 128 * 1024];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => hasher.update(&buf[..n]),
                Err(_) => return None,
            }
        }
        Some(hasher.finalize().to_vec())
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
        for item in iter.flatten() {
            let (key, val) = item;
            let path = String::from_utf8_lossy(&key).to_string();
            baseline.insert(path, val.to_vec());
        }
        info!("FIM: loaded {} baselines from database", baseline.len());
    }

    pub fn verify_file(&self, path: &str) -> Option<String> {
        if !self.enabled.load(std::sync::atomic::Ordering::Relaxed) {
            return None;
        }

        let baseline = self.baseline.read();
        let stored_hash = baseline.get(path)?;

        let current_hash = Self::sha256_file(Path::new(path))?;

        if current_hash != *stored_hash {
            let msg = format!("FIM: file {path} has been modified  -  hash mismatch");
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
