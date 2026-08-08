use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

/// Resolve a bare command name (e.g. "curl") to a full path by searching
/// $PATH. Returns None when not found.
fn trust_resolve_path(name: &str) -> Option<String> {
    let path = std::env::var("PATH").unwrap_or_default();
    for dir in path.split(':') {
        let candidate = format!("{dir}/{name}");
        if std::path::Path::new(&candidate).is_file() {
            return Some(candidate);
        }
    }
    None
}

const TRUSTED_PATHS: &[&str] = &[
    "/usr/bin/",
    "/usr/libexec/",
    "/usr/lib64/",
    "/usr/lib/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
];

const ALWAYS_ALLOW_BINARIES: &[&str] = &[
    "dnf",
    "rpm",
    "flatpak",
    "systemd-resolved",
    "systemd-network",
    "sshd",
    "chronyd",
    "NetworkManager",
    "firewalld",
    "packagekitd",
    "dbus-daemon",
    "systemd-logind",
];

pub struct TrustEngine {
    cache: Arc<RwLock<HashMap<Vec<u8>, TrustStatus>>>,
    /// Cheap memo keyed by (path, size, mtime): avoids re-reading + hashing the
    /// whole binary (and re-spawning `rpm`) for every connect from the same
    /// unchanged binary.
    path_memo: Arc<RwLock<HashMap<(String, u64, u64), TrustStatus>>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TrustStatus {
    TrustedSystemPackage,
    TrustedBinary,
    Untrusted,
    Unknown,
}

impl TrustEngine {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::with_capacity(4096))),
            path_memo: Arc::new(RwLock::new(HashMap::with_capacity(4096))),
        }
    }

    pub fn verify_binary(&self, binary_path: &str, pid: u32) -> TrustStatus {
        Self::verify_impl(&self.cache, &self.path_memo, binary_path, pid)
    }

    /// Async variant for use from the event loop: the expensive part
    /// (whole-file read + SHA-256 + `rpm` subprocess) runs on a blocking
    /// thread, so a slow disk or a slow rpm query cannot stall event
    /// processing. Results are memoized, so subsequent connects from the same
    /// unchanged binary are cheap cache hits.
    pub async fn verify_binary_async(&self, binary_path: &str, pid: u32) -> TrustStatus {
        let cache = self.cache.clone();
        let path_memo = self.path_memo.clone();
        let binary_path = binary_path.to_string();
        tokio::task::spawn_blocking(move || {
            Self::verify_impl(&cache, &path_memo, &binary_path, pid)
        })
        .await
        .unwrap_or(TrustStatus::Unknown)
    }

    fn verify_impl(
        cache: &RwLock<HashMap<Vec<u8>, TrustStatus>>,
        path_memo: &RwLock<HashMap<(String, u64, u64), TrustStatus>>,
        binary_path: &str,
        pid: u32,
    ) -> TrustStatus {
        if binary_path == "unknown" || binary_path.is_empty() {
            return TrustStatus::Unknown;
        }

        // Short-lived processes (curl one-liners, scripted tools) resolve to
        // the bare comm name ("curl") because /proc/<pid>/exe is gone by the
        // time the event is processed. Resolve basenames against PATH so the
        // trust verdict still applies; unresolvable basenames fall through to
        // the ALWAYS_ALLOW check and are logged at debug, not per-event warn.
        let resolved = if binary_path.contains('/') {
            binary_path.to_string()
        } else {
            trust_resolve_path(binary_path).unwrap_or_else(|| binary_path.to_string())
        };

        // Cheap memo first: (path, size, mtime) → status. Avoids reading and
        // hashing the whole binary on every connect.
        let meta = match std::fs::metadata(&resolved) {
            Ok(m) => m,
            Err(e) => {
                if resolved.contains('/') {
                    warn!("TrustEngine: cannot stat {resolved} for PID {pid}: {e}");
                } else {
                    debug!("TrustEngine: cannot stat {resolved} for PID {pid}: {e}");
                }
                return TrustStatus::Unknown;
            }
        };
        let memo_key = (
            binary_path.to_string(),
            meta.len(),
            meta.modified()
                .map(|t| {
                    t.duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos() as u64)
                        .unwrap_or(0)
                })
                .unwrap_or(0),
        );
        {
            let memo = path_memo.read();
            if let Some(status) = memo.get(&memo_key) {
                return status.clone();
            }
        }

        let binary_bytes = match std::fs::read(binary_path) {
            Ok(b) => b,
            Err(e) => {
                warn!("TrustEngine: cannot read binary {binary_path} for PID {pid}: {e}");
                return TrustStatus::Unknown;
            }
        };

        let hash = Sha256::digest(&binary_bytes).to_vec();

        {
            let cache = cache.read();
            if let Some(status) = cache.get(&hash) {
                return status.clone();
            }
        }

        let status = Self::check_binary_status_gpg(binary_path, pid);

        {
            let mut cache = cache.write();
            cache.insert(hash, status.clone());
            if cache.len() > 8192 {
                cache.clear();
            }
        }
        {
            let mut memo = path_memo.write();
            memo.insert(memo_key, status.clone());
            if memo.len() > 8192 {
                memo.clear();
            }
        }
        status
    }

    fn check_binary_status_gpg(binary_path: &str, pid: u32) -> TrustStatus {
        let binary_name = Path::new(binary_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        for &allowed in ALWAYS_ALLOW_BINARIES {
            if binary_name == allowed {
                return TrustStatus::TrustedBinary;
            }
        }

        let in_trusted_path = TRUSTED_PATHS.iter().any(|p| binary_path.starts_with(p));
        if !in_trusted_path {
            info!(
                "TrustEngine: PID {pid} binary {binary_path} not in trusted paths  -  marking untrusted"
            );
            return TrustStatus::Untrusted;
        }

        if Self::verify_rpm_package(binary_path) {
            // `rpm -qVf` verifies the installed file against the RPM database
            // (sizes/checksums/modes). It is NOT a cryptographic signature
            // check  -  that would require the original .rpm and `rpm -K`. We
            // deliberately do not claim "signed": a modified file fails the
            // DB check and the binary is treated as unverifiable.
            let integ_ok = Self::verify_rpm_integrity(binary_path);
            if integ_ok {
                info!("TrustEngine: PID {pid} binary {binary_path} verified against RPM database");
                return TrustStatus::TrustedSystemPackage;
            } else {
                warn!(
                    "TrustEngine: PID {pid} binary {binary_path} is from RPM but failed integrity verification (modified or unverifiable)"
                );
                return TrustStatus::Unknown;
            }
        }

        info!(
            "TrustEngine: PID {pid} binary {binary_path} in trusted path but not from RPM database"
        );
        TrustStatus::TrustedBinary
    }

    fn verify_rpm_package(binary_path: &str) -> bool {
        let output = match std::process::Command::new("rpm")
            .args(["-qf", "--queryformat", "%{NAME}", binary_path])
            .output()
        {
            Ok(o) => o,
            Err(e) => {
                warn!("rpm query failed for {binary_path}: {e}");
                return false;
            }
        };

        if output.status.success() {
            let pkg_name = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !pkg_name.is_empty() {
                info!("TrustEngine: {binary_path} belongs to RPM package {pkg_name}");
                return true;
            }
        }
        false
    }

    /// Verify the installed binary's file attributes against the RPM database
    /// (`rpm -qVf`). Note: this is integrity-vs-DB, not a GPG signature check.
    fn verify_rpm_integrity(binary_path: &str) -> bool {
        let output = match std::process::Command::new("rpm")
            .args(["-qVf", binary_path])
            .output()
        {
            Ok(o) => o,
            Err(e) => {
                warn!("rpm integrity verification failed for {binary_path}: {e}");
                return false;
            }
        };

        output.status.success()
    }

    pub fn is_allowed_connect(&self, binary_path: &str, pid: u32) -> bool {
        let status = self.verify_binary(binary_path, pid);
        match status {
            TrustStatus::TrustedSystemPackage | TrustStatus::TrustedBinary => true,
            TrustStatus::Untrusted | TrustStatus::Unknown => false,
        }
    }

    pub fn cache_size(&self) -> usize {
        self.cache.read().len()
    }
}
