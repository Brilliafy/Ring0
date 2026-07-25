use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};

const TRUSTED_PATHS: &[&str] = &[
    "/usr/bin/",
    "/usr/libexec/",
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
    gpg_key_map: Arc<RwLock<Vec<String>>>,
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
        let mut engine = Self {
            cache: Arc::new(RwLock::new(HashMap::with_capacity(4096))),
            gpg_key_map: Arc::new(RwLock::new(Vec::new())),
        };
        engine.load_gpg_keys();
        engine
    }

    fn load_gpg_keys(&mut self) {
        let gpg_dirs = &["/etc/pki/rpm-gpg/", "/usr/share/distribution-gpg-keys/"];
        let mut keys = self.gpg_key_map.write();
        for dir in gpg_dirs {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path
                        .extension()
                        .map(|e| e == "asc" || e == "gpg")
                        .unwrap_or(false)
                    {
                        keys.push(path.display().to_string());
                    }
                }
            }
        }
        info!("Loaded {} GPG key files for RPM verification", keys.len());
    }

    pub fn verify_binary(&self, binary_path: &str, pid: u32) -> TrustStatus {
        if binary_path == "unknown" || binary_path.is_empty() {
            return TrustStatus::Unknown;
        }

        let binary_bytes = match fs::read(binary_path) {
            Ok(b) => b,
            Err(e) => {
                warn!("TrustEngine: cannot read binary {binary_path} for PID {pid}: {e}");
                return TrustStatus::Unknown;
            }
        };

        let hash = Sha256::digest(&binary_bytes).to_vec();

        {
            let cache = self.cache.read();
            if let Some(status) = cache.get(&hash) {
                return status.clone();
            }
        }

        let status = self.check_binary_status(binary_path, pid, &binary_bytes);

        let mut cache = self.cache.write();
        cache.insert(hash, status.clone());
        status
    }

    fn check_binary_status(&self, binary_path: &str, pid: u32, binary_bytes: &[u8]) -> TrustStatus {
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
                "TrustEngine: PID {pid} binary {binary_path} not in trusted paths — marking untrusted"
            );
            return TrustStatus::Untrusted;
        }

        if self.verify_rpm_package(binary_path) {
            let sig_ok = self.verify_rpm_signature(binary_path);
            if sig_ok {
                info!("TrustEngine: PID {pid} binary {binary_path} verified as signed RPM package");
                return TrustStatus::TrustedSystemPackage;
            } else {
                warn!(
                    "TrustEngine: PID {pid} binary {binary_path} is from RPM but signature verification failed"
                );
                return TrustStatus::Unknown;
            }
        }

        info!(
            "TrustEngine: PID {pid} binary {binary_path} in trusted path but not from RPM database"
        );
        TrustStatus::TrustedBinary
    }

    fn verify_rpm_package(&self, binary_path: &str) -> bool {
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

    fn verify_rpm_signature(&self, binary_path: &str) -> bool {
        let output = match std::process::Command::new("rpm")
            .args(["-qVf", binary_path])
            .output()
        {
            Ok(o) => o,
            Err(e) => {
                warn!("rpm signature verification failed for {binary_path}: {e}");
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

    pub fn gpg_key_count(&self) -> usize {
        self.gpg_key_map.read().len()
    }
}
