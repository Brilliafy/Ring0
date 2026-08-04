use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::info;

const _FLATPAK_DIRS: &[&str] = &["/var/lib/flatpak/app", "~/.local/share/flatpak/app"];

const _BWRAP_EXEC: &str = "bwrap";

#[derive(Debug, Clone)]
pub struct FlatpakApp {
    pub app_id: String,
    pub pid: u32,
    pub instance_path: String,
    pub shared_network: bool,
    pub shared_dbus: bool,
    pub allowed_features: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SandboxAnomaly {
    pub timestamp: u64,
    pub pid: u32,
    pub app_id: String,
    pub event_type: String,
    pub description: String,
}

pub struct DesktopSandbox {
    apps: Arc<RwLock<HashMap<u32, FlatpakApp>>>,
    anomalies: Arc<RwLock<Vec<SandboxAnomaly>>>,
}

impl DesktopSandbox {
    pub fn new() -> Self {
        Self {
            apps: Arc::new(RwLock::new(HashMap::new())),
            anomalies: Arc::new(RwLock::new(Vec::with_capacity(1024))),
        }
    }

    pub fn resolve_pid(&self, pid: u32, binary: &str, cmdline: &str) -> Option<FlatpakApp> {
        if !binary.contains("flatpak") && !cmdline.contains("flatpak") && !cmdline.contains("bwrap")
        {
            let cached = self.apps.read().get(&pid).cloned();
            return cached;
        }

        let app_id = self.extract_flatpak_id(pid, cmdline);
        let app_id = match app_id {
            Some(id) => id,
            None => return self.apps.read().get(&pid).cloned(),
        };

        let instance_path = format!("/proc/{pid}/root/app");
        let metadata_path = format!("/proc/{pid}/root/app/metadata");

        let shared_network = Self::check_metadata_permission(&metadata_path, "shared=network");
        let shared_dbus = Self::check_metadata_permission(&metadata_path, "shared=ipc");

        let mut allowed_features = Vec::new();
        if shared_network {
            allowed_features.push("network".into());
        }
        if shared_dbus {
            allowed_features.push("dbus".into());
        }

        let app = FlatpakApp {
            app_id: app_id.clone(),
            pid,
            instance_path,
            shared_network,
            shared_dbus,
            allowed_features,
        };

        self.apps.write().insert(pid, app.clone());
        info!("DesktopSandbox: resolved PID {pid} -> Flatpak {app_id} (network={shared_network})");
        Some(app)
    }

    fn extract_flatpak_id(&self, pid: u32, cmdline: &str) -> Option<String> {
        if let Some(id) = cmdline.split(' ').find(|s| s.contains('.')) {
            if id.chars().filter(|c| *c == '.').count() >= 2 {
                return Some(id.to_string());
            }
        }
        let info_path = format!("/proc/{pid}/root/.flatpak-info");
        if let Ok(content) = fs::read_to_string(&info_path) {
            for line in content.lines() {
                if let Some(id) = line.strip_prefix("application=") {
                    return Some(id.trim().to_string());
                }
            }
        }
        None
    }

    fn check_metadata_permission(metadata_path: &str, perm: &str) -> bool {
        if let Ok(content) = fs::read_to_string(metadata_path) {
            return content.contains(perm);
        }
        false
    }

    pub fn check_network_anomaly(&self, pid: u32, binary: &str) -> Option<SandboxAnomaly> {
        let apps = self.apps.read();
        let app = apps.get(&pid)?;
        if app.shared_network {
            return None;
        }
        if binary.contains("dbus-daemon") || binary.contains("pipewire") {
            return None;
        }
        let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
        let anomaly = SandboxAnomaly {
            timestamp: now,
            pid,
            app_id: app.app_id.clone(),
            event_type: "unauthorized_network".into(),
            description: format!(
                "Flatpak app {} (PID {}) opened network socket but has no network permission",
                app.app_id, pid
            ),
        };
        self.anomalies.write().push(anomaly.clone());
        info!("[SANDBOX] {} — no network permission", anomaly.description);
        Some(anomaly)
    }

    pub fn check_file_anomaly(&self, pid: u32, path: &str) -> Option<SandboxAnomaly> {
        let apps = self.apps.read();
        let app = apps.get(&pid)?;
        if path.starts_with("/app/") || path.starts_with("/run/") || path.starts_with("/tmp/") {
            return None;
        }
        if path.starts_with("/etc/") || path.starts_with("/usr/") || path.starts_with("/home/") {
            let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
            let anomaly = SandboxAnomaly {
                timestamp: now,
                pid,
                app_id: app.app_id.clone(),
                event_type: "sandbox_escape".into(),
                description: format!(
                    "Flatpak app {} (PID {}) accessed host path {} outside sandbox",
                    app.app_id, pid, path
                ),
            };
            self.anomalies.write().push(anomaly.clone());
            info!("[SANDBOX] {} — host file access", anomaly.description);
            return Some(anomaly);
        }
        None
    }

    pub fn is_flatpak_process(&self, pid: u32) -> bool {
        self.apps.read().contains_key(&pid)
    }

    pub fn list_apps(&self) -> Vec<FlatpakApp> {
        self.apps.read().values().cloned().collect()
    }

    pub fn anomaly_count(&self) -> usize {
        self.anomalies.read().len()
    }

    pub fn recent_anomalies(&self, n: usize) -> Vec<SandboxAnomaly> {
        self.anomalies
            .read()
            .iter()
            .rev()
            .take(n)
            .cloned()
            .collect()
    }
}
