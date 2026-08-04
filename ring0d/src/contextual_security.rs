use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::info;

const _SCREEN_LOCKED_POLICY: &str = "drop_background_on_lock";
const _BACKGROUND_ISOLATION_POLICY: &str = "block_background_network";

pub struct ContextualSecurity {
    screen_locked: Arc<AtomicBool>,
    background_whitelist: Arc<RwLock<HashSet<String>>>,
    per_process_policies: Arc<RwLock<HashMap<u32, ProcessPolicy>>>,
    dbus_monitor: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Debug, Clone)]
pub struct ProcessPolicy {
    pub pid: u32,
    pub binary_name: String,
    pub block_on_lock: bool,
    pub block_background: bool,
    pub is_foreground: bool,
}

impl ContextualSecurity {
    pub fn new() -> Self {
        let mut whitelist = HashSet::new();
        whitelist.insert("ring0d".into());
        whitelist.insert("systemd".into());
        whitelist.insert("sshd".into());
        whitelist.insert("NetworkManager".into());
        whitelist.insert("systemd-resolved".into());

        Self {
            screen_locked: Arc::new(AtomicBool::new(false)),
            background_whitelist: Arc::new(RwLock::new(whitelist)),
            per_process_policies: Arc::new(RwLock::new(HashMap::new())),
            dbus_monitor: None,
        }
    }

    pub fn start_dbus_monitor(&mut self) {
        let locked = self.screen_locked.clone();
        self.dbus_monitor = Some(tokio::spawn(async move {
            let conn = zbus::Connection::session().await.ok();
            loop {
                if let Some(conn) = &conn {
                    match screen_locked_via_dbus(conn).await {
                        Some(l) => locked.store(l, Ordering::Relaxed),
                        None => {}
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        }));
        info!("ContextualSecurity: D-Bus screen-lock monitor active");
    }

    pub fn is_screen_locked(&self) -> bool {
        self.screen_locked.load(Ordering::Relaxed)
    }

    pub fn should_block_connection(&self, pid: u32, binary: &str) -> bool {
        let binary_name = binary.rsplit('/').next().unwrap_or(binary);

        {
            let whitelist = self.background_whitelist.read();
            if whitelist.contains(binary_name) {
                return false;
            }
        }

        let policies = self.per_process_policies.read();
        if let Some(policy) = policies.get(&pid) {
            if self.screen_locked.load(Ordering::Relaxed) && policy.block_on_lock {
                info!("ContextualSecurity: blocking PID {pid} ({binary_name}) — screen locked");
                return true;
            }
            if !policy.is_foreground && policy.block_background {
                info!(
                    "ContextualSecurity: blocking PID {pid} ({binary_name}) — background process"
                );
                return true;
            }
        }

        if self.screen_locked.load(Ordering::Relaxed) && !binary.contains("/usr/bin/") {
            info!("ContextualSecurity: blocking PID {pid} ({binary_name}) — screen locked + non-system binary");
            return true;
        }

        false
    }

    pub fn set_process_policy(&self, pid: u32, policy: ProcessPolicy) {
        self.per_process_policies.write().insert(pid, policy);
    }

    pub fn remove_process_policy(&self, pid: u32) {
        self.per_process_policies.write().remove(&pid);
    }

    pub fn add_background_whitelist(&self, name: &str) {
        self.background_whitelist.write().insert(name.to_string());
    }

    pub fn update_foreground_status(&self, pid: u32, is_foreground: bool) {
        let mut policies = self.per_process_policies.write();
        if let Some(p) = policies.get_mut(&pid) {
            p.is_foreground = is_foreground;
        }
    }

    pub fn policy_count(&self) -> usize {
        self.per_process_policies.read().len()
    }
}
async fn screen_locked_via_dbus(conn: &zbus::Connection) -> Option<bool> {
    for (bus, path, iface) in [
        ("org.gnome.ScreenSaver", "/org/gnome/ScreenSaver", "org.gnome.ScreenSaver"),
        ("org.freedesktop.ScreenSaver", "/org/freedesktop/ScreenSaver", "org.freedesktop.ScreenSaver"),
        ("org.kde.screensaver", "/org/freedesktop/ScreenSaver", "org.freedesktop.ScreenSaver"),
    ] {
        let Ok(proxy) = zbus::proxy::Proxy::new(conn, bus, path, iface).await else {
            continue;
        };
        if let Ok(active) = proxy.get_property::<bool>("Active").await {
            return Some(active);
        }
    }
    None
}
