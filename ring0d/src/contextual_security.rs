use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::{info, warn};

const SCREEN_LOCKED_POLICY: &str = "drop_background_on_lock";
const BACKGROUND_ISOLATION_POLICY: &str = "block_background_network";

pub struct ContextualSecurity {
    screen_locked: AtomicBool,
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
            screen_locked: AtomicBool::new(false),
            background_whitelist: Arc::new(RwLock::new(whitelist)),
            per_process_policies: Arc::new(RwLock::new(HashMap::new())),
            dbus_monitor: None,
        }
    }

    pub fn start_dbus_monitor(&mut self) {
        let locked = self.screen_locked.clone();
        let handle = tokio::spawn(async move {
            match zbus::Connection::system().await {
                Ok(conn) => {
                    match conn
                        .call_method(
                            Some("org.freedesktop.login1"),
                            "/org/freedesktop/login1/seat/seat0",
                            Some("org.freedesktop.DBus.Properties"),
                            "Get",
                            &("org.freedesktop.login1.Session", "LockedHint"),
                        )
                        .await
                    {
                        Ok(_) => info!("ContextualSecurity: D-Bus login1 monitor connected"),
                        Err(e) => warn!("ContextualSecurity: D-Bus login1 not available: {e}"),
                    }
                    let mut prop_stream = conn
                        .subscribe_property_changes::<bool>(
                            Some("org.freedesktop.login1"),
                            Some("/org/freedesktop/login1/session/self"),
                            Some("org.freedesktop.login1.Session"),
                            Some("LockedHint"),
                        )
                        .await
                        .unwrap();
                    use futures_util::StreamExt;
                    while let Some(change) = prop_stream.next().await {
                        locked.store(change, Ordering::Relaxed);
                        if change {
                            info!(
                                "ContextualSecurity: Screen LOCKED — applying network quarantine"
                            );
                        } else {
                            info!("ContextualSecurity: Screen UNLOCKED — restoring network access");
                        }
                    }
                }
                Err(e) => warn!("ContextualSecurity: D-Bus system bus unavailable: {e}"),
            }
        });
        self.dbus_monitor = Some(handle);
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
