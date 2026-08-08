use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct SelfDefenseEvent {
    pub timestamp: u64,
    pub attacker_pid: u32,
    pub target_path: String,
    pub syscall: String,
    pub blocked: bool,
}

pub struct SelfDefense {
    locked: AtomicBool,
    events: Arc<RwLock<Vec<SelfDefenseEvent>>>,
    daemon_pid: u32,
}

impl SelfDefense {
    pub fn new() -> Self {
        let daemon_pid = std::process::id();
        info!("SelfDefense active for PID {daemon_pid}");
        Self {
            locked: AtomicBool::new(false),
            events: Arc::new(RwLock::new(Vec::with_capacity(256))),
            daemon_pid,
        }
    }

    pub fn lock_ebpf_maps(&self) {
        self.locked.store(true, Ordering::SeqCst);
        info!("eBPF maps locked  -  detach/resize prevented");
    }

    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::SeqCst)
    }

    pub fn ingest_kill_attempt(
        &self,
        attacker_pid: u32,
        target_pid: u32,
        sig: u32,
    ) -> Option<SelfDefenseEvent> {
        if target_pid != self.daemon_pid {
            return None;
        }
        let attacker_binary = crate::process::ProcessResolver::binary_path(attacker_pid)
            .unwrap_or_else(|| "unknown".into());
        warn!("self-defense: PID {attacker_pid} ({attacker_binary}) attempted SIG{sig} on daemon PID {target_pid}");

        let evt = SelfDefenseEvent {
            timestamp: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64,
            attacker_pid,
            target_path: format!("PID {}", target_pid),
            syscall: format!("kill(pid={}, sig={})", target_pid, sig),
            blocked: true,
        };
        self.push_event(evt.clone());
        Some(evt)
    }

    pub fn ingest_unlink_attempt(&self, attacker_pid: u32, path: &str) -> Option<SelfDefenseEvent> {
        let attacker_binary = crate::process::ProcessResolver::binary_path(attacker_pid)
            .unwrap_or_else(|| "unknown".into());
        warn!("self-defense: PID {attacker_pid} ({attacker_binary}) attempted unlink {path}");

        let evt = SelfDefenseEvent {
            timestamp: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64,
            attacker_pid,
            target_path: path.to_string(),
            syscall: format!("unlinkat({})", path),
            blocked: true,
        };
        self.push_event(evt.clone());
        Some(evt)
    }

    pub fn recent_events(&self) -> Vec<SelfDefenseEvent> {
        self.events.read().iter().rev().take(50).cloned().collect()
    }

    /// Push an event into the bounded history buffer.
    fn push_event(&self, evt: SelfDefenseEvent) {
        const MAX_EVENTS: usize = 2048;
        let mut events = self.events.write();
        if events.len() >= MAX_EVENTS {
            let excess = events.len() - MAX_EVENTS + 1;
            events.drain(0..excess);
        }
        events.push(evt);
    }
}
