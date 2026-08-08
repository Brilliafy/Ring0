use std::sync::Arc;

use parking_lot::RwLock;
use tracing::{debug, info};

#[derive(Debug, Clone)]
pub struct PrivEscAttempt {
    pub timestamp: u64,
    pub pid: u32,
    pub uid: u32,
    pub event_type: String,
    pub description: String,
    pub blocked: bool,
}

pub struct PrivEscDetector {
    log: Arc<RwLock<Vec<PrivEscAttempt>>>,
}

impl PrivEscDetector {
    pub fn new() -> Self {
        Self {
            log: Arc::new(RwLock::new(Vec::with_capacity(256))),
        }
    }

    /// Push an attempt into the bounded history buffer.
    fn push_attempt(&self, attempt: PrivEscAttempt) {
        const MAX_ATTEMPTS: usize = 4096;
        let mut log = self.log.write();
        if log.len() >= MAX_ATTEMPTS {
            let excess = log.len() - MAX_ATTEMPTS + 1;
            log.drain(0..excess);
        }
        log.push(attempt);
    }

    pub fn ingest_ptrace_attempt(
        &self,
        pid: u32,
        uid: u32,
        target_pid: u32,
    ) -> Option<PrivEscAttempt> {
        let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
        // The kernel LSM hook cannot expose the child's pid without CO-RE
        // task_struct bindings, so target_pid is 0 — don't present it as data.
        let desc = if target_pid != 0 {
            format!(
                "ptrace injection attempt: PID {} -> PID {}",
                pid, target_pid
            )
        } else {
            format!("ptrace access attempt: PID {}", pid)
        };
        let attempt = PrivEscAttempt {
            timestamp: now,
            pid,
            uid,
            event_type: "ptrace_attach".into(),
            description: desc.clone(),
            blocked: true,
        };
        self.push_attempt(attempt.clone());
        debug!("[PRIVESC] {desc}");
        Some(attempt)
    }

    pub fn ingest_capable_check(
        &self,
        pid: u32,
        uid: u32,
        capability: u32,
    ) -> Option<PrivEscAttempt> {
        let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
        let desc = format!("capability check: PID {} requested cap={}", pid, capability);
        let blocked = capability == 21 || capability == 12 || capability == 17;
        let attempt = PrivEscAttempt {
            timestamp: now,
            pid,
            uid,
            event_type: "capable".into(),
            description: desc.clone(),
            blocked,
        };
        if blocked {
            debug!("[PRIVESC_BLOCKED] {desc}");
        }
        self.push_attempt(attempt.clone());
        Some(attempt)
    }

    pub fn ingest_setuid_event(
        &self,
        pid: u32,
        old_uid: u32,
        new_uid: u32,
    ) -> Option<PrivEscAttempt> {
        let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
        let desc = format!(
            "setuid transition: PID {} UID {} -> {}",
            pid, old_uid, new_uid
        );
        let blocked = new_uid == 0 && old_uid != 0;
        let attempt = PrivEscAttempt {
            timestamp: now,
            pid,
            uid: old_uid,
            event_type: "setuid".into(),
            description: desc.clone(),
            blocked,
        };
        if blocked {
            debug!("[PRIVESC_BLOCKED] {desc}");
        }
        self.push_attempt(attempt.clone());
        Some(attempt)
    }

    pub fn recent_attempts(&self, n: usize) -> Vec<PrivEscAttempt> {
        self.log.read().iter().rev().take(n).cloned().collect()
    }

    pub fn total_blocked(&self) -> usize {
        self.log.read().iter().filter(|a| a.blocked).count()
    }
    pub fn total_attempts(&self) -> usize {
        self.log.read().len()
    }
}
