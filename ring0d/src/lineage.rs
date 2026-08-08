//! Process lineage tree: pid -> { ppid, binary, cmdline, cwd, … } fed by the
//! `sched_process_exec` tracepoint and the netlink proc connector. Lets the
//! risk engine answer "who is this network activity really from?"  -  binary
//! path, ancestry chain, and recent connections  -  without shelling out to
//! /proc on every event.

use std::collections::VecDeque;

use dashmap::DashMap;

/// Max tracked processes / connections. Bounded so hostile fork/exec churn
/// cannot grow memory without limit; `prune` reclaims entries for exited pids.
const MAX_PROCS: usize = 32768;
const MAX_CONNECTS_PER_PID: usize = 32;

/// Script-host parents that make a child's network activity suspicious.
pub const SCRIPT_HOSTS: &[&str] = &[
    "bash",
    "sh",
    "dash",
    "python",
    "python3",
    "perl",
    "ruby",
    "php",
    "node",
    "lua",
    "pwsh",
    "powershell",
    "zsh",
    "fish",
    "curl",
    "wget",
    "busybox",
];

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub binary: String,
    pub cmdline: String,
    pub cwd: String,
    pub first_seen: u64,
    pub last_seen: u64,
}

#[derive(Debug, Clone)]
pub struct ConnectionRef {
    pub dst_ip: u32,
    pub dst_port: u16,
    pub timestamp: u64,
}

pub struct LineageTree {
    procs: DashMap<u32, ProcessInfo>,
    connects: DashMap<u32, VecDeque<ConnectionRef>>,
    last_prune: std::sync::atomic::AtomicU64,
}

impl LineageTree {
    pub fn new() -> Self {
        Self {
            procs: DashMap::new(),
            connects: DashMap::new(),
            last_prune: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn record_exec(&self, pid: u32, ppid: u32, binary: &str, cmdline: &str) {
        let now = crate::now_ns();
        if self.procs.len() >= MAX_PROCS {
            self.prune();
        }
        let cwd = std::fs::read_link(format!("/proc/{pid}/cwd"))
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let mut entry = self.procs.entry(pid).or_insert_with(|| ProcessInfo {
            pid,
            ppid,
            binary: binary.to_string(),
            cmdline: cmdline.to_string(),
            cwd,
            first_seen: now,
            last_seen: now,
        });
        entry.ppid = ppid;
        entry.binary.clone_from(&binary.to_string());
        entry.cmdline.clone_from(&cmdline.to_string());
        entry.last_seen = now;
    }

    pub fn record_connect(&self, pid: u32, dst_ip: u32, dst_port: u16) {
        let mut q = self.connects.entry(pid).or_insert_with(VecDeque::new);
        q.push_back(ConnectionRef {
            dst_ip,
            dst_port,
            timestamp: crate::now_ns(),
        });
        while q.len() > MAX_CONNECTS_PER_PID {
            q.pop_front();
        }
    }

    pub fn lookup(&self, pid: u32) -> Option<ProcessInfo> {
        self.procs.get(&pid).map(|e| e.clone())
    }

    /// Walk the ppid chain up to `depth` steps, oldest-ancestor first.
    /// Missing links (ppid exited, ppid 0/1) terminate the walk early.
    pub fn ancestry(&self, pid: u32, depth: usize) -> Vec<ProcessInfo> {
        let mut chain = Vec::new();
        let mut cur = pid;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..depth {
            if !seen.insert(cur) {
                break;
            }
            let Some(info) = self.lookup(cur) else { break };
            let next = info.ppid;
            chain.push(info);
            if next == 0 || next == cur || next == 1 {
                break;
            }
            cur = next;
        }
        chain
    }

    pub fn latest_connection(&self, pid: u32) -> Option<ConnectionRef> {
        self.connects.get(&pid).and_then(|q| q.back().cloned())
    }

    pub fn len(&self) -> usize {
        self.procs.len()
    }

    /// Drop entries for processes that no longer exist (cheap /proc check),
    /// and drop stale connection records. Called periodically.
    pub fn prune(&self) {
        let now = crate::now_ns();
        // Age connections out after 60s (they're only used for immediate
        // TLS-event enrichment).
        let cutoff = now.saturating_sub(60_000_000_000);
        self.connects.retain(|_, q| {
            q.retain(|c| c.timestamp >= cutoff);
            !q.is_empty()
        });
        // Only sweep procs when the table is large (the /proc check is
        // cheap but not free); at low occupancy stale entries are harmless.
        if self.procs.len() < 1024 {
            return;
        }
        self.procs.retain(|pid, info| {
            // Keep the entry if the pid still exists and is not a zombie.
            match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                Ok(stat) => {
                    let state = stat.split_whitespace().nth(2).unwrap_or("X");
                    !state.starts_with('Z') || now.saturating_sub(info.last_seen) < 5_000_000_000
                }
                Err(_) => false,
            }
        });
        // Hard cap: if still over, drop oldest by last_seen.
        while self.procs.len() > MAX_PROCS {
            let oldest = self.procs.iter().min_by_key(|e| e.last_seen).map(|e| e.pid);
            if let Some(pid) = oldest {
                self.procs.remove(&pid);
            } else {
                break;
            }
        }
    }

    /// Periodic maintenance; rate-limited internally.
    pub fn maybe_prune(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let last = self.last_prune.load(std::sync::atomic::Ordering::Relaxed);
        if now.saturating_sub(last) >= 60 {
            self.last_prune
                .store(now, std::sync::atomic::Ordering::Relaxed);
            self.prune();
        }
    }
}

impl Default for LineageTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lineage_records_and_walks_ancestry() {
        let tree = LineageTree::new();
        tree.record_exec(10, 5, "/usr/bin/python3", "python3 evil.py");
        tree.record_exec(5, 1, "/usr/bin/bash", "bash");
        let ancestry = tree.ancestry(10, 4);
        assert_eq!(ancestry.len(), 2);
        assert_eq!(ancestry[0].pid, 10);
        assert_eq!(ancestry[0].ppid, 5);
        assert_eq!(ancestry[1].pid, 5);
        // Chain terminates at init.
        let deep = tree.ancestry(10, 10);
        assert_eq!(deep.len(), 2);
    }

    #[test]
    fn lineage_tracks_connections() {
        let tree = LineageTree::new();
        tree.record_connect(10, 0x0A000001, 443);
        let c = tree.latest_connection(10).unwrap();
        assert_eq!(c.dst_ip, 0x0A000001);
        assert_eq!(c.dst_port, 443);
        assert!(tree.latest_connection(99).is_none());
    }

    #[test]
    fn script_host_list_has_expected_entries() {
        assert!(SCRIPT_HOSTS.contains(&"bash"));
        assert!(SCRIPT_HOSTS.contains(&"python3"));
        assert!(SCRIPT_HOSTS.contains(&"powershell"));
    }
}
