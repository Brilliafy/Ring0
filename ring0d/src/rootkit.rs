use std::collections::HashSet;
use std::fs;
use std::sync::Arc;

use anyhow::Result;
use parking_lot::RwLock;
use tracing::warn;

pub struct RootkitDetector {
    known_pids: Arc<RwLock<HashSet<u32>>>,
    scan_count: Arc<RwLock<u64>>,
}

#[derive(Debug, Clone)]
pub struct RootkitFinding {
    pub alert_type: String,
    pub description: String,
    pub pid: u32,
    pub hidden: bool,
    pub module_name: String,
    pub timestamp: u64,
}

impl RootkitDetector {
    pub fn new() -> Self {
        Self {
            known_pids: Arc::new(RwLock::new(HashSet::new())),
            scan_count: Arc::new(RwLock::new(0)),
        }
    }

    pub fn scan_hidden_pids(&self) -> Vec<RootkitFinding> {
        let mut findings = Vec::new();
        let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;

        let proc_pids: HashSet<u32> = match self.enumerate_proc_pids() {
            Ok(pids) => pids,
            Err(e) => {
                warn!("Rootkit scan failed to enumerate /proc: {e:?}");
                return findings;
            }
        };

        *self.scan_count.write() += 1;

        let mut known = self.known_pids.write();
        for &pid in &proc_pids {
            known.insert(pid);
        }
        known.retain(|pid| proc_pids.contains(pid));
        drop(known);

        for &pid in &proc_pids {
            if let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) {
                let name = status
                    .lines()
                    .find(|l| l.starts_with("Name:"))
                    .unwrap_or("")
                    .to_string();
                let state = status
                    .lines()
                    .find(|l| l.starts_with("State:"))
                    .unwrap_or("")
                    .to_string();
                if state.contains("T (stopped)") || state.contains("Z (zombie)") {
                    let ppid_line = status
                        .lines()
                        .find(|l| l.starts_with("PPid:"))
                        .unwrap_or("")
                        .to_string();
                    let ppid = ppid_line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("0")
                        .parse::<u32>()
                        .unwrap_or(0);
                    if ppid == 1 {
                        continue;
                    }
                    let exe_path = match fs::read_link(format!("/proc/{pid}/exe")) {
                        Ok(p) => p.display().to_string(),
                        Err(_) => "unknown".into(),
                    };
                    if exe_path.contains("(deleted)") || !proc_pids.contains(&ppid) {
                        findings.push(RootkitFinding {
                            alert_type: "SuspiciousProcess".into(),
                            description: format!(
                                "Suspicious stopped/orphaned process: {} {} ppid={}",
                                pid, name, ppid
                            ),
                            pid,
                            hidden: false,
                            module_name: name,
                            timestamp: now,
                        });
                    }
                }
            }
        }

        let cmdline_pids = self.enumerate_all_cmdlines();
        for pid in &cmdline_pids {
            if !proc_pids.contains(pid) {
                findings.push(RootkitFinding {
                    alert_type: "HiddenProcess".into(),
                    description: format!(
                        "PID {} appears in cmdline enumeration but is hidden from /proc",
                        pid
                    ),
                    pid: *pid,
                    hidden: true,
                    module_name: String::new(),
                    timestamp: now,
                });
            }
        }

        findings
    }

    fn enumerate_proc_pids(&self) -> Result<HashSet<u32>> {
        let mut pids = HashSet::new();
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = match name.to_str() {
                Some(s) => s.to_string(),
                None => continue,
            };
            if let Ok(pid) = name_str.parse::<u32>() {
                pids.insert(pid);
            }
        }
        Ok(pids)
    }

    fn enumerate_all_cmdlines(&self) -> HashSet<u32> {
        let mut pids = HashSet::new();
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = match name.to_str() {
                    Some(s) => s.to_string(),
                    None => continue,
                };
                if let Ok(pid) = name_str.parse::<u32>() {
                    let cmdline_path = format!("/proc/{pid}/cmdline");
                    if fs::read_to_string(&cmdline_path).is_ok() {
                        pids.insert(pid);
                    }
                }
            }
        }
        pids
    }

    pub fn ingest_memfd_event(
        &self,
        _pid: u32,
        _name: &str,
        _flags: u32,
    ) -> Option<RootkitFinding> {
        let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
        Some(RootkitFinding {
            alert_type: "FilelessExec".into(),
            description: format!(
                "memfd_create by PID {}: name={} flags=0x{:x}",
                _pid, _name, _flags
            ),
            pid: _pid,
            hidden: false,
            module_name: _name.to_string(),
            timestamp: now,
        })
    }

    pub fn ingest_wx_mmap_event(
        &self,
        _pid: u32,
        _prot: u32,
        _flags: u32,
        _len: u64,
    ) -> Option<RootkitFinding> {
        let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
        let prot_write = 2;
        let prot_exec = 4;
        let is_wx = (_prot & prot_write) != 0 && (_prot & prot_exec) != 0;
        if is_wx {
            Some(RootkitFinding {
                alert_type: "WXMemoryMapping".into(),
                description: format!(
                    "Process {} mapped W+X memory: prot=0x{:x} flags=0x{:x} len={}",
                    _pid, _prot, _flags, _len
                ),
                pid: _pid,
                hidden: false,
                module_name: String::new(),
                timestamp: now,
            })
        } else {
            Some(RootkitFinding {
                alert_type: "AnonymousExecMapping".into(),
                description: format!(
                    "Process {} mapped anonymous executable memory: prot=0x{:x} len={}",
                    _pid, _prot, _len
                ),
                pid: _pid,
                hidden: false,
                module_name: String::new(),
                timestamp: now,
            })
        }
    }

    pub fn ingest_module_event(
        &self,
        _pid: u32,
        _name: &str,
        _flags: u32,
    ) -> Option<RootkitFinding> {
        let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
        let binary =
            crate::process::ProcessResolver::binary_path(_pid).unwrap_or_else(|| "unknown".into());
        Some(RootkitFinding {
            alert_type: "KernelModuleLoad".into(),
            description: format!(
                "Process {} ({}) loaded kernel module: {} flags=0x{:x}",
                _pid, binary, _name, _flags
            ),
            pid: _pid,
            hidden: false,
            module_name: _name.to_string(),
            timestamp: now,
        })
    }

    pub fn scan_count(&self) -> u64 {
        *self.scan_count.read()
    }
}
